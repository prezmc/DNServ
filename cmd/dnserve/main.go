// Command dnserve runs a DNServe node.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prezmc/dnserve/internal/cache"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/server"
	"github.com/prezmc/dnserve/internal/upstream"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dnserve:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", envOr("DNSERVE_CONFIG", "/data/dnserve.yaml"), "path to the YAML config file")
	logLevel := flag.String("log-level", envOr("DNSERVE_LOG_LEVEL", "info"), "debug, info, warn or error")
	checkConfig := flag.Bool("check-config", false, "validate the config and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.String("healthcheck", "", "probe http://ADDR/healthz and exit 0 if healthy (for container health checks)")
	flag.Parse()

	if *healthcheck != "" {
		return probe(*healthcheck)
	}

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *checkConfig {
		fmt.Println("config OK")
		return nil
	}
	log.Info("starting dnserve", "version", version, "config", *cfgPath, "upstream_mode", cfg.Upstream.Mode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Upstream.
	group, err := upstream.NewGroup(cfg.Upstream.Servers, cfg.Upstream.Bootstrap, cfg.Upstream.Timeout, log)
	if err != nil {
		return err
	}

	// Cache, warmed from disk.
	var c *cache.Cache
	cachePath := filepath.Join(cfg.DataDir, "cache.gob")
	if cfg.Cache.Enabled {
		c = cache.New(cache.Options{
			MaxEntries: cfg.Cache.MaxEntries, MinTTL: cfg.Cache.MinTTL, MaxTTL: cfg.Cache.MaxTTL,
			NegativeTTL: cfg.Cache.NegativeTTL, ServeStale: cfg.Cache.ServeStale, Prefetch: cfg.Cache.Prefetch,
		})
		if cfg.Cache.Persist {
			if n, err := c.Load(cachePath); err != nil {
				log.Warn("cache reload failed", "err", err)
			} else if n > 0 {
				log.Info("cache warmed from disk", "entries", n)
			}
		}
	}

	// Filtering. DNS starts answering right away; the index is built in the
	// background and /readyz reports ready once it is in place.
	engine := filter.NewEngine(cfg.Filtering, cfg.DataDir, nil, log)
	var filterReady atomic.Bool
	go func() {
		if err := engine.Rebuild(ctx, false); err != nil {
			log.Error("initial filter build failed", "err", err)
		}
		filterReady.Store(true)
		engine.Run(ctx)
	}()

	srv, err := server.New(cfg, c, engine, group, log)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           httpHandler(srv, c, engine, group, &filterReady),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("http listening", "addr", cfg.HTTP.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	_ = srv.Shutdown(shutCtx)
	if c != nil && cfg.Cache.Persist {
		if n, err := c.Save(cachePath); err != nil {
			log.Warn("cache save failed", "err", err)
		} else {
			log.Info("cache saved", "entries", n)
		}
	}
	return nil
}

func httpHandler(srv *server.Server, c *cache.Cache, engine *filter.Engine, group *upstream.Group, ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "filter lists loading\n", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		srv.Metrics.WritePrometheus(w)
		if c != nil {
			st := c.Stats()
			fmt.Fprintf(w, "# TYPE dnserve_cache_entries gauge\ndnserve_cache_entries %d\n", st.Entries)
			fmt.Fprintf(w, "# TYPE dnserve_cache_prefetches_total counter\ndnserve_cache_prefetches_total %d\n", st.Prefetches)
		}
		fmt.Fprintf(w, "# TYPE dnserve_filter_rules gauge\ndnserve_filter_rules %d\n", engine.Rules())
		fmt.Fprintln(w, "# TYPE dnserve_upstream_latency_ms gauge")
		for _, s := range group.Stats() {
			fmt.Fprintf(w, "dnserve_upstream_latency_ms{server=%q} %g\n", s.Server, s.LatencyMS)
		}
	})
	return mux
}

// probe checks a running node's health endpoint. Distroless images have no
// shell or curl, so the binary checks itself.
func probe(addr string) error {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
