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
	"github.com/prezmc/dnserve/internal/recursive"
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
	if err := cfg.ApplyEnv(os.Getenv); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if *checkConfig {
		fmt.Println("config OK")
		return nil
	}
	log.Info("starting dnserve", "version", version, "config", *cfgPath, "upstream_mode", cfg.Upstream.Mode)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Upstream, by mode.
	up, err := buildResolver(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { stop(); up.wait() }() // stop Unbound on any exit path

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

	srv, err := server.New(cfg, c, engine, up.resolver, log)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	if tc := cfg.DNS.TLS; len(tc.DoTListen)+len(tc.DoHListen) > 0 {
		cert, fp, selfSigned, err := server.LoadOrCreateCert(tc, cfg.DataDir)
		if err != nil {
			return err
		}
		if selfSigned {
			log.Warn("using a self-signed certificate for DNS over TLS/HTTPS; most devices need a trusted one (set dns.tls.cert_file)", "sha256", fp)
		} else {
			log.Info("tls certificate loaded", "sha256", fp)
		}
		if err := srv.StartEncrypted(cert); err != nil {
			return err
		}
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           httpHandler(srv, c, engine, up, &filterReady),
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

func httpHandler(srv *server.Server, c *cache.Cache, engine *filter.Engine, up *resolverSet, ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "filter lists loading\n", http.StatusServiceUnavailable)
			return
		}
		if up.unbound != nil && !up.unbound.Ready() {
			http.Error(w, "unbound not ready\n", http.StatusServiceUnavailable)
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
		for _, g := range up.groups {
			for _, s := range g.Stats() {
				fmt.Fprintf(w, "dnserve_upstream_latency_ms{server=%q} %g\n", s.Server, s.LatencyMS)
			}
		}
		if up.unbound != nil {
			fmt.Fprintf(w, "# TYPE dnserve_unbound_up gauge\ndnserve_unbound_up %d\n", b2i(up.unbound.Ready()))
			fmt.Fprintf(w, "# TYPE dnserve_unbound_restarts_total counter\ndnserve_unbound_restarts_total %d\n", up.unbound.Restarts())
		}
		if up.tunnel != nil {
			ok, _ := up.tunnel.Up()
			fmt.Fprintf(w, "# TYPE dnserve_tunnel_up gauge\ndnserve_tunnel_up %d\n", b2i(ok))
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

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// resolverSet is the upstream path for the configured mode plus the parts
// health and metrics report on.
type resolverSet struct {
	resolver server.Resolver
	groups   []*upstream.Group
	unbound  *recursive.Unbound
	tunnel   *recursive.Tunnel
	done     chan struct{} // closed when Unbound has stopped
}

func (r *resolverSet) wait() {
	if r.done != nil {
		<-r.done
	}
}

func buildResolver(ctx context.Context, cfg config.Config, log *slog.Logger) (*resolverSet, error) {
	u := cfg.Upstream
	set := &resolverSet{}
	forward := func() (*upstream.Group, error) {
		g, err := upstream.NewGroup(u.Servers, u.Bootstrap, u.Timeout, log)
		if err == nil {
			set.groups = append(set.groups, g)
		}
		return g, err
	}
	if u.Mode == "forward" {
		g, err := forward()
		set.resolver = g
		return set, err
	}

	// recursive and tunnel: run the bundled Unbound.
	r := u.Recursive
	opts := recursive.Options{
		Binary: r.Binary, Dir: filepath.Join(cfg.DataDir, "unbound"), Port: r.Port,
		Threads: r.Threads, CacheMB: r.CacheMB, ServeExpired: cfg.Cache.ServeStale,
	}
	ub := recursive.New(opts, log.With("component", "unbound"))
	confPath, err := ub.Prepare()
	if err != nil {
		return nil, err
	}
	set.unbound = ub
	set.done = make(chan struct{})
	go func() {
		defer close(set.done)
		ub.Run(ctx, confPath)
	}()
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := ub.WaitReady(wctx); err != nil {
		log.Error("unbound is not answering yet; DNS will SERVFAIL until it is", "err", err)
	}
	local, err := upstream.NewGroup([]string{"udp://" + ub.Addr()}, nil, u.Timeout, log)
	if err != nil {
		return nil, err
	}
	set.groups = append(set.groups, local)
	if u.Mode == "recursive" {
		set.resolver = local
		return set, nil
	}

	expected, err := recursive.ParsePrefixes(u.Tunnel.ExpectedEgress)
	if err != nil {
		return nil, err
	}
	t := &recursive.Tunnel{Primary: local, Interface: u.Tunnel.Interface, Expected: expected, Log: log.With("component", "tunnel")}
	if u.Tunnel.OnDown == "forward" {
		g, err := forward()
		if err != nil {
			return nil, err
		}
		t.Fallback = g
	}
	t.Check(ctx)
	go t.Run(ctx, u.Tunnel.CheckInterval)
	set.tunnel = t
	set.resolver = t
	return set, nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
