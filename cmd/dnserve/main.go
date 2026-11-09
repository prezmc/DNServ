// Command dnserve runs a DNServe node.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // schedules need zone data; the image has none

	"github.com/prezmc/dnserve/internal/api"
	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/cache"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/policy"
	"github.com/prezmc/dnserve/internal/querylog"
	"github.com/prezmc/dnserve/internal/recursive"
	"github.com/prezmc/dnserve/internal/server"
	"github.com/prezmc/dnserve/internal/store"
	"github.com/prezmc/dnserve/internal/upstream"
	"github.com/prezmc/dnserve/internal/web"
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
	resetMFA := flag.String("reset-mfa", "", "recovery: clear USERNAME's two-factor setup and exit (stop the node first)")
	resetPassword := flag.Bool("reset-password", false, "with -reset-mfa: also set and print a new temporary password")
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

	// Base config: built-in defaults, then the optional file, then
	// DNSERVE_* environment variables. Settings saved in the dashboard
	// are layered on top, so a node needs no files to get started.
	base, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := base.ApplyEnv(os.Getenv); err != nil {
		return err
	}
	if err := base.Validate(); err != nil {
		return err
	}
	if *checkConfig {
		fmt.Println("config OK")
		return nil
	}
	if *resetMFA != "" {
		return recoverAccount(base.DataDir, *resetMFA, *resetPassword)
	}

	st, err := store.Open(base.DataDir)
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	cfg := st.State().Settings.Overlay(base)
	if err := cfg.Validate(); err != nil {
		log.Error("saved settings are invalid; using the file and environment config until they are fixed", "err", err)
		cfg = base
	}
	log.Info("starting dnserve", "version", version, "config", *cfgPath, "data_dir", cfg.DataDir, "upstream_mode", cfg.Upstream.Mode)
	started := time.Now()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Upstream, by mode.
	first, err := buildResolver(ctx, cfg, log, nil)
	if err != nil {
		return err
	}
	var up atomic.Pointer[resolverSet]
	up.Store(first)
	defer func() { stop(); up.Load().close(nil) }() // stop Unbound on any exit path

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

	srv, err := server.New(cfg, c, engine, first.resolver, log)
	if err != nil {
		return err
	}
	qlog := querylog.New(20000)
	srv.SetQueryLog(qlog)
	srv.SetPolicy(policy.Build(st.State()))
	if loc, err := cfg.Location(); err == nil {
		srv.SetTimeZone(loc)
	}
	if err := setLocalDNS(srv, cfg, log); err != nil {
		log.Error("local dns", "err", err)
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

	// Admin API: setup, sign-in, users, settings.
	sessions, err := auth.OpenSessions(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open sessions: %w", err)
	}
	adm := api.New(st, sessions, base, log.With("component", "api"))
	adm.AllowedOrigins = splitList(os.Getenv("DNSERVE_ALLOWED_ORIGINS"))
	adm.QueryLog = qlog
	adm.CheckDomain = engine.Lookup
	adm.LookupName = srv.LookupName
	adm.Status = func() any {
		set := up.Load()
		eff := adm.Effective()
		out := map[string]any{
			"version":        version,
			"uptime_seconds": int64(time.Since(started).Seconds()),
			"upstream_mode":  set.mode,
			"queries":        srv.Metrics.Counts(),
			"filter": map[string]any{
				"enabled": engine.Enabled(), "ready": filterReady.Load(),
				"rules": engine.Rules(), "lists": engine.Status(),
			},
		}
		var ups []upstream.Stat
		for _, g := range set.groups {
			ups = append(ups, g.Stats()...)
		}
		out["upstreams"] = ups
		if set.unbound != nil {
			out["unbound"] = map[string]any{"ready": set.unbound.ub.Ready(), "restarts": set.unbound.ub.Restarts()}
		}
		// Lets the UI offer tunnel mode only where a VPN interface exists.
		if ifc := eff.Upstream.Tunnel.Interface; ifc != "" {
			_, err := net.InterfaceByName(ifc)
			out["tunnel_interface_present"] = err == nil
		}
		out["started_at"] = started.UTC()
		if set.tunnel != nil {
			ok, why := set.tunnel.Up()
			out["tunnel"] = map[string]any{"up": ok, "detail": why, "interface": eff.Upstream.Tunnel.Interface}
		}
		if c != nil {
			out["cache"] = c.Stats()
		}
		return out
	}

	// Apply saved settings live. Changes are queued and applied one at a
	// time off the request path (starting Unbound can take seconds).
	reload := make(chan struct{}, 1)
	st.Subscribe(func(old, new *store.State) {
		// Groups are cheap to compile, so apply them right here.
		if !reflect.DeepEqual(old.Groups, new.Groups) || !reflect.DeepEqual(old.Devices, new.Devices) {
			srv.SetPolicy(policy.Build(new))
		}
		if !reflect.DeepEqual(old.Settings, new.Settings) {
			select {
			case reload <- struct{}{}:
			default:
			}
		}
	})
	go func() {
		applied := cfg
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
			}
			next := adm.Effective()
			if err := next.Validate(); err != nil {
				log.Error("not applying settings", "err", err)
				continue
			}
			applied = applySettings(ctx, applied, next, srv, engine, &up, log)
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           httpHandler(srv, c, engine, &up, &filterReady, adm.Handler()),
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
	_ = sessions.Save()
	if c != nil && cfg.Cache.Persist {
		if n, err := c.Save(cachePath); err != nil {
			log.Warn("cache save failed", "err", err)
		} else {
			log.Info("cache saved", "entries", n)
		}
	}
	return nil
}

// applySettings moves the running node from cfg to next and returns what
// is now in force.
func applySettings(ctx context.Context, cfg, next config.Config, srv *server.Server, engine *filter.Engine, up *atomic.Pointer[resolverSet], log *slog.Logger) config.Config {
	var newSet *resolverSet
	if !reflect.DeepEqual(cfg.Upstream, next.Upstream) {
		old := up.Load()
		set, err := buildResolver(ctx, next, log, old.unbound)
		if err != nil {
			log.Error("upstream change failed; keeping the current upstream", "err", err)
			next.Upstream = cfg.Upstream
		} else {
			newSet = set
		}
	}
	var r server.Resolver
	if newSet != nil {
		r = newSet.resolver
	}
	if err := srv.Apply(r, next.DNS.AllowedNets, next.Filtering, newSet != nil); err != nil {
		log.Error("settings change failed", "err", err)
		if newSet != nil {
			newSet.close(up.Load().unbound)
		}
		return cfg
	}
	if newSet != nil {
		old := up.Swap(newSet)
		old.close(newSet.unbound)
		log.Info("upstream changed", "mode", next.Upstream.Mode)
	}
	if loc, err := next.Location(); err == nil {
		srv.SetTimeZone(loc)
	}
	if cfg.DNS.LocalDNS != next.DNS.LocalDNS {
		if err := setLocalDNS(srv, next, log); err != nil {
			log.Error("local dns change failed", "err", err)
		}
	}
	engine.SetConfig(next.Filtering)
	f, n := cfg.Filtering, next.Filtering
	if !slices.Equal(f.Rules, n.Rules) || !reflect.DeepEqual(f.Lists, n.Lists) ||
		!reflect.DeepEqual(f.Allowlists, n.Allowlists) || f.BlockBypass != n.BlockBypass {
		if err := engine.Rebuild(ctx, false); err != nil {
			log.Error("filter rebuild failed", "err", err)
		}
	}
	return next
}

// recoverAccount is the locked-out-admin escape hatch. It needs shell
// access to the data volume, which already implies full control.
func recoverAccount(dataDir, username string, newPassword bool) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	u := st.State().UserByName(username)
	if u == nil {
		return fmt.Errorf("no user %q", username)
	}
	if _, err := st.Apply(store.NewCommand(store.OpMFAReset, "console", store.IDOnly{ID: u.ID})); err != nil {
		return err
	}
	fmt.Printf("two-factor sign-in cleared for %q; set it up again at the next sign-in\n", username)
	if newPassword {
		pw := auth.RandomID(12)
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if _, err := st.Apply(store.NewCommand(store.OpUserPassword, "console", store.UserPassword{ID: u.ID, PasswordHash: hash})); err != nil {
			return err
		}
		fmt.Printf("temporary password: %s\n", pw)
	}
	sessions, err := auth.OpenSessions(dataDir)
	if err == nil {
		sessions.RevokeUser(u.ID, "")
	}
	return nil
}

// setLocalDNS points LAN names at the router, or clears it.
func setLocalDNS(srv *server.Server, cfg config.Config, log *slog.Logger) error {
	if cfg.DNS.LocalDNS == "" {
		srv.SetLocalDNS(nil)
		return nil
	}
	addr, err := config.LocalDNSAddr(cfg.DNS.LocalDNS)
	if err != nil {
		return err
	}
	g, err := upstream.NewGroup([]string{"udp://" + addr}, nil, 2*time.Second, log)
	if err != nil {
		return err
	}
	srv.SetLocalDNS(g)
	log.Info("local names go to the router", "addr", addr)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, f)
	}
	return out
}

func httpHandler(srv *server.Server, c *cache.Cache, engine *filter.Engine, ups *atomic.Pointer[resolverSet], ready *atomic.Bool, apiHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", web.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		up := ups.Load()
		if !ready.Load() {
			http.Error(w, "filter lists loading\n", http.StatusServiceUnavailable)
			return
		}
		if up.unbound != nil && !up.unbound.ub.Ready() {
			http.Error(w, "unbound not ready\n", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		up := ups.Load()
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
			fmt.Fprintf(w, "# TYPE dnserve_unbound_up gauge\ndnserve_unbound_up %d\n", b2i(up.unbound.ub.Ready()))
			fmt.Fprintf(w, "# TYPE dnserve_unbound_restarts_total counter\ndnserve_unbound_restarts_total %d\n", up.unbound.ub.Restarts())
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
	mode     string
	resolver server.Resolver
	groups   []*upstream.Group
	unbound  *unboundProc // shared between sets while the mode needs it
	tunnel   *recursive.Tunnel
	cancel   context.CancelFunc // stops this set's background checks
}

// unboundProc is a running bundled Unbound.
type unboundProc struct {
	ub     *recursive.Unbound
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (p *unboundProc) stop() {
	p.once.Do(func() { p.cancel(); <-p.done })
}

// close stops the set's background work, and its Unbound unless keep is
// the same process (it moved to the next set).
func (r *resolverSet) close(keep *unboundProc) {
	r.cancel()
	if r.unbound != nil && r.unbound != keep {
		r.unbound.stop()
	}
}

// buildResolver builds the upstream path for cfg. A running Unbound is
// reused when the new mode needs one too, since its config doesn't depend
// on upstream settings.
func buildResolver(ctx context.Context, cfg config.Config, log *slog.Logger, reuse *unboundProc) (*resolverSet, error) {
	u := cfg.Upstream
	sctx, cancel := context.WithCancel(ctx)
	set := &resolverSet{mode: u.Mode, cancel: cancel}
	fail := func(err error) (*resolverSet, error) {
		set.close(reuse)
		return nil, err
	}
	forward := func() (*upstream.Group, error) {
		g, err := upstream.NewGroup(u.Servers, u.Bootstrap, u.Timeout, log)
		if err == nil {
			set.groups = append(set.groups, g)
		}
		return g, err
	}
	if u.Mode == "forward" {
		g, err := forward()
		if err != nil {
			return fail(err)
		}
		set.resolver = g
		return set, nil
	}

	// recursive and tunnel: run the bundled Unbound.
	if reuse != nil {
		set.unbound = reuse
	} else {
		r := u.Recursive
		opts := recursive.Options{
			Binary: r.Binary, Dir: filepath.Join(cfg.DataDir, "unbound"), Port: r.Port,
			Threads: r.Threads, CacheMB: r.CacheMB, ServeExpired: cfg.Cache.ServeStale,
		}
		ub := recursive.New(opts, log.With("component", "unbound"))
		confPath, err := ub.Prepare()
		if err != nil {
			return fail(err)
		}
		uctx, ucancel := context.WithCancel(ctx)
		p := &unboundProc{ub: ub, cancel: ucancel, done: make(chan struct{})}
		set.unbound = p
		go func() {
			defer close(p.done)
			ub.Run(uctx, confPath)
		}()
		wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
		err = ub.WaitReady(wctx)
		wcancel()
		if err != nil {
			log.Error("unbound is not answering yet; DNS will SERVFAIL until it is", "err", err)
		}
	}
	local, err := upstream.NewGroup([]string{"udp://" + set.unbound.ub.Addr()}, nil, u.Timeout, log)
	if err != nil {
		return fail(err)
	}
	set.groups = append(set.groups, local)
	if u.Mode == "recursive" {
		set.resolver = local
		return set, nil
	}

	expected, err := recursive.ParsePrefixes(u.Tunnel.ExpectedEgress)
	if err != nil {
		return fail(err)
	}
	t := &recursive.Tunnel{Primary: local, Interface: u.Tunnel.Interface, Expected: expected, Log: log.With("component", "tunnel")}
	if u.Tunnel.OnDown == "forward" {
		g, err := forward()
		if err != nil {
			return fail(err)
		}
		t.Fallback = g
	}
	t.Check(sctx)
	go t.Run(sctx, u.Tunnel.CheckInterval)
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
