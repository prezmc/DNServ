// Command dnserv runs a DNServ node.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/api"
	"github.com/prezmc/dnserv/internal/auth"
	"github.com/prezmc/dnserv/internal/backup"
	"github.com/prezmc/dnserv/internal/cache"
	"github.com/prezmc/dnserv/internal/cluster"
	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/policy"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/recursive"
	"github.com/prezmc/dnserv/internal/server"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
	"github.com/prezmc/dnserv/internal/upstream"
	"github.com/prezmc/dnserv/internal/virustotal"
	"github.com/prezmc/dnserv/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dnserv:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", envOr("DNSERV_CONFIG", "/data/dnserv.yaml"), "path to the YAML config file")
	logLevel := flag.String("log-level", envOr("DNSERV_LOG_LEVEL", "info"), "debug, info, warn or error")
	checkConfig := flag.Bool("check-config", false, "validate the config and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.String("healthcheck", "", "probe http://ADDR/healthz and exit 0 if healthy (for container health checks)")
	resetMFA := flag.String("reset-mfa", "", "recovery: clear USERNAME's two-factor setup when the node next starts, and exit (stop the node first)")
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
	// DNSERV_* environment variables. Settings saved in the dashboard
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
	switch role := strings.ToLower(envOr("DNSERV_ROLE", "node")); role {
	case "node":
	case "witness":
		return runWitness(base, st, log)
	default:
		return fmt.Errorf("DNSERV_ROLE: unknown role %q (node or witness)", role)
	}
	// Clustering. Every node runs Raft, alone or not, so another node can
	// join at any time. Changes go through the cluster from here on.
	cl, err := cluster.Open(cluster.Options{
		DataDir: base.DataDir, Listen: base.Cluster.Listen, Advertise: base.Cluster.Advertise,
		Name: os.Getenv("DNSERV_NODE_NAME"), Version: version, Log: log.With("component", "cluster"),
	}, st)
	if err != nil {
		return fmt.Errorf("start cluster: %w", err)
	}
	defer cl.Close()
	go applyConsoleCommands(cl, st, base.DataDir, log)

	cfg := st.State().Settings.Overlay(base)
	if err := cfg.Validate(); err != nil {
		log.Error("saved settings are invalid; using the file and environment config until they are fixed", "err", err)
		cfg = base
	}
	log.Info("starting dnserv", "version", version, "config", *cfgPath, "data_dir", cfg.DataDir, "upstream_mode", cfg.Upstream.Mode)
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
	syncLists(ctx, cl, engine, log)
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
	// Long-term query history, this node's own. The dashboard on any node
	// asks the others and merges what they say.
	hist, err := analytics.Open(filepath.Join(cfg.DataDir, "history.db"), cl.Name, cfg.History.Days, cfg.History.StatsDays, log.With("component", "analytics"))
	if err != nil {
		log.Error("query history is unavailable", "err", err)
	} else {
		srv.SetHistory(hist)
		defer hist.Close()
		// Upstream response times and failures, for the Performance page.
		obs := upstream.Observer(hist.ObserveUpstream)
		upstreamObserver.Store(&obs)
		for _, g := range first.groups {
			g.SetObserver(obs)
		}
	}
	srv.SetPolicy(policy.Build(st.State()))
	selfID := cl.ID() // fixed for the life of the node
	setPause(srv, st.State(), selfID)
	if loc, err := cfg.Location(); err == nil {
		srv.SetTimeZone(loc)
	}
	if err := setLocalDNS(srv, cfg, log); err != nil {
		log.Error("local dns", "err", err)
	}
	srv.SetRecords(server.NewRecords(cfg.DNS.Records))
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
	adm.AllowedOrigins = splitList(os.Getenv("DNSERV_ALLOWED_ORIGINS"))
	adm.Cluster = cl
	// Scheduled backups: each node keeps its own in /data/backups; the
	// leader also writes to the off-box folder when one is set.
	adm.Backups = &backup.Manager{
		Store: st, Dir: filepath.Join(cfg.DataDir, "backups"), Version: version,
		Node:     cl.Name,
		Cluster:  func() string { return st.State().Cluster.ID },
		IsLeader: func() bool { return cl.LocalStatus().State == "Leader" },
		// The same time zone as group schedules.
		Loc: func() *time.Location {
			if l, err := adm.Effective().Location(); err == nil {
				return l
			}
			return time.UTC
		},
		Log: log.With("component", "backup"),
	}
	go adm.Backups.Run(ctx)
	adm.QueryLog = qlog
	if hist != nil {
		adm.Analytics = hist
	}
	// Risk scores and domain types for analytics (never used to block).
	intel := threat.New(filepath.Join(cfg.DataDir, "threat"), nil, log.With("component", "threat"))
	intel.SetEnabled(cfg.Analytics.ThreatFeeds)
	intel.SetTrusted(cfg.Analytics.TrustedDomains)
	go intel.Run(ctx)
	adm.Intel = intel
	if hist != nil {
		hist.SetChecker(intel.CheckAnswer) // runs on the history writer, not the query path
	}
	cl.Handle(api.PeerAnalytics, adm.PeerHandler)
	adm.CheckDomain = engine.Lookup
	adm.AlsoOn = engine.AlsoOn
	adm.VirusTotal = virustotal.New(func() string { return st.State().VirusTotalKey })
	adm.LookupName = srv.LookupName
	clearLocal := func() int {
		if c == nil {
			return 0
		}
		n := c.Len()
		c.Flush()
		return n
	}
	cl.Handle(peerCacheClear, func(context.Context, json.RawMessage) (any, error) { return clearLocal(), nil })
	adm.ClearCache = func(ctx context.Context) []api.CacheCleared {
		out := []api.CacheCleared{{Server: cl.Name(), Entries: clearLocal()}}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		for _, r := range cl.AskPeers(pctx, peerCacheClear, nil) {
			res := api.CacheCleared{Server: r.Name}
			if r.Err != nil {
				res.Error = r.Err.Error()
			} else {
				json.Unmarshal(r.Body, &res.Entries)
			}
			out = append(out, res)
		}
		return out
	}
	if hist != nil {
		clearHist := func(ctx context.Context, what string) error {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			return hist.Clear(cctx, what)
		}
		cl.Handle(peerHistoryClear, func(ctx context.Context, body json.RawMessage) (any, error) {
			var what string
			if err := json.Unmarshal(body, &what); err != nil {
				return nil, err
			}
			return nil, clearHist(ctx, what)
		})
		adm.ClearHistory = func(ctx context.Context, what string) []api.HistoryCleared {
			res := api.HistoryCleared{Server: cl.Name()}
			if err := clearHist(ctx, what); err != nil {
				res.Error = err.Error()
			}
			out := []api.HistoryCleared{res}
			pctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			for _, r := range cl.AskPeers(pctx, peerHistoryClear, what) {
				res := api.HistoryCleared{Server: r.Name}
				if r.Err != nil {
					res.Error = r.Err.Error()
				}
				out = append(out, res)
			}
			return out
		}
	}
	var updating atomic.Bool
	cl.Handle(peerListsUpdate, func(context.Context, json.RawMessage) (any, error) {
		adm.UpdateLists()
		return nil, nil
	})
	adm.UpdateLists = func() {
		// In a cluster the leader downloads, and the others copy its lists.
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := cl.AskLeader(actx, peerListsUpdate, nil)
		cancel()
		if err == nil {
			return
		}
		if !errors.Is(err, cluster.ErrNoFullLeader) {
			log.Warn("couldn't ask the leader to update lists; updating here", "err", err)
		}
		if !updating.CompareAndSwap(false, true) {
			return // one at a time
		}
		go func() {
			defer updating.Store(false)
			if err := engine.Rebuild(ctx, true); err != nil {
				log.Warn("list update failed", "err", err)
			}
		}()
	}
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
		if hist != nil {
			out["history"] = hist.Stats()
		}
		ls := cl.LocalStatus()
		out["cluster"] = map[string]any{
			"healthy": ls.LeaderID != "", "leader": st.State().Cluster.NodeName(ls.LeaderID),
			"nodes": len(st.State().Cluster.Nodes), "name": cl.Name(),
		}
		return out
	}

	// Apply saved settings live. Changes are queued and applied one at a
	// time off the request path (starting Unbound can take seconds).
	reload := make(chan struct{}, 1)
	// While a node that was in a cluster joins another one, its state is
	// briefly empty until the new cluster's copy arrives. Devices keep
	// getting answers from the settings in force until then, so changes
	// are compared with what DNS last used, not with the state before.
	var (
		subMu   sync.Mutex
		shown   = st.State()
		holding atomic.Bool
	)
	st.Subscribe(func(_, new *store.State) {
		subMu.Lock()
		defer subMu.Unlock()
		if new.Cluster.ID == "" && shown.Cluster.ID != "" {
			holding.Store(true)
			return
		}
		holding.Store(false)
		old := shown
		shown = new
		// Groups are cheap to compile, so apply them right here.
		if !reflect.DeepEqual(old.Groups, new.Groups) || !reflect.DeepEqual(old.Devices, new.Devices) {
			srv.SetPolicy(policy.Build(new))
		}
		if !reflect.DeepEqual(old.Pauses, new.Pauses) || old.Cluster.ID != new.Cluster.ID {
			setPause(srv, new, selfID)
		}
		if hist != nil && (!reflect.DeepEqual(old.Settings.HistoryDays, new.Settings.HistoryDays) || !reflect.DeepEqual(old.Settings.StatsDays, new.Settings.StatsDays)) {
			h := new.Settings.Overlay(base).History
			hist.SetRetention(h.Days, h.StatsDays)
		}
		if !reflect.DeepEqual(old.Settings.ThreatFeeds, new.Settings.ThreatFeeds) || !reflect.DeepEqual(old.Settings.TrustedDomains, new.Settings.TrustedDomains) {
			ac := new.Settings.Overlay(base).Analytics
			intel.SetTrusted(ac.TrustedDomains)
			intel.SetEnabled(ac.ThreatFeeds)
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
			if holding.Load() {
				continue
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

// runWitness runs a witness: a cluster member that votes and keeps the
// log, so two full nodes keep a majority when either is down. It answers
// no DNS and has no dashboard. It joins with the code in DNSERV_JOIN.
func runWitness(base config.Config, st *store.Store, log *slog.Logger) error {
	cl, err := cluster.Open(cluster.Options{
		DataDir: base.DataDir, Listen: base.Cluster.Listen, Advertise: base.Cluster.Advertise,
		Name: os.Getenv("DNSERV_NODE_NAME"), Version: version, Log: log.With("component", "cluster"), Witness: true,
	}, st)
	if err != nil {
		return fmt.Errorf("start cluster: %w", err)
	}
	defer cl.Close()
	log.Info("starting dnserv witness", "version", version, "name", cl.Name())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if cl.Joined() {
			return
		}
		code := strings.TrimSpace(os.Getenv("DNSERV_JOIN"))
		if code == "" {
			log.Warn("this witness isn't in a cluster yet: on a DNServ node open Cluster, make a join code, and start this container with DNSERV_JOIN=<code>")
			return
		}
		for {
			jctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			name, err := cl.Join(jctx, code, "")
			cancel()
			if err == nil {
				log.Info("witness joined the cluster", "name", name)
				return
			}
			if errors.Is(err, store.ErrBadJoinCode) {
				log.Error("join code refused; make a new one under Cluster and restart this container with it", "err", err)
				return
			}
			log.Warn("joining failed; retrying in 15s", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if cl.LocalStatus().LeaderID == "" {
			http.Error(w, "no cluster leader\n", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		ls := cl.LocalStatus()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		leader := "none (changes paused)"
		if ls.LeaderID != "" {
			leader = st.State().Cluster.NodeName(ls.LeaderID)
		}
		fmt.Fprintf(w, "DNServ witness %q\nIn a cluster: %v\nLeader: %s\n\nThis container only votes in the cluster. Manage it from a DNServ node's dashboard under Cluster.\n", cl.Name(), cl.Joined(), leader)
	})
	httpSrv := &http.Server{Addr: base.HTTP.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server failed", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(sctx)
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
	if !reflect.DeepEqual(cfg.DNS.Records, next.DNS.Records) {
		srv.SetRecords(server.NewRecords(next.DNS.Records))
		log.Info("local records changed", "records", len(next.DNS.Records))
	}
	if cfg.DNS.LocalDNS != next.DNS.LocalDNS {
		if err := setLocalDNS(srv, next, log); err != nil {
			log.Error("local dns change failed", "err", err)
		}
	}
	engine.SetConfig(next.Filtering)
	f, n := cfg.Filtering, next.Filtering
	if !slices.Equal(f.Rules, n.Rules) || !reflect.DeepEqual(f.Lists, n.Lists) ||
		!reflect.DeepEqual(f.Allowlists, n.Allowlists) || f.BlockBypass != n.BlockBypass ||
		!slices.Equal(f.BlockedServices, n.BlockedServices) {
		if err := engine.Rebuild(ctx, false); err != nil {
			log.Error("filter rebuild failed", "err", err)
		}
	}
	return next
}

// recoverAccount is the locked-out-admin escape hatch. It needs shell
// access to the data volume, which already implies full control. Changes
// must go through the cluster, so they are queued in the data volume and
// applied when the node next starts and has a leader.
func recoverAccount(dataDir, username string, newPassword bool) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	u := st.State().UserByName(username)
	if u == nil {
		return fmt.Errorf("no user %q", username)
	}
	cmds := []store.Command{store.NewCommand(store.OpMFAReset, "console", store.IDOnly{ID: u.ID})}
	var pw string
	if newPassword {
		pw = auth.RandomID(12)
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		cmds = append(cmds, store.NewCommand(store.OpUserPassword, "console", store.UserPassword{ID: u.ID, PasswordHash: hash}))
	}
	if err := queueConsoleCommands(dataDir, cmds); err != nil {
		return err
	}
	fmt.Printf("two-factor sign-in will be cleared for %q when the node starts; set it up again at the next sign-in\n", username)
	if pw != "" {
		fmt.Printf("temporary password (works once the node has started): %s\n", pw)
	}
	fmt.Println("in a cluster, the node needs to reach the leader for this to apply")
	sessions, err := auth.OpenSessions(dataDir)
	if err == nil {
		sessions.RevokeUser(u.ID, "")
		_ = sessions.Save()
	}
	return nil
}

func consolePath(dataDir string) string { return filepath.Join(dataDir, "console-commands.json") }

func queueConsoleCommands(dataDir string, cmds []store.Command) error {
	var all []store.Command
	if b, err := os.ReadFile(consolePath(dataDir)); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	all = append(all, cmds...)
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return os.WriteFile(consolePath(dataDir), b, 0o600)
}

// applyConsoleCommands applies commands queued by -reset-mfa once the
// cluster can take changes.
func applyConsoleCommands(cl *cluster.Cluster, st *store.Store, dataDir string, log *slog.Logger) {
	b, err := os.ReadFile(consolePath(dataDir))
	if err != nil {
		return
	}
	var cmds []store.Command
	if err := json.Unmarshal(b, &cmds); err != nil {
		log.Error("unreadable console commands; removing", "err", err)
		os.Remove(consolePath(dataDir))
		return
	}
	for len(cmds) > 0 {
		if _, err := st.Apply(cmds[0]); err != nil && errors.Is(err, store.ErrUnavailable) {
			time.Sleep(5 * time.Second)
			continue
		} else if err != nil {
			log.Error("console command failed", "op", cmds[0].Op, "err", err)
		} else {
			log.Warn("applied console command", "op", cmds[0].Op)
		}
		cmds = cmds[1:]
	}
	os.Remove(consolePath(dataDir))
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
			fmt.Fprintf(w, "# TYPE dnserv_cache_entries gauge\ndnserv_cache_entries %d\n", st.Entries)
			fmt.Fprintf(w, "# TYPE dnserv_cache_prefetches_total counter\ndnserv_cache_prefetches_total %d\n", st.Prefetches)
		}
		fmt.Fprintf(w, "# TYPE dnserv_filter_rules gauge\ndnserv_filter_rules %d\n", engine.Rules())
		fmt.Fprintln(w, "# TYPE dnserv_upstream_latency_ms gauge")
		for _, g := range up.groups {
			for _, s := range g.Stats() {
				fmt.Fprintf(w, "dnserv_upstream_latency_ms{server=%q} %g\n", s.Server, s.LatencyMS)
			}
		}
		if up.unbound != nil {
			fmt.Fprintf(w, "# TYPE dnserv_unbound_up gauge\ndnserv_unbound_up %d\n", b2i(up.unbound.ub.Ready()))
			fmt.Fprintf(w, "# TYPE dnserv_unbound_restarts_total counter\ndnserv_unbound_restarts_total %d\n", up.unbound.ub.Restarts())
		}
		if up.tunnel != nil {
			ok, _ := up.tunnel.Up()
			fmt.Fprintf(w, "# TYPE dnserv_tunnel_up gauge\ndnserv_tunnel_up %d\n", b2i(ok))
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

// upstreamObserver, once history is open, is given every upstream group
// built, so upstream timings reach the history.
var upstreamObserver atomic.Pointer[upstream.Observer]

func observe(g *upstream.Group) {
	if o := upstreamObserver.Load(); o != nil {
		g.SetObserver(*o)
	}
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
			g.SetStrategy(upstream.Strategy(u.Strategy))
			observe(g)
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
	observe(local)
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

// Peer RPCs for keeping blocklists the same on every node.
const (
	peerListVersions = "lists.versions" // the leader's list versions, by URL
	peerListsChanged = "lists.changed"  // the leader has new list contents
	peerListsUpdate  = "lists.update"   // download lists now (sent to the leader)
	peerCacheClear   = "cache.clear"    // empty the answer cache
	peerHistoryClear = "history.clear"  // delete performance stats or all query history
)

// syncLists makes every node in a cluster filter with exactly the same
// list contents: the leader downloads lists, and the others copy its copy
// of each one (by SHA-256) over the cluster link instead of downloading
// their own, which could differ. A node that can't reach the leader
// downloads lists itself, so filtering never depends on the cluster.
func syncLists(ctx context.Context, cl *cluster.Cluster, engine *filter.Engine, log *slog.Logger) {
	cl.ServeFiles(engine.FileBySHA)
	cl.Handle(peerListVersions, func(context.Context, json.RawMessage) (any, error) { return engine.Versions(), nil })
	var pending atomic.Bool
	cl.Handle(peerListsChanged, func(context.Context, json.RawMessage) (any, error) {
		if pending.CompareAndSwap(false, true) {
			go func() {
				defer pending.Store(false)
				if err := engine.Rebuild(ctx, false); err != nil {
					log.Warn("filter rebuild failed", "err", err)
				}
			}()
		}
		return nil, nil
	})
	engine.SetPeer(listPeer{cl})
	engine.SetOnRebuild(func(changed bool) {
		if !changed || cl.LocalStatus().LeaderID != cl.ID() {
			return
		}
		nctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for _, r := range cl.AskPeers(nctx, peerListsChanged, nil) {
			if r.Err != nil {
				log.Debug("couldn't tell a node about new lists; it catches up on its next refresh", "node", r.Name, "err", r.Err)
			}
		}
	})
}

// listPeer gets list versions and contents from the cluster leader.
type listPeer struct{ cl *cluster.Cluster }

func (p listPeer) Versions(ctx context.Context) (map[string]string, error) {
	raw, err := p.cl.AskLeader(ctx, peerListVersions, nil)
	if err != nil {
		return nil, err
	}
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func (p listPeer) Fetch(ctx context.Context, sha string, w io.Writer) error {
	return p.cl.FetchFromLeader(ctx, sha, w)
}

// setPause passes the pause on filtering in force on this node (its own,
// or the one for every node) to the DNS server.
func setPause(srv *server.Server, st *store.State, self string) {
	p, ok := st.PauseFor(self, time.Now())
	srv.SetPause(ok, p.Until)
}
