// Package cluster replicates a node's managed state (users, settings,
// devices, groups, rules) to other nodes with embedded Raft.
//
// Every node runs Raft, even alone: a single node is a one-member
// cluster, so adding a second one needs no restart. Commands from the
// store go through the Raft log and are applied on every node in the same
// order. Nodes talk over one port with mutual TLS, using certificates from
// a private cluster CA; a new node joins with a one-time code made in the
// dashboard, so there are no files to copy between servers.
//
// DNS never depends on the cluster: each node answers from its own copy
// of the state, so a node that loses the others keeps filtering with the
// last settings it had. Only changes need a working cluster.
package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/store"
)

// Options configure a node's cluster membership.
type Options struct {
	DataDir string
	// Listen is the cluster listener, like ":8081".
	Listen string
	// Advertise, when set, is how other nodes reach this one. Otherwise
	// it is learned from the address the dashboard is opened at.
	Advertise string
	// Name is this node's display name when it is first created.
	Name    string
	Version string
	Log     *slog.Logger
	// Witness runs this node as a witness: it votes and keeps the log so
	// two full nodes keep a majority when one is down, but it never
	// starts a cluster of its own and hands leadership to a full node.
	Witness bool
	// Fast shortens Raft timeouts (tests).
	Fast bool
}

// Cluster is this node's membership and its Raft instance.
type Cluster struct {
	opt   Options
	st    *store.Store
	dir   string
	log   *slog.Logger
	hlog  hclog.Logger
	creds atomic.Pointer[creds]
	// learned mirrors id.Advertise, readable without c.mu (Raft asks for
	// the address while c.mu is held during start).
	learned atomic.Pointer[string]

	mu        sync.Mutex // guards id and the Raft instance across restarts
	id        identity
	r         *raft.Raft
	bolt      *raftboltdb.BoltStore
	trans     *raft.NetworkTransport
	startedAt time.Time

	ln     net.Listener
	mux    *mux
	rpcSrv *http.Server
	client atomic.Pointer[http.Client]

	// Leader bookkeeping, used only by the run loop.
	leaderSince  time.Time
	lastTransfer atomic.Int64 // unix nanoseconds; also set by RPC handlers
	lastAddrSync time.Time
	wasLeader    string

	kick   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// identity is this node's own, unreplicated, cluster file.
type identity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Advertise is the address learned from the dashboard.
	Advertise string `json:"advertise,omitempty"`
	ClusterID string `json:"cluster_id"`
	// Joined is set once this node has joined another node's cluster. It
	// then never starts a cluster of its own, even with an empty log.
	Joined  bool   `json:"joined,omitempty"`
	CertPEM string `json:"cert"`
	KeyPEM  string `json:"key"`
	CAPEM   string `json:"ca"`
	// PendingCAKey is the CA key of a cluster this node started, kept
	// until the cluster.init command has put it in the replicated state.
	PendingCAKey string `json:"pending_ca_key,omitempty"`
}

// Open starts the node's cluster listener and Raft, and routes the
// store's changes through Raft.
func Open(opt Options, st *store.Store) (*Cluster, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	lvl := hclog.Warn
	if opt.Log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = hclog.Debug
	}
	c := &Cluster{
		opt: opt, st: st, dir: filepath.Join(opt.DataDir, "cluster"), log: opt.Log,
		hlog: hclog.New(&hclog.LoggerOptions{Name: "raft", Level: lvl, Output: os.Stderr}),
		kick: make(chan struct{}, 1),
	}
	if err := c.loadIdentity(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", opt.Listen)
	if err != nil {
		return nil, fmt.Errorf("cluster listener: %w", err)
	}
	c.ln = ln
	c.mux = newMux(ln, func() *tls.Config { return c.creds.Load().serverConfig() }, c.isMember, c.log)
	c.rpcSrv = &http.Server{Handler: c.rpcHandler(), ReadHeaderTimeout: 5 * time.Second, ConnContext: connContext}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	go c.mux.serve()
	go c.rpcSrv.Serve(c.mux.rpc)

	if err := c.startRaft(nil); err != nil {
		ln.Close()
		return nil, err
	}
	st.SetProposer(c)
	st.Subscribe(func(old, new *store.State) {
		if old.Cluster.Preferred != new.Cluster.Preferred || len(old.Cluster.Nodes) != len(new.Cluster.Nodes) || nodesChanged(old, new) {
			c.poke()
		}
	})
	c.wg.Add(1)
	go c.run()
	c.log.Info("cluster listening", "addr", ln.Addr().String(), "node", c.id.Name, "advertise", c.advertise())
	return c, nil
}

func nodesChanged(a, b *store.State) bool {
	for id, n := range b.Cluster.Nodes {
		o := a.Cluster.Nodes[id]
		if o == nil || o.Addr != n.Addr || o.NeverLeader != n.NeverLeader {
			return true
		}
	}
	return false
}

// Close stops Raft and the listener.
func (c *Cluster) Close() error {
	c.cancel()
	c.wg.Wait()
	c.st.SetProposer(nil)
	c.mu.Lock()
	err := c.stopRaftLocked()
	c.mu.Unlock()
	c.ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.rpcSrv.Shutdown(ctx)
	return err
}

// ID returns this node's ID.
func (c *Cluster) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id.ID
}

// Addr is the cluster listener's local address.
func (c *Cluster) Addr() string { return c.ln.Addr().String() }

func (c *Cluster) poke() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// --- identity ---

var containerID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func (c *Cluster) loadIdentity() error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(c.dir, "identity.json"))
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &c.id); err != nil {
			return fmt.Errorf("read cluster identity: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		// A new node: start its own one-node cluster with a new CA.
		id := c.id
		id.ID = auth.RandomID(8)
		id.Name = c.opt.Name
		if id.Name == "" {
			h, _ := os.Hostname()
			if h == "" || containerID.MatchString(h) {
				h = "node-" + strings.ToLower(id.ID[:4])
			}
			id.Name = h
		}
		id.ClusterID = auth.RandomID(8)
		ca, caKey, err := newCA(id.ClusterID)
		if err != nil {
			return err
		}
		key, err := newKey()
		if err != nil {
			return err
		}
		cert, err := issue(ca, caKey, id.ID, &key.PublicKey)
		if err != nil {
			return err
		}
		id.CertPEM, id.KeyPEM, id.CAPEM, id.PendingCAKey = cert, keyPEM(key), ca, caKey
		c.id = id
		if err := c.saveIdentityLocked(); err != nil {
			return err
		}
	default:
		return err
	}
	c.setLearnedLocked(c.id.Advertise)
	cr, err := loadCreds(c.id.CertPEM, c.id.KeyPEM, c.id.CAPEM)
	if err != nil {
		return fmt.Errorf("cluster certificate: %w", err)
	}
	c.creds.Store(cr)
	c.client.Store(c.newClient(cr))
	return nil
}

func (c *Cluster) saveIdentityLocked() error {
	b, err := json.MarshalIndent(c.id, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.dir, "identity.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.dir, "identity.json"))
}

// advertise is the address other nodes should use for this one.
func (c *Cluster) advertise() string {
	if c.opt.Advertise != "" {
		return c.opt.Advertise
	}
	if a := c.learned.Load(); a != nil && *a != "" {
		return *a
	}
	return net.JoinHostPort(guessIP(), c.port())
}

// setLearnedLocked records a learned address; c.mu must be held.
func (c *Cluster) setLearnedLocked(a string) {
	c.id.Advertise = a
	c.learned.Store(&a)
}

// AdvertiseLearned reports whether the address came from the config or
// the dashboard (true) or is only a guess (false).
func (c *Cluster) AdvertiseLearned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opt.Advertise != "" || c.id.Advertise != ""
}

func (c *Cluster) port() string {
	_, p, err := net.SplitHostPort(c.opt.Listen)
	if err != nil || p == "" || p == "0" {
		if c.ln != nil {
			_, p, _ = net.SplitHostPort(c.ln.Addr().String())
		}
	}
	return p
}

// LearnHost records host (from the dashboard's URL) as the address other
// nodes use, unless the config sets one. Loopback names are ignored.
func (c *Cluster) LearnHost(host string) {
	if c.opt.Advertise != "" {
		return
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if !usableHost(host) {
		return
	}
	a := net.JoinHostPort(host, c.port())
	c.mu.Lock()
	changed := c.id.Advertise != a
	if changed {
		c.setLearnedLocked(a)
		_ = c.saveIdentityLocked()
	}
	c.mu.Unlock()
	if changed {
		c.log.Info("cluster address learned from the dashboard", "advertise", a)
		c.poke()
	}
}

func usableHost(h string) bool {
	if h == "" || strings.EqualFold(h, "localhost") || strings.ContainsAny(h, " /") {
		return false
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return false
	}
	return true
}

func guessIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return n.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// --- Raft lifecycle ---

func (c *Cluster) raftDir() string { return filepath.Join(c.dir, "raft") }

func (c *Cluster) raftConfig() *raft.Config {
	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(c.id.ID)
	conf.Logger = c.hlog
	conf.SnapshotThreshold = 2048
	conf.TrailingLogs = 2048
	if c.opt.Fast {
		conf.HeartbeatTimeout = 150 * time.Millisecond
		conf.ElectionTimeout = 150 * time.Millisecond
		conf.LeaderLeaseTimeout = 100 * time.Millisecond
		conf.CommitTimeout = 5 * time.Millisecond
	}
	return conf
}

// startRaft opens the log and starts Raft. A node with no log that has
// never joined another cluster starts its own. With recover set, the log
// is first rewritten to that configuration (forced recovery).
func (c *Cluster) startRaft(recover *raft.Configuration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(c.raftDir(), 0o700); err != nil {
		return err
	}
	bolt, err := raftboltdb.NewBoltStore(filepath.Join(c.raftDir(), "raft.db"))
	if err != nil {
		return fmt.Errorf("open raft log: %w", err)
	}
	fail := func(err error) error { bolt.Close(); return err }
	snaps, err := raft.NewFileSnapshotStoreWithLogger(c.raftDir(), 2, c.hlog)
	if err != nil {
		return fail(err)
	}
	logs, err := raft.NewLogCache(256, bolt)
	if err != nil {
		return fail(err)
	}
	sl := &streamLayer{
		chanListener: newChanListener(c.ln.Addr()),
		advertise:    c.advertise,
		dialConf:     func() *tls.Config { return c.creds.Load().clientConfig(alpnRaft) },
	}
	trans := raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: sl, MaxPool: 3, Timeout: 10 * time.Second, Logger: c.hlog})
	conf := c.raftConfig()

	// The store keeps the index it has applied, so it doesn't need the
	// snapshot unless it is behind it (state.json lost or older).
	if list, err := snaps.List(); err == nil && len(list) > 0 {
		conf.NoSnapshotRestoreOnStart = c.st.State().RaftIndex >= list[0].Index
	}
	f := &fsm{st: c.st}
	if recover != nil {
		if err := raft.RecoverCluster(conf, f, logs, bolt, snaps, trans, *recover); err != nil {
			trans.Close()
			return fail(fmt.Errorf("recover: %w", err))
		}
		conf.NoSnapshotRestoreOnStart = true // the store is already up to date
	}
	existing, err := raft.HasExistingState(logs, bolt, snaps)
	if err != nil {
		trans.Close()
		return fail(err)
	}
	if !existing && !c.id.Joined && !c.opt.Witness {
		boot := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: conf.LocalID, Address: raft.ServerAddress(c.advertiseLocked())}}}
		if err := raft.BootstrapCluster(conf, logs, bolt, snaps, trans, boot); err != nil {
			trans.Close()
			return fail(fmt.Errorf("start cluster: %w", err))
		}
	}
	c.mux.setRaft(sl)
	r, err := raft.NewRaft(conf, f, logs, bolt, snaps, trans)
	if err != nil {
		c.mux.setRaft(nil)
		trans.Close()
		return fail(fmt.Errorf("start raft: %w", err))
	}
	c.r, c.bolt, c.trans, c.startedAt = r, bolt, trans, time.Now()
	return nil
}

// advertiseLocked is advertise; kept for callers holding c.mu.
func (c *Cluster) advertiseLocked() string { return c.advertise() }

func (c *Cluster) stopRaftLocked() error {
	if c.r == nil {
		return nil
	}
	err := c.r.Shutdown().Error()
	c.mux.setRaft(nil)
	c.trans.Close()
	c.bolt.Close()
	c.r, c.bolt, c.trans = nil, nil, nil
	return err
}

func (c *Cluster) raft() *raft.Raft {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.r
}

// --- the state machine ---

type fsm struct{ st *store.Store }

type applyResult struct {
	res any
	err error
}

func (f *fsm) Apply(l *raft.Log) any {
	var cmd store.Command
	if err := json.Unmarshal(l.Data, &cmd); err != nil {
		return applyResult{err: fmt.Errorf("bad log entry %d: %w", l.Index, err)}
	}
	res, err := f.st.ApplyRaft(l.Index, cmd)
	return applyResult{res: res, err: err}
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) { return snapshot{f.st.State()}, nil }

func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	st := store.NewState()
	if err := json.NewDecoder(rc).Decode(st); err != nil {
		return err
	}
	return f.st.Replace(st)
}

type snapshot struct{ st *store.State }

func (s snapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.st); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s snapshot) Release() {}

// --- proposing changes ---

// Propose implements store.Proposer: the command is committed through the
// leader and applied here before Propose returns.
func (c *Cluster) Propose(cmd store.Command) (any, error) {
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := c.raft()
		if r == nil {
			return nil, store.ErrUnavailable
		}
		if r.State() == raft.Leader {
			f := r.Apply(data, 5*time.Second)
			if err := f.Error(); err != nil {
				if errors.Is(err, raft.ErrNotLeader) && time.Now().Before(deadline) {
					continue // lost leadership before the entry was stored; it wasn't applied
				}
				return nil, fmt.Errorf("%w (%v)", store.ErrUnavailable, err)
			}
			ar, _ := f.Response().(applyResult)
			return ar.res, ar.err
		}
		if lid := c.leaderID(); lid != "" {
			res, index, err := c.forwardApply(lid, data)
			if errors.Is(err, errRetry) && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if errors.Is(err, errRetry) {
				return nil, store.ErrUnavailable
			}
			if index > 0 {
				// Read your own writes: wait for the entry to reach this node.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = c.st.WaitIndex(ctx, index)
				cancel()
			}
			return res, err
		}
		// No leader. Wait out an election, but fail fast when the
		// cluster has plainly lost quorum.
		c.mu.Lock()
		young := time.Since(c.startedAt) < 5*time.Second
		c.mu.Unlock()
		recent := time.Since(r.LastContact()) < 3*time.Second
		if (!young && !recent) || time.Now().After(deadline) {
			return nil, store.ErrUnavailable
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *Cluster) leaderID() string {
	r := c.raft()
	if r == nil {
		return ""
	}
	_, id := r.LeaderWithID()
	return string(id)
}

// addrOf finds a node's cluster address: from the replicated node list,
// else Raft's configuration.
func (c *Cluster) addrOf(id string) string {
	if n := c.st.State().Cluster.Nodes[id]; n != nil && n.Addr != "" {
		return n.Addr
	}
	if r := c.raft(); r != nil {
		if f := r.GetConfiguration(); f.Error() == nil {
			for _, s := range f.Configuration().Servers {
				if string(s.ID) == id {
					return string(s.Address)
				}
			}
		}
	}
	return ""
}

// --- the run loop: leader housekeeping ---

func (c *Cluster) run() {
	defer c.wg.Done()
	t := time.NewTicker(2 * time.Second)
	if c.opt.Fast {
		t.Reset(200 * time.Millisecond)
	}
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		case <-c.kick:
		}
		c.tick()
	}
}

func (c *Cluster) tick() {
	r := c.raft()
	if r == nil {
		return
	}
	leader := c.leaderID()
	if leader != c.wasLeader {
		st := c.st.State()
		switch {
		case leader == "":
			c.log.Warn("cluster has no leader; DNS keeps working, changes are paused until it has one")
		case leader == c.ID():
			c.log.Info("this node is now the cluster leader")
		default:
			c.log.Info("cluster leader", "node", st.Cluster.NodeName(leader))
		}
		c.wasLeader = leader
		if leader == c.ID() {
			c.leaderSince = time.Now()
		}
	}
	if leader == "" {
		return
	}
	if leader == c.ID() {
		c.ensureInit()
		c.reconcile(r)
	}
	c.syncAddr()
}

// ensureInit puts the cluster's CA and this node into the replicated
// state the first time it leads. A node from before clustering brings its
// state along, so nodes that join later receive it through the log.
func (c *Cluster) ensureInit() {
	st := c.st.State()
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()
	if st.Cluster.ID != "" {
		if id.PendingCAKey != "" && st.Cluster.CACert == id.CAPEM {
			c.mu.Lock()
			c.id.PendingCAKey = ""
			_ = c.saveIdentityLocked()
			c.mu.Unlock()
		}
		return
	}
	if id.PendingCAKey == "" {
		return // joined node: the cluster's leader initializes it
	}
	init := store.ClusterInit{ID: id.ClusterID, CACert: id.CAPEM, CAKey: id.PendingCAKey,
		Node: store.Node{ID: id.ID, Name: id.Name, Addr: c.advertise()}}
	if st.Version > 0 {
		init.Import = st
	}
	if _, err := c.st.Apply(store.NewCommand(store.OpClusterInit, "system", init)); err != nil {
		c.log.Warn("cluster setup failed; will retry", "err", err)
	}
}

// syncAddr keeps this node's address in the replicated list current.
func (c *Cluster) syncAddr() {
	n := c.st.State().Cluster.Nodes[c.ID()]
	adv := c.advertise()
	if n == nil || n.Addr == adv || time.Since(c.lastAddrSync) < 5*time.Second {
		return
	}
	c.lastAddrSync = time.Now()
	upd := *n
	upd.Addr = adv
	if _, err := c.st.Apply(store.NewCommand(store.OpClusterNode, "system", upd)); err != nil {
		c.log.Debug("address update failed", "err", err)
	}
}

// reconcile moves Raft's membership towards the replicated node list. New
// nodes join as non-voters and are promoted once they have caught up, so
// a node that fails to start never costs the cluster its quorum.
func (c *Cluster) reconcile(r *raft.Raft) {
	f := r.GetConfiguration()
	if f.Error() != nil {
		return
	}
	cfg := f.Configuration()
	st := c.st.State()
	want := st.Cluster.Nodes
	if len(want) == 0 {
		return
	}
	self := c.ID()
	have := map[string]raft.Server{}
	voters := 0
	for _, s := range cfg.Servers {
		have[string(s.ID)] = s
		if s.Suffrage == raft.Voter {
			voters++
		}
	}
	const wait = 5 * time.Second
	for id := range have {
		if want[id] == nil && id != self {
			c.log.Info("removing node from raft", "id", id)
			if err := r.RemoveServer(raft.ServerID(id), 0, wait).Error(); err != nil {
				c.log.Warn("remove node", "id", id, "err", err)
			}
			return // one membership change per pass
		}
	}
	for id, n := range want {
		s, in := have[id]
		sid, addr := raft.ServerID(id), raft.ServerAddress(n.Addr)
		switch {
		case !in:
			c.log.Info("adding node", "node", n.Name, "addr", n.Addr)
			if err := r.AddNonvoter(sid, addr, 0, wait).Error(); err != nil {
				c.log.Warn("add node", "node", n.Name, "err", err)
			}
			return
		case s.Address != addr:
			var err error
			if s.Suffrage == raft.Voter {
				err = r.AddVoter(sid, addr, 0, wait).Error()
			} else {
				err = r.AddNonvoter(sid, addr, 0, wait).Error()
			}
			if err != nil {
				c.log.Warn("update node address", "node", n.Name, "err", err)
			}
			return
		case !n.NeverLeader && s.Suffrage != raft.Voter:
			if c.caughtUp(r, id) {
				c.log.Info("node caught up; it now votes", "node", n.Name)
				if err := r.AddVoter(sid, addr, 0, wait).Error(); err != nil {
					c.log.Warn("promote node", "node", n.Name, "err", err)
				}
				return
			}
		case id == self && n.Witness && s.Suffrage == raft.Voter:
			if to := c.pickSuccessor(r, have, want); to != "" {
				c.transferTo(r, to, "a witness hands leadership to a full node")
				return
			}
		case n.NeverLeader && s.Suffrage == raft.Voter:
			if id == self {
				if to := c.pickSuccessor(r, have, want); to != "" {
					c.transferTo(r, to, "this node is set to never lead")
				}
				return
			}
			if voters > 1 {
				c.log.Info("node set to never lead; it no longer votes", "node", n.Name)
				if err := r.DemoteVoter(sid, 0, wait).Error(); err != nil {
					c.log.Warn("demote node", "node", n.Name, "err", err)
				}
				return
			}
		}
	}
	// Preferred leader.
	p := st.Cluster.Preferred
	if p != "" && p != self && have[p].Suffrage == raft.Voter && want[p] != nil &&
		time.Since(c.leaderSince) > 5*time.Second && time.Since(time.Unix(0, c.lastTransfer.Load())) > 30*time.Second && c.caughtUp(r, p) {
		c.transferTo(r, p, "handing over to the preferred leader")
	}
}

func (c *Cluster) pickSuccessor(r *raft.Raft, have map[string]raft.Server, want map[string]*store.Node) string {
	cs := c.st.State().Cluster
	if p := cs.Preferred; p != "" && have[p].Suffrage == raft.Voter && p != c.ID() && c.caughtUp(r, p) {
		return p
	}
	for id, s := range have {
		if id != c.ID() && s.Suffrage == raft.Voter && want[id] != nil && !want[id].NeverLeader && !want[id].Witness && c.caughtUp(r, id) {
			return id
		}
	}
	return ""
}

func (c *Cluster) transferTo(r *raft.Raft, id, why string) {
	c.lastTransfer.Store(time.Now().UnixNano())
	c.log.Info("transferring leadership", "to", c.st.State().Cluster.NodeName(id), "why", why)
	if err := r.LeadershipTransferToServer(raft.ServerID(id), raft.ServerAddress(c.addrOf(id))).Error(); err != nil {
		c.log.Warn("leadership transfer failed", "err", err)
	}
}

// caughtUp asks a peer how far it has applied the log.
func (c *Cluster) caughtUp(r *raft.Raft, id string) bool {
	ps, err := c.peerStatus(c.ctx, id, time.Second)
	return err == nil && ps.AppliedIndex+10 >= r.AppliedIndex()
}

// isMember reports whether a node may use Raft with this one. A node with
// no members yet (it is joining) accepts the cluster's nodes.
func (c *Cluster) isMember(nodeID string) bool {
	nodes := c.st.State().Cluster.Nodes
	return len(nodes) == 0 || nodes[nodeID] != nil
}

// Joined reports whether this node joined another node's cluster (rather
// than starting its own).
func (c *Cluster) Joined() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id.Joined
}

// Name is this node's display name.
func (c *Cluster) Name() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.st.State().Cluster.Nodes[c.id.ID]; n != nil {
		return n.Name
	}
	return c.id.Name
}
