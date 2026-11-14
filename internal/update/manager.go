package update

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Prefs are the owner's choices (store.UpdatePrefs, without importing the
// store).
type Prefs struct {
	Check    bool
	Auto     bool
	AutoHour int
	// Skip is a version that was rolled back; it isn't offered or
	// installed automatically until a newer one is out.
	Skip string
	// Channel is ChannelStable (numbered releases; "" too) or
	// ChannelLatest (every change merged to main).
	Channel string
}

// channel is the tag this node follows.
func (m *Manager) channel() string {
	if c := m.prefs().Channel; c == ChannelLatest {
		return c
	}
	return ChannelStable
}

// Member is one cluster node, for the rollout.
type Member struct {
	ID      string
	Name    string
	Leader  bool
	Witness bool
}

// Peers is how a node reaches the rest of the cluster (nil: one node).
type Peers interface {
	Self() string
	Members() []Member
	Ask(ctx context.Context, id, rpc string, in any) (json.RawMessage, error)
}

// RPC names between nodes.
const (
	RPCInfo  = "update.info"
	RPCStart = "update.start"
)

// NodeInfo is one server's version and updater, for the Updates page.
type NodeInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Self    bool   `json:"self,omitempty"`
	Witness bool   `json:"witness,omitempty"`
	Leader  bool   `json:"leader,omitempty"`
	Version string `json:"version,omitempty"`
	// Release is the release number ("1.2.3"), "" for a build of main.
	Release  string    `json:"release,omitempty"`
	Revision string    `json:"revision,omitempty"`
	Created  time.Time `json:"created,omitzero"`
	// Ready: answering DNS (a witness: in touch with the cluster).
	Ready bool `json:"ready"`
	// Updater is this server's updater (nil: none set up).
	Updater *SidecarStatus `json:"updater,omitempty"`
	// UpdaterError is why the updater couldn't be asked, when one seems
	// to be set up.
	UpdaterError string `json:"updater_error,omitempty"`
	// Behind: runs an older version than the newest release.
	Behind    bool   `json:"behind,omitempty"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// Manager checks for new versions and installs them.
type Manager struct {
	Version  string
	Registry *Registry
	Sidecar  *Client
	// Image is the reference to check when the updater can't say which
	// one this container runs (DNSERV_UPDATE_IMAGE, or DefaultImage).
	Image string
	// Ready reports whether this node is serving.
	Ready func() bool
	Prefs func() Prefs
	// Location is the cluster's time zone, for automatic updates.
	Location func() *time.Location
	// Peers is nil for a node on its own.
	Peers Peers
	// Audit records that an update or rollback started (nil: not
	// recorded).
	Audit func(by, revision string, servers []string, auto, rollback bool)
	// Backup saves a backup of the settings and accounts before anything
	// changes, and returns its file name ("" when backups aren't set up).
	Backup func() (string, error)
	// SetSkip records the version a rollback went back from ("" clears
	// it).
	SetSkip func(by, revision string)
	// StateFile keeps the last rollout across this node's own restart.
	StateFile string
	Log       *slog.Logger

	// GitHub lists what changed (tests point it elsewhere).
	GitHub    *http.Client
	GitHubAPI string
	// StepWait is how long one server gets to come back (default 6 min);
	// Poll how often it is asked (default 3s); Settle how long DNS gets
	// to warm up before the next server (default 10s).
	StepWait, Poll, Settle time.Duration

	mu        sync.Mutex
	latest    *Release
	checkedAt time.Time
	checkErr  string
	changes   map[string]*Changes
	notes     map[string][]ReleaseNote // by the newest release's revision
	rollout   *Rollout
	autoDay   string
}

// LocalInfo describes this node.
func (m *Manager) LocalInfo(ctx context.Context) NodeInfo {
	n := NodeInfo{Version: m.Version, Release: VersionOf(m.Version), Revision: RevisionOf(m.Version), Reachable: true, Self: true}
	if m.Ready != nil {
		n.Ready = m.Ready()
	}
	st, err := m.Sidecar.Status(ctx)
	switch {
	case errors.Is(err, ErrNoUpdater):
	case err != nil:
		n.UpdaterError = err.Error()
	default:
		n.Updater = st
		if st.Revision != "" && n.Revision == "" {
			n.Revision = st.Revision
		}
		n.Created = st.Created
	}
	return n
}

// image is the reference this node checks.
func (m *Manager) image(ctx context.Context) string {
	img := m.Image
	if img == "" {
		img = DefaultImage
	}
	if st, err := m.Sidecar.Status(ctx); err == nil && st.Image != "" && !st.Pinned {
		img = st.Image
	}
	return withTag(img, m.channel())
}

// Check asks the registry for the newest image now.
func (m *Manager) Check(ctx context.Context) (*Release, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	rel, err := m.Registry.Latest(ctx, m.image(ctx))
	m.mu.Lock()
	m.checkedAt = time.Now()
	if err != nil {
		m.checkErr = err.Error()
	} else {
		m.latest, m.checkErr = rel, ""
	}
	m.mu.Unlock()
	if err != nil {
		m.Log.Warn("couldn't check for a new version", "err", err)
		return nil, err
	}
	if from := RevisionOf(m.Version); from != "" && from != rel.Revision {
		m.changesFor(ctx, rel, from)
	}
	return rel, nil
}

func (m *Manager) changesFor(ctx context.Context, rel *Release, from string) *Changes {
	key := from + "..." + rel.Revision
	m.mu.Lock()
	c, ok := m.changes[key]
	m.mu.Unlock()
	if ok {
		return c
	}
	c, err := GitHubChanges(ctx, m.GitHub, m.GitHubAPI, rel.Source, from, rel.Revision)
	if err != nil {
		m.Log.Debug("couldn't list what changed", "err", err)
		return nil
	}
	m.mu.Lock()
	if m.changes == nil {
		m.changes = map[string]*Changes{}
	}
	m.changes[key] = c
	m.mu.Unlock()
	return c
}

// Latest is the last check's result.
func (m *Manager) Latest() (*Release, time.Time, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latest, m.checkedAt, m.checkErr
}

// Nodes asks every server about its version and updater.
func (m *Manager) Nodes(ctx context.Context) []NodeInfo {
	self := m.LocalInfo(ctx)
	var members []Member
	selfID := ""
	if m.Peers != nil {
		members, selfID = m.Peers.Members(), m.Peers.Self()
	}
	if len(members) == 0 {
		members = []Member{{ID: selfID, Name: "this server", Leader: true}}
	}
	out := make([]NodeInfo, len(members))
	var wg sync.WaitGroup
	for i, mb := range members {
		if mb.ID == selfID {
			out[i] = self
			out[i].ID, out[i].Name, out[i].Leader, out[i].Witness = mb.ID, mb.Name, mb.Leader, mb.Witness
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := m.askInfo(ctx, mb.ID)
			if err != nil {
				n = NodeInfo{Error: err.Error()}
			}
			n.ID, n.Name, n.Leader, n.Witness, n.Self = mb.ID, mb.Name, mb.Leader, mb.Witness, false
			out[i] = n
		}()
	}
	wg.Wait()
	rel, _, _ := m.Latest()
	for i := range out {
		out[i].Behind = rel != nil && out[i].Reachable && out[i].Revision != rel.Revision
	}
	slices.SortStableFunc(out, func(a, b NodeInfo) int {
		if a.Witness != b.Witness {
			if a.Witness {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func (m *Manager) askInfo(ctx context.Context, id string) (NodeInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	raw, err := m.Peers.Ask(ctx, id, RPCInfo, nil)
	if err != nil {
		return NodeInfo{}, err
	}
	var n NodeInfo
	if err := json.Unmarshal(raw, &n); err != nil {
		return NodeInfo{}, err
	}
	n.Reachable = true
	return n, nil
}

// HandleInfo answers RPCInfo.
func (m *Manager) HandleInfo(ctx context.Context, _ json.RawMessage) (any, error) {
	return m.LocalInfo(ctx), nil
}

// HandleStart answers RPCStart: update this node now, to the newest
// version or to {"revision": ...}.
func (m *Manager) HandleStart(ctx context.Context, body json.RawMessage) (any, error) {
	var req Request
	if len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	return m.Sidecar.Start(ctx, req)
}

// Changes lists what's new for this node (nil: unknown).
func (m *Manager) Changes(ctx context.Context) *Changes {
	rel, _, _ := m.Latest()
	from := RevisionOf(m.Version)
	if rel == nil || from == "" || from == rel.Revision {
		return nil
	}
	return m.changesFor(ctx, rel, from)
}

// Releases are the release notes from this node's version up to the
// newest release, on the releases channel (nil otherwise, or unknown).
func (m *Manager) Releases(ctx context.Context) []ReleaseNote {
	rel, _, _ := m.Latest()
	if rel == nil || m.channel() != ChannelStable {
		return nil
	}
	if _, ok := semver(rel.Version); !ok {
		return nil
	}
	m.mu.Lock()
	cached, ok := m.notes[rel.Revision]
	m.mu.Unlock()
	if !ok {
		all, err := GitHubReleases(ctx, m.GitHub, m.GitHubAPI, rel.Source)
		if err != nil {
			m.Log.Debug("couldn't read the release notes", "err", err)
			return nil
		}
		cached = all
		m.mu.Lock()
		m.notes = map[string][]ReleaseNote{rel.Revision: all}
		m.mu.Unlock()
	}
	return notesBetween(cached, VersionOf(m.Version), rel.Version)
}

// Run checks every few hours, and installs automatically when the owner
// turned that on, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	go m.resume(ctx)
	next := time.Now().Add(2 * time.Minute)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		p := m.prefs()
		if p.Check && time.Now().After(next) {
			next = time.Now().Add(6 * time.Hour)
			_, _ = m.Check(ctx)
		}
		if p.Auto {
			m.maybeAuto(ctx, p)
		}
	}
}

func (m *Manager) prefs() Prefs {
	if m.Prefs == nil {
		return Prefs{Check: true}
	}
	return m.Prefs()
}

// maybeAuto starts an automatic update at the owner's hour, from the
// leader only, at most once a day.
func (m *Manager) maybeAuto(ctx context.Context, p Prefs) {
	loc := time.Local
	if m.Location != nil {
		if l := m.Location(); l != nil {
			loc = l
		}
	}
	now := time.Now().In(loc)
	if now.Hour() != p.AutoHour {
		return
	}
	if m.Peers != nil {
		leader := false
		for _, mb := range m.Peers.Members() {
			if mb.Leader && mb.ID == m.Peers.Self() {
				leader = true
			}
		}
		if !leader {
			return
		}
	}
	day := now.Format(time.DateOnly)
	m.mu.Lock()
	done := m.autoDay == day
	m.autoDay = day
	m.mu.Unlock()
	if done {
		return
	}
	if _, err := m.Check(ctx); err != nil {
		return
	}
	if _, err := m.Install(ctx, "automatic updates", nil, true); err != nil && !errors.Is(err, ErrNothingToDo) {
		m.Log.Warn("automatic update didn't start", "err", err)
	}
}

func (m *Manager) saveRollout(r *Rollout) {
	if m.StateFile == "" {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	tmp := m.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, m.StateFile)
	}
}
