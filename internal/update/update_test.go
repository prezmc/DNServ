package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRef(t *testing.T) {
	for in, want := range map[string]Ref{
		"ghcr.io/prezmc/dnserv:latest": {Registry: "ghcr.io", Repo: "prezmc/dnserv", Tag: "latest"},
		"ghcr.io/prezmc/dnserv":        {Registry: "ghcr.io", Repo: "prezmc/dnserv", Tag: "latest"},
		"prezmcmahon/dnserv:1.2":       {Registry: "registry-1.docker.io", Repo: "prezmcmahon/dnserv", Tag: "1.2"},
		"alpine":                       {Registry: "registry-1.docker.io", Repo: "library/alpine", Tag: "latest"},
		"localhost:5000/dnserv":        {Registry: "localhost:5000", Repo: "dnserv", Tag: "latest"},
		"ghcr.io/x/y@sha256:abc":       {Registry: "ghcr.io", Repo: "x/y", Tag: "latest", Digest: "sha256:abc"},
	} {
		got, err := ParseRef(in)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

func TestRevisionOf(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	if RevisionOf("main-"+sha) != sha || RevisionOf("v1.0.0-"+sha) != sha || RevisionOf("dev") != "" {
		t.Fatal("RevisionOf")
	}
}

// fakeRegistry needs a token, like ghcr.io, and serves an index with or
// without annotations.
func fakeRegistry(t *testing.T, annotated bool, rev string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.URL.Query().Get("scope") != "repository:prezmc/dnserv:pull" {
				t.Errorf("scope %q", r.URL.Query().Get("scope"))
			}
			fmt.Fprint(w, `{"token":"tok"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/prezmc/dnserv/manifests/latest":
			w.Header().Set("Docker-Content-Digest", "sha256:index")
			ann := ""
			if annotated {
				ann = `"annotations":{"org.opencontainers.image.revision":"` + rev + `","org.opencontainers.image.created":"2026-11-14T10:00:00Z","org.opencontainers.image.source":"https://github.com/prezmc/DNServ"},`
			}
			fmt.Fprint(w, `{"mediaType":"application/vnd.oci.image.index.v1+json",`+ann+`"manifests":[
				{"digest":"sha256:arm","platform":{"os":"linux","architecture":"arm64"}},
				{"digest":"sha256:amd","platform":{"os":"linux","architecture":"amd64"}}]}`)
		case "/v2/prezmc/dnserv/manifests/sha256:amd":
			fmt.Fprint(w, `{"config":{"digest":"sha256:cfg"}}`)
		case "/v2/prezmc/dnserv/blobs/sha256:cfg":
			fmt.Fprint(w, `{"config":{"Labels":{"org.opencontainers.image.revision":"`+rev+`","org.opencontainers.image.source":"https://github.com/prezmc/DNServ"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRegistryLatest(t *testing.T) {
	for _, annotated := range []bool{true, false} {
		srv := fakeRegistry(t, annotated, "abc123")
		g := &Registry{Scheme: "http", Arch: "amd64"}
		rel, err := g.Latest(context.Background(), strings.TrimPrefix(srv.URL, "http://")+"/prezmc/dnserv:latest")
		if err != nil {
			t.Fatal(err)
		}
		if rel.Revision != "abc123" || rel.Digest != "sha256:index" || rel.Source != "https://github.com/prezmc/DNServ" {
			t.Fatalf("annotated=%v: %+v", annotated, rel)
		}
		if annotated && rel.Created.IsZero() {
			t.Fatal("created not read")
		}
	}
	if _, err := (&Registry{}).Latest(context.Background(), "ghcr.io/x/y@sha256:abc"); err == nil {
		t.Fatal("a pinned image has no newer version")
	}
}

func TestGitHubChanges(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/prezmc/DNServ/compare/aaa...bbb" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"html_url":"https://github.com/prezmc/DNServ/compare/aaa...bbb","total_commits":4,"commits":[
			{"commit":{"message":"Fix a thing"}},
			{"commit":{"message":"Merge pull request #70 from prezmc/x\n\nAnswer _dns.resolver.arpa locally"}},
			{"commit":{"message":"Another fix"}},
			{"commit":{"message":"Merge pull request #71 from prezmc/y\n\nAdd built-in updates"}}]}`)
	}))
	defer gh.Close()
	c, err := GitHubChanges(context.Background(), nil, gh.URL, "https://github.com/prezmc/DNServ", "aaa", "bbb")
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 4 || len(c.Items) != 2 || c.Items[0] != "Add built-in updates (#71)" {
		t.Fatalf("%+v", c)
	}
	if c, _ := GitHubChanges(context.Background(), nil, gh.URL, "https://gitlab.com/x/y", "aaa", "bbb"); c != nil {
		t.Fatal("only GitHub sources")
	}
}

func TestRecreateBody(t *testing.T) {
	id := "0123456789abcdef0123"
	inspect := `{"Id":"` + id + `","Name":"/dnserv","Image":"sha256:old",
		"Config":{"Hostname":"0123456789ab","Image":"ghcr.io/prezmc/dnserv:latest",
			"Env":["TZ=UTC","DNSERV_CONFIG=/data/dnserv.yaml","PATH=/usr/bin"],
			"Labels":{"com.docker.compose.project":"dnserv","com.docker.compose.image":"sha256:old","org.opencontainers.image.revision":"old"},
			"Cmd":null,"Entrypoint":["/usr/local/bin/dnserv"],"User":"dnserv"},
		"HostConfig":{"PortBindings":{"53/udp":[{"HostPort":"53"}]},"RestartPolicy":{"Name":"unless-stopped"},"NetworkMode":"dnserv_default"},
		"NetworkSettings":{"Networks":{"dnserv_default":{"Aliases":["dnserv","0123456789ab"],"IPAddress":"172.18.0.2"}}}}`
	var c Container
	_ = json.Unmarshal([]byte(inspect), &c)
	_ = json.Unmarshal([]byte(inspect), &c.Raw)
	img := &Image{Config: map[string]json.RawMessage{}}
	_ = json.Unmarshal([]byte(`{"Env":["DNSERV_CONFIG=/data/dnserv.yaml","PATH=/usr/bin"],"Entrypoint":["/usr/local/bin/dnserv"],"User":"dnserv","Labels":{"org.opencontainers.image.revision":"old"}}`), &img.Config)
	body, err := recreateBody(&c, img, "ghcr.io/prezmc/dnserv:latest", "sha256:new", "ghcr.io/prezmc/dnserv:latest")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	s := string(b)
	for _, want := range []string{`"Env":["TZ=UTC"]`, `"com.docker.compose.image":"sha256:new"`, `"com.docker.compose.project":"dnserv"`, `"HostPort":"53"`, `"Aliases":["dnserv"]`, `"Image":"ghcr.io/prezmc/dnserv:latest"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	for _, gone := range []string{"Hostname", "Entrypoint", `"User"`, "org.opencontainers.image.revision", "172.18.0.2", labelTrack} {
		if strings.Contains(s, gone) {
			t.Errorf("%s should come from the new image: %s", gone, s)
		}
	}
}

// fakePeers is a cluster of nodes, each a function of the rollout.
type fakePeers struct {
	self    string
	members []Member
	mu      sync.Mutex
	nodes   map[string]*NodeInfo
	started []string
	// onStart decides what a node does when told to update.
	onStart func(id string, n *NodeInfo)
}

func (p *fakePeers) Self() string      { return p.self }
func (p *fakePeers) Members() []Member { return p.members }
func (p *fakePeers) Ask(_ context.Context, id, rpc string, _ any) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.nodes[id]
	switch rpc {
	case RPCInfo:
		return json.Marshal(n)
	case RPCStart:
		p.started = append(p.started, id)
		j := &Job{State: JobPulling, Started: time.Now()}
		n.Updater.Job = j
		p.onStart(id, n)
		return json.Marshal(j)
	}
	return nil, fmt.Errorf("unknown %s", rpc)
}

// fakeSidecar serves the updater socket for this node.
func fakeSidecar(t *testing.T, st *SidecarStatus, started *atomic.Int32) string {
	dir, err := os.MkdirTemp("", "upd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st) })
	mux.HandleFunc("POST /v1/update", func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		writeJSON(w, 202, &Job{State: JobPulling, Started: time.Now()})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return path
}

func TestRollout(t *testing.T) {
	newRev, oldRev := "new0000", "old0000"
	reg := fakeRegistry(t, true, newRev)
	var selfStarts atomic.Int32
	sock := fakeSidecar(t, &SidecarStatus{Image: strings.TrimPrefix(reg.URL, "http://") + "/prezmc/dnserv:latest", Revision: oldRev}, &selfStarts)

	mk := func(rev string, updater bool) *NodeInfo {
		n := &NodeInfo{Revision: rev, Ready: true}
		if updater {
			n.Updater = &SidecarStatus{Revision: rev}
		}
		return n
	}
	peers := &fakePeers{self: "a",
		members: []Member{{ID: "a", Name: "alpha"}, {ID: "b", Name: "bravo", Leader: true}, {ID: "c", Name: "charlie"}, {ID: "w", Name: "witness", Witness: true}, {ID: "d", Name: "delta"}},
		nodes:   map[string]*NodeInfo{"b": mk(oldRev, true), "c": mk(oldRev, true), "w": mk(oldRev, true), "d": mk(newRev, true)},
	}
	peers.onStart = func(id string, n *NodeInfo) {
		// Comes back on the new version, done.
		n.Revision = newRev
		n.Updater.Job.State, n.Updater.Job.Finished = JobDone, time.Now()
	}
	var audited []string
	m := &Manager{
		Version: "main-" + oldRev, Registry: &Registry{Scheme: "http", Arch: "amd64"}, Sidecar: NewClient(sock),
		Ready: func() bool { return true }, Peers: peers, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:     func(by, rev string, servers []string, auto, rollback bool) { audited = servers },
		Backup:    func() (string, error) { return "dnserv-alpha-before.dnsbak", nil },
		StateFile: filepath.Join(t.TempDir(), "rollout.json"),
		Poll:      time.Millisecond, Settle: time.Millisecond, StepWait: time.Second,
		GitHubAPI: "http://127.0.0.1:1", // not reachable: no change list
	}
	// "a" reports revision from its version, which isn't a 40-char sha
	// in this test; give it one the fake registry knows as old.
	m.Version = "dev"
	if _, err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := m.Install(context.Background(), "admin", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, s := range r.Steps {
		order = append(order, s.Name)
	}
	// Witness, follower, leader, then this node; delta is current.
	if strings.Join(order, ",") != "witness,charlie,bravo,alpha" || strings.Join(audited, ",") != "witness,charlie,bravo,alpha" {
		t.Fatalf("order %v, audited %v", order, audited)
	}
	deadline := time.Now().Add(5 * time.Second)
	for selfStarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	peers.mu.Lock()
	started := strings.Join(peers.started, ",")
	peers.mu.Unlock()
	if selfStarts.Load() != 1 || started != "w,c,b" {
		t.Fatalf("self %d, peers %v", selfStarts.Load(), started)
	}
	ro := m.Rollout()
	if ro.State != RolloutRunning || ro.Steps[3].State != StepRestarting || ro.Steps[0].State != StepDone {
		t.Fatalf("%+v", ro)
	}

	// After this node restarts on the new version, the record finishes.
	m2 := &Manager{Version: "main-" + strings.Repeat("e", 40), Sidecar: NewClient(sock), StateFile: m.StateFile, Log: m.Log, Poll: time.Millisecond}
	b, _ := os.ReadFile(m.StateFile)
	var saved Rollout
	_ = json.Unmarshal(b, &saved)
	saved.Revision = strings.Repeat("e", 40)
	b, _ = json.Marshal(saved)
	_ = os.WriteFile(m.StateFile, b, 0o600)
	for i := range saved.Steps {
		saved.Steps[i].To = strings.Repeat("e", 40)
	}
	b, _ = json.Marshal(saved)
	_ = os.WriteFile(m.StateFile, b, 0o600)
	m2.resume(context.Background())
	ro = m2.Rollout()
	if ro.State != RolloutDone || ro.Steps[3].State != StepDone || ro.Message != "4 of 4 servers updated" || ro.Backup != "dnserv-alpha-before.dnsbak" {
		t.Fatalf("after restart: %+v", ro)
	}
}

func TestRollBack(t *testing.T) {
	oldRev, newRev := "0123456789abcdef0123456789abcdef01234567", "fedcba9876543210fedcba9876543210fedcba98"
	var selfStarts atomic.Int32
	sock := fakeSidecar(t, &SidecarStatus{Revision: newRev}, &selfStarts)
	peers := &fakePeers{self: "a",
		members: []Member{{ID: "a", Name: "alpha", Leader: true}, {ID: "b", Name: "bravo"}},
		nodes:   map[string]*NodeInfo{"b": {Revision: newRev, Ready: true, Updater: &SidecarStatus{}}},
	}
	var asked []string
	peers.onStart = func(id string, n *NodeInfo) {
		n.Revision = oldRev
		n.Updater.Job.State, n.Updater.Job.Finished = JobDone, time.Now()
	}
	skipped := ""
	m := &Manager{Version: "main-" + newRev, Sidecar: NewClient(sock), Peers: peers, Registry: &Registry{},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Poll: time.Millisecond, Settle: time.Millisecond, StepWait: time.Second,
		SetSkip: func(by, rev string) { skipped = rev },
		Backup:  func() (string, error) { return "before-rollback.dnsbak", nil }}
	if _, err := m.RollBack(context.Background(), "admin"); err != ErrNoRollback {
		t.Fatalf("nothing to roll back yet: %v", err)
	}
	// The last update moved both servers from oldRev to newRev.
	m.rollout = &Rollout{Revision: newRev, State: RolloutDone, Steps: []Step{
		{ID: "b", Name: "bravo", From: oldRev, To: newRev, State: StepDone},
		{ID: "a", Name: "alpha", Self: true, From: oldRev, To: newRev, State: StepDone}}}
	if !m.CanRollBack() {
		t.Fatal("should offer a rollback")
	}
	r, err := m.RollBack(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Rollback || r.Steps[0].Name != "bravo" || r.Steps[0].To != oldRev || !r.Steps[1].Self || skipped != newRev || r.Backup != "before-rollback.dnsbak" {
		t.Fatalf("%+v skipped=%q", r, skipped)
	}
	deadline := time.Now().Add(5 * time.Second)
	for selfStarts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	_ = asked
	if selfStarts.Load() != 1 || m.Rollout().Steps[0].State != StepDone {
		t.Fatalf("%+v", m.Rollout())
	}
	if m.CanRollBack() {
		t.Fatal("a rollback isn't rolled back")
	}
	// A failing backup stops everything before any server changes.
	m.rollout.State = RolloutDone
	m.rollout.Rollback = false
	m.Backup = func() (string, error) { return "", fmt.Errorf("disk full") }
	if _, err := m.RollBack(context.Background(), "admin"); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("backup failure: %v", err)
	}
}

func TestRevisionRef(t *testing.T) {
	ref, err := revisionRef("ghcr.io/prezmc/dnserv:latest", "cae8b50aaaa")
	if err != nil || ref != "ghcr.io/prezmc/dnserv:sha-cae8b50" {
		t.Fatal(ref, err)
	}
	if _, err := revisionRef("ghcr.io/prezmc/dnserv:latest", "latest; rm -rf"); err == nil {
		t.Fatal("only hex versions")
	}
}

func TestRolloutStopsAtFailure(t *testing.T) {
	newRev, oldRev := "new0000", "old0000"
	reg := fakeRegistry(t, true, newRev)
	var selfStarts atomic.Int32
	sock := fakeSidecar(t, &SidecarStatus{Image: strings.TrimPrefix(reg.URL, "http://") + "/prezmc/dnserv:latest", Revision: oldRev}, &selfStarts)
	peers := &fakePeers{self: "a",
		members: []Member{{ID: "a", Name: "alpha", Leader: true}, {ID: "b", Name: "bravo"}},
		nodes:   map[string]*NodeInfo{"b": {Revision: oldRev, Ready: true, Updater: &SidecarStatus{}}},
	}
	peers.onStart = func(id string, n *NodeInfo) {
		n.Updater.Job.State, n.Updater.Job.Message, n.Updater.Job.Finished = JobRolledBack, "the new version stopped with exit code 1, so the old version is running again", time.Now()
	}
	m := &Manager{Version: "dev", Registry: &Registry{Scheme: "http", Arch: "amd64"}, Sidecar: NewClient(sock), Peers: peers,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Poll: time.Millisecond, Settle: time.Millisecond, StepWait: time.Second, GitHubAPI: "http://127.0.0.1:1"}
	if _, err := m.Install(context.Background(), "admin", nil, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Rollout().State == RolloutRunning && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	ro := m.Rollout()
	if ro.State != RolloutFailed || selfStarts.Load() != 0 || ro.Steps[1].State != StepWaiting {
		t.Fatalf("this node must not update after bravo failed: %+v, self starts %d", ro, selfStarts.Load())
	}
	if _, err := m.Install(context.Background(), "admin", []string{"zzz"}, false); err != ErrNothingToDo {
		t.Fatalf("nothing picked: %v", err)
	}
}
