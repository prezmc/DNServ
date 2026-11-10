package filter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/prezmc/dnserve/internal/config"
)

// enginePeer is a Peer backed by another engine, standing in for the
// cluster link to the leader.
type enginePeer struct {
	leader  *Engine
	fetches atomic.Int32
	down    bool
}

func (p *enginePeer) Versions(context.Context) (map[string]string, error) {
	if p.down {
		return nil, errors.New("leader unreachable")
	}
	return p.leader.Versions(), nil
}

func (p *enginePeer) Fetch(_ context.Context, sha string, w io.Writer) error {
	p.fetches.Add(1)
	path, ok := p.leader.FileBySHA(sha)
	if !ok {
		return errors.New("no such file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func TestFollowerUsesLeadersListCopy(t *testing.T) {
	// The list changes between downloads, as real lists do: each request
	// gets a different version.
	var n atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			io.WriteString(w, "||a.example^\n||b.example^\n")
		default:
			io.WriteString(w, "||a.example^\n||b.example^\n||c.example^\n")
		}
	}))
	defer ts.Close()
	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "remote", URL: ts.URL, Enabled: true}}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	leader := NewEngine(cfg, t.TempDir(), ts.Client(), quiet)
	changed := make(chan bool, 4)
	leader.SetOnRebuild(func(c bool) { changed <- c })
	if err := leader.Rebuild(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !<-changed {
		t.Fatal("first build should report new list contents")
	}

	follower := NewEngine(cfg, t.TempDir(), ts.Client(), quiet)
	peer := &enginePeer{leader: leader}
	follower.SetPeer(peer)
	if err := follower.Rebuild(ctx, false); err != nil {
		t.Fatal(err)
	}
	if follower.Rules() != leader.Rules() || follower.Lookup("c.example").Blocked {
		t.Fatalf("follower has %d rules, leader %d: it should use the leader's copy, not download a newer one", follower.Rules(), leader.Rules())
	}
	st := follower.Status()[0]
	if !st.FromLeader || st.SHA256 != leader.Status()[0].SHA256 {
		t.Fatalf("follower status %+v", st)
	}
	// A refresh on the follower keeps following; with the same version
	// cached it needn't fetch again.
	if err := follower.Rebuild(ctx, true); err != nil {
		t.Fatal(err)
	}
	if peer.fetches.Load() != 1 || n.Load() != 1 {
		t.Fatalf("fetches from leader %d, downloads %d; want 1 and 1", peer.fetches.Load(), n.Load())
	}

	// The leader refreshes and gets the new version; the follower follows.
	if err := leader.Rebuild(ctx, true); err != nil {
		t.Fatal(err)
	}
	<-changed
	if err := follower.Rebuild(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !follower.Lookup("c.example").Blocked || follower.Rules() != leader.Rules() {
		t.Fatal("follower didn't pick up the leader's new version")
	}

	// Without the leader, a node downloads lists itself.
	alone := NewEngine(cfg, t.TempDir(), ts.Client(), quiet)
	alone.SetPeer(&enginePeer{leader: leader, down: true})
	if err := alone.Rebuild(ctx, false); err != nil {
		t.Fatal(err)
	}
	if alone.Rules() == 0 || alone.Status()[0].FromLeader {
		t.Fatalf("node without a leader: %d rules, status %+v", alone.Rules(), alone.Status()[0])
	}
}
