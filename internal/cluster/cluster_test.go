package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prezmc/dnserve/internal/store"
)

type node struct {
	t    *testing.T
	dir  string
	addr string
	st   *store.Store
	c    *Cluster
	// witness runs the node as a witness; noAdvertise leaves its address
	// to be learned when it joins.
	witness, noAdvertise bool
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startNode(t *testing.T, name string) *node {
	n := &node{t: t, dir: t.TempDir(), addr: freeAddr(t)}
	n.open(name)
	return n
}

func startWitness(t *testing.T, name string) *node {
	n := &node{t: t, dir: t.TempDir(), addr: freeAddr(t), witness: true}
	n.open(name)
	return n
}

func (n *node) open(name string) {
	t := n.t
	st, err := store.Open(n.dir)
	if err != nil {
		t.Fatal(err)
	}
	adv := n.addr
	if n.noAdvertise {
		adv = ""
	}
	c, err := Open(Options{DataDir: n.dir, Listen: n.addr, Advertise: adv, Name: name, Version: "test", Log: quiet(), Fast: true, Witness: n.witness}, st)
	if err != nil {
		t.Fatal(err)
	}
	n.st, n.c = st, c
	t.Cleanup(func() { n.close() })
}

func (n *node) close() {
	if n.c != nil {
		n.c.Close()
		n.c = nil
	}
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (n *node) apply(op string, d any) error {
	_, err := n.st.Apply(store.NewCommand(op, "test", d))
	return err
}

func (n *node) mustApply(op string, d any) {
	n.t.Helper()
	if err := n.apply(op, d); err != nil {
		n.t.Fatalf("%s: %v", op, err)
	}
}

func (n *node) leading() bool { return n.c.leaderID() == n.c.ID() }

func user(id, name string) store.UserCreate {
	return store.UserCreate{ID: id, Username: name, Role: store.RoleAdmin, PasswordHash: "h"}
}

func voters(t *testing.T, n *node) int {
	return n.c.Status(context.Background()).Voters
}

// pair starts a, makes it lead, and joins b to it.
func pair(t *testing.T) (*node, *node) {
	a := startNode(t, "alpha")
	waitFor(t, "a to lead and set up the cluster", func() bool { return a.leading() && a.st.State().Cluster.ID != "" })
	a.mustApply(store.OpUserCreate, user("u1", "admin"))

	b := startNode(t, "beta")
	code, _, err := a.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	name, err := b.c.Join(context.Background(), code, "")
	if err != nil {
		t.Fatal(err)
	}
	if name != "beta" {
		t.Fatalf("joined as %q", name)
	}
	waitFor(t, "b to receive the state", func() bool { return b.st.State().Users["u1"] != nil })
	waitFor(t, "b to become a voter", func() bool { return voters(t, a) == 2 })
	return a, b
}

func TestJoinReplicateAndForward(t *testing.T) {
	a, b := pair(t)
	if b.st.State().Cluster.ID != a.st.State().Cluster.ID {
		t.Fatal("b is in a different cluster")
	}
	// A change made on the follower goes through the leader and is
	// visible on the follower as soon as Apply returns.
	b.mustApply(store.OpUserCreate, store.UserCreate{ID: "u2", Username: "pat", Role: store.RoleViewer, PasswordHash: "h"})
	if b.st.State().Users["u2"] == nil {
		t.Fatal("follower doesn't see its own write")
	}
	waitFor(t, "a to get the write", func() bool { return a.st.State().Users["u2"] != nil })
	// Validation errors come back through the leader intact.
	if err := b.apply(store.OpUserDelete, store.IDOnly{ID: "nope"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forwarded error: %v", err)
	}
	// A join code works once.
	code, _, err := a.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	c := startNode(t, "gamma")
	if _, err := c.c.Join(context.Background(), code, ""); err != nil {
		t.Fatal(err)
	}
	d := startNode(t, "delta")
	if _, err := d.c.Join(context.Background(), code, ""); !errors.Is(err, store.ErrBadJoinCode) {
		t.Fatalf("reused join code: %v", err)
	}
	waitFor(t, "three voters", func() bool { return voters(t, a) == 3 })
}

func TestCodeForWrongClusterRejected(t *testing.T) {
	a := startNode(t, "alpha")
	waitFor(t, "a ready", func() bool { return a.leading() && a.st.State().Cluster.ID != "" })
	code, _, err := a.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	jc, _ := parseJoinCode(code)
	other := startNode(t, "other")
	waitFor(t, "other ready", func() bool { return other.leading() })
	jc.Addrs = []string{other.addr} // right secret, wrong cluster
	b := startNode(t, "beta")
	if _, err := b.c.Join(context.Background(), jc.String(), ""); err == nil {
		t.Fatal("joined a cluster whose CA doesn't match the code")
	}
}

func TestLeadershipControls(t *testing.T) {
	a, b := pair(t)
	waitFor(t, "a leads", a.leading)

	// Transfer to b.
	if err := a.c.TransferLeadership(b.c.ID()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b leads", b.leading)

	// Preferring a moves leadership back to it.
	b.mustApply(store.OpClusterPreferred, store.IDOnly{ID: a.c.ID()})
	waitFor(t, "a leads again (preferred)", func() bool { return a.leading() && b.c.leaderID() == a.c.ID() })
	if err := a.c.TransferLeadership(b.c.ID()); err == nil {
		t.Fatal("transfer away from the preferred leader allowed")
	}
	// Never-leader can't be set on the preferred node.
	nb := *a.st.State().Cluster.Nodes[a.c.ID()]
	nb.NeverLeader = true
	if err := a.apply(store.OpClusterNode, nb); err == nil {
		t.Fatal("preferred node set to never lead")
	}

	// b never leads: it stops voting, so a alone is a majority and keeps
	// taking changes with b switched off.
	n := *a.st.State().Cluster.Nodes[b.c.ID()]
	n.NeverLeader = true
	a.mustApply(store.OpClusterNode, n)
	waitFor(t, "b demoted", func() bool { return voters(t, a) == 1 })
	b.close()
	a.mustApply(store.OpUserCreate, store.UserCreate{ID: "u3", Username: "kim", Role: store.RoleViewer, PasswordHash: "h"})
}

func TestForceRecoverTwoNodes(t *testing.T) {
	a, b := pair(t)
	waitFor(t, "a leads", a.leading)
	a.close() // the leader dies

	// b alone has no majority: DNS state is intact but changes pause.
	waitFor(t, "b sees no leader", func() bool { return b.c.leaderID() == "" })
	if err := b.apply(store.OpUserCreate, store.UserCreate{ID: "u9", Username: "lee", Role: store.RoleViewer, PasswordHash: "h"}); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("write without quorum: %v", err)
	}
	if b.st.State().Users["u1"] == nil {
		t.Fatal("b lost its copy of the state")
	}

	// With two voters, the lost node can't have a majority alone, so
	// recovery needs no extra confirmation.
	if err := b.c.ForceRecover(context.Background(), "admin", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b leads", b.leading)
	b.mustApply(store.OpUserCreate, store.UserCreate{ID: "u9", Username: "lee", Role: store.RoleViewer, PasswordHash: "h"})
	cs := b.st.State().Cluster
	if len(cs.Nodes) != 1 || cs.Nodes[b.c.ID()] == nil {
		t.Fatalf("nodes after recovery: %v", cs.Nodes)
	}

	// The old leader comes back but is fenced off: it never gets a
	// majority, takes no changes, and b doesn't follow it.
	a.open("alpha")
	time.Sleep(time.Second)
	if a.leading() {
		t.Fatal("the node left behind became leader")
	}
	if err := a.apply(store.OpUserCreate, store.UserCreate{ID: "u10", Username: "max", Role: store.RoleViewer, PasswordHash: "h"}); err == nil {
		t.Fatal("the node left behind took a change")
	}
	if !b.leading() {
		t.Fatal("b lost leadership to the node left behind")
	}
	// It can rejoin with a new code (its state is replaced).
	code, _, err := b.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.Join(context.Background(), code, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a gets b's state", func() bool { return a.st.State().Users["u9"] != nil })
}

func TestForceRecoverRefusals(t *testing.T) {
	a, b := pair(t)
	if err := b.c.ForceRecover(context.Background(), "admin", false); err == nil {
		t.Fatal("recovery allowed with a working leader")
	}
	// b set to never lead, then a lost: a alone was a majority, so b
	// recovering could split the cluster. It needs explicit confirmation.
	n := *a.st.State().Cluster.Nodes[b.c.ID()]
	n.NeverLeader = true
	a.mustApply(store.OpClusterNode, n)
	waitFor(t, "b demoted", func() bool { return voters(t, a) == 1 })
	a.close()
	waitFor(t, "b sees no leader", func() bool { return b.c.leaderID() == "" })
	var risk *RiskError
	if err := b.c.ForceRecover(context.Background(), "admin", false); !errors.As(err, &risk) {
		t.Fatalf("want a risk warning, got %v", err)
	}
	if err := b.c.ForceRecover(context.Background(), "admin", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b leads", b.leading)
}

func TestRestartKeepsStateWithoutQuorum(t *testing.T) {
	a, b := pair(t)
	b.mustApply(store.OpUserCreate, store.UserCreate{ID: "u2", Username: "pat", Role: store.RoleViewer, PasswordHash: "h"})
	waitFor(t, "a has it", func() bool { return a.st.State().Users["u2"] != nil })
	audit := len(b.st.State().Audit)
	a.close()
	b.close()
	// b restarts alone: no leader, but it serves its full last state at
	// once, and replaying the log doesn't apply anything twice.
	b.open("beta")
	if b.st.State().Users["u2"] == nil {
		t.Fatal("restarted node lost state")
	}
	a.open("alpha")
	waitFor(t, "a leader again", func() bool { return a.c.leaderID() != "" && b.c.leaderID() != "" })
	time.Sleep(300 * time.Millisecond)
	if got := len(b.st.State().Audit); got != audit {
		t.Fatalf("audit grew from %d to %d on replay", audit, got)
	}
}

func TestUpgradeImportsExistingState(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(store.NewCommand(store.OpUserCreate, "test", user("old", "admin"))); err != nil {
		t.Fatal(err)
	}
	a := &node{t: t, dir: dir, addr: freeAddr(t)}
	a.open("alpha")
	waitFor(t, "cluster set up", func() bool { return a.st.State().Cluster.ID != "" })
	if a.st.State().Users["old"] == nil {
		t.Fatal("existing user lost on upgrade")
	}
	b := startNode(t, "beta")
	code, _, err := a.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.c.Join(context.Background(), code, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b gets the pre-cluster state", func() bool { return b.st.State().Users["old"] != nil })
}

func TestWitnessKeepsTwoNodesWorking(t *testing.T) {
	a, b := pair(t)
	w := &node{t: t, dir: t.TempDir(), addr: freeAddr(t), witness: true, noAdvertise: true}
	w.open("shed-pi")
	if w.c.leaderID() != "" || len(w.st.State().Cluster.Nodes) != 0 {
		t.Fatal("a witness started a cluster of its own")
	}
	code, _, err := a.c.CreateJoinCode("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.Join(context.Background(), code, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "three voters", func() bool { return voters(t, a) == 3 })
	wn := a.st.State().Cluster.Nodes[w.c.ID()]
	if !wn.Witness || wn.Addr != w.addr {
		t.Fatalf("witness recorded as %+v, want address %s learned from its connection", wn, w.addr)
	}
	if err := a.apply(store.OpClusterPreferred, store.IDOnly{ID: w.c.ID()}); err == nil {
		t.Fatal("witness made preferred leader")
	}
	if err := a.c.TransferLeadership(w.c.ID()); err == nil {
		t.Fatal("leadership handed to a witness")
	}
	if st := a.c.Status(context.Background()); st.Tolerates != 1 {
		t.Fatalf("tolerates %d, want 1", st.Tolerates)
	}

	// Losing the leader: b takes over with the witness's vote, and never
	// the witness itself for long.
	a.close()
	waitFor(t, "b leads", b.leading)
	b.mustApply(store.OpUserCreate, store.UserCreate{ID: "u5", Username: "sam", Role: store.RoleViewer, PasswordHash: "h"})
	waitFor(t, "witness has the change", func() bool { return w.st.State().Users["u5"] != nil })

	// Losing the other full node instead: the witness may win the
	// election, but hands leadership to a full node as soon as one is back.
	a.open("alpha")
	waitFor(t, "a back", func() bool { return a.st.State().Users["u5"] != nil })
	b.close()
	waitFor(t, "a leads", a.leading)
	a.mustApply(store.OpUserCreate, store.UserCreate{ID: "u6", Username: "joe", Role: store.RoleViewer, PasswordHash: "h"})
	time.Sleep(time.Second)
	if w.leading() {
		t.Fatal("witness kept leadership while a full node was up")
	}
}

func TestAskPeers(t *testing.T) {
	a, b := pair(t)
	b.c.Handle("echo", func(ctx context.Context, body json.RawMessage) (any, error) {
		var in map[string]string
		json.Unmarshal(body, &in)
		return map[string]string{"from": b.c.Name(), "got": in["q"]}, nil
	})
	reps := a.c.AskPeers(context.Background(), "echo", map[string]string{"q": "hi"})
	if len(reps) != 1 || reps[0].Err != nil {
		t.Fatalf("replies = %+v", reps)
	}
	var out map[string]string
	json.Unmarshal(reps[0].Body, &out)
	if out["got"] != "hi" || out["from"] != b.c.Name() || reps[0].Name != b.c.Name() {
		t.Fatalf("reply = %v", out)
	}
	// A node without the handler says so; a stopped node is reported, not waited on.
	if reps := b.c.AskPeers(context.Background(), "echo", nil); len(reps) != 1 || reps[0].Err == nil {
		t.Fatalf("missing handler: %+v", reps)
	}
	b.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if reps := a.c.AskPeers(ctx, "echo", nil); len(reps) != 1 || reps[0].Err == nil {
		t.Fatalf("stopped peer: %+v", reps)
	}
}
