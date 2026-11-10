//go:build failover

package failover

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// unavailable reports whether err is the "changes are paused" answer.
func unavailable(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusServiceUnavailable
}

func (l *lab) other(of string, among ...string) string {
	for _, n := range among {
		if n != of {
			return n
		}
	}
	l.t.Fatalf("no node other than %s", of)
	return ""
}

// waitLeader waits until node sees a leader other than not, and returns
// its name and how long it took.
func (l *lab) waitLeader(name, not string, timeout time.Duration) (string, time.Duration) {
	l.t.Helper()
	var leader string
	d := l.waitFor(name+" sees a new leader", timeout, func() bool {
		leader = l.leaderName(name)
		return leader != "" && leader != not
	})
	return leader, d
}

// fullLeader waits until the leader is a full node (a witness that wins
// an election hands leadership on) and returns its name.
func (l *lab) fullLeader(via string) string {
	l.t.Helper()
	var name string
	l.waitFor("a full node leads", 30*time.Second, func() bool {
		name = l.leaderName(via)
		return name != "" && !l.node(name).witness
	})
	return name
}

// waitChange retries a change through via until the cluster takes it.
func (l *lab) waitChange(via string, timeout time.Duration) (string, time.Duration) {
	l.t.Helper()
	var name string
	d := l.waitFor("a change through "+via, timeout, func() bool {
		var err error
		name, err = l.change(via)
		return err == nil
	})
	return name, d
}

// expectPaused checks that a change through via is refused with the
// "changes are paused" message, and how long the refusal took.
func (l *lab) expectPaused(via string, r *result) {
	l.t.Helper()
	var took time.Duration
	l.waitFor("changes on "+via+" refused as paused", 30*time.Second, func() bool {
		start := time.Now()
		_, err := l.change(via)
		took = time.Since(start)
		if err == nil {
			l.t.Fatalf("a change through %s went through, but it can't reach a majority", via)
		}
		return unavailable(err)
	})
	r.note("changes on %s paused (refused in %s)", via, took.Round(10*time.Millisecond))
}

// waitHealthy waits until every node in names is a reachable member and
// none is still catching up.
func (l *lab) waitHealthy(via string, names ...string) {
	l.t.Helper()
	l.waitFor("cluster healthy with "+via, 90*time.Second, func() bool {
		st, err := l.tryStatus(via)
		if err != nil || !st.Healthy {
			return false
		}
		ok := 0
		for _, m := range st.Nodes {
			for _, n := range names {
				if m.Name == n && m.Reachable && m.Role != "joining" && m.Role != "adding" && m.Behind == 0 {
					ok++
				}
			}
		}
		return ok == len(names)
	})
}

// TestTwoNodesAndWitness is the recommended set-up: two DNServ servers and
// a witness on a third machine.
func TestTwoNodesAndWitness(t *testing.T) {
	l := newLab(t)
	l.bootstrap("n1")
	l.probe.watch("n1")
	l.addNode("n2", "n1")
	l.probe.watch("n2")
	l.addWitness("w", "n1")
	l.waitHealthy("n1", "n1", "n2", "w")
	full := []string{"n1", "n2"}

	l.scenario("changes reach both nodes", func(r *result) {
		start := time.Now()
		l.mustChange("n1")
		r.note("change on n1 answered by both in %s", time.Since(start).Round(10*time.Millisecond))
		start = time.Now()
		l.mustChange("n2")
		r.note("change on n2 (a follower) answered by both in %s", time.Since(start).Round(10*time.Millisecond))
	})

	l.scenario("blocklists match on both nodes", func(r *result) {
		// A list server that hands out a new version on every download,
		// as busy real lists do.
		var hits atomic.Int32
		ln, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := hits.Add(1)
			fmt.Fprintf(w, "||ads.blocklab.example^\n")
			for i := int32(0); i < n; i++ {
				fmt.Fprintf(w, "||v%d.blocklab.example^\n", i+1)
			}
		})}
		go srv.Serve(ln)
		defer srv.Close()
		gw, err := docker("network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", l.prefix+"-lan")
		if err != nil {
			t.Fatal(err)
		}
		url := fmt.Sprintf("http://%s:%d/list.txt", gw, ln.Addr().(*net.TCPAddr).Port)
		if _, err := l.api("n1").do("PATCH", "/api/v1/settings", map[string]any{"lists": []map[string]any{{"name": "lab list", "url": url, "enabled": true}}}, nil); err != nil {
			t.Fatal(err)
		}
		same := func() (int, bool) {
			var a, b int
			var sa, sb string
			for i, n := range []string{"n1", "n2"} {
				var st struct {
					Filter struct {
						Rules int
						Lists []struct{ SHA256 string }
					}
				}
				if _, err := l.api(n).do("GET", "/api/v1/status", nil, &st); err != nil || len(st.Filter.Lists) == 0 {
					return 0, false
				}
				if i == 0 {
					a, sa = st.Filter.Rules, st.Filter.Lists[0].SHA256
				} else {
					b, sb = st.Filter.Rules, st.Filter.Lists[0].SHA256
				}
			}
			return a, a == b && sa == sb && sa != ""
		}
		start := time.Now()
		var rules int
		l.waitFor("both nodes on the same list version", 30*time.Second, func() bool { var ok bool; rules, ok = same(); return ok })
		r.note("list added: both nodes had the same %d rules after %s (%d download(s) from the list's server)", rules, time.Since(start).Round(10*time.Millisecond), hits.Load())
		for _, n := range []string{"n1", "n2"} {
			l.waitFor(n+" blocks the list's domain", 10*time.Second, func() bool {
				a, err := query(l.node(n).ip, "ads.blocklab.example.")
				return err == nil && len(a) > 0 && a[0] == "0.0.0.0"
			})
		}
		// "Update lists now" on a follower: the leader downloads, the
		// follower copies it.
		follower := l.other(l.fullLeader("n1"), full...)
		before := hits.Load()
		start = time.Now()
		if _, err := l.api(follower).do("POST", "/api/v1/lists/update", map[string]any{}, nil); err != nil {
			t.Fatal(err)
		}
		l.waitFor("both nodes on the new version", 30*time.Second, func() bool { n, ok := same(); return ok && n > rules })
		got, _ := same()
		r.note("update on %s: both nodes moved to the new version (%d rules) after %s, with %d download(s)", follower, got, time.Since(start).Round(10*time.Millisecond), hits.Load()-before)
		if hits.Load()-before != 1 {
			t.Errorf("an update made %d downloads from the list's server, want 1 (the leader's)", hits.Load()-before)
		}
	})

	l.scenario("leader server dies", func(r *result) {
		leader := l.fullLeader("n1")
		survivor := l.other(leader, full...)
		killed := time.Now()
		l.kill(leader)
		got, d := l.waitLeader(survivor, leader, 30*time.Second)
		r.note("%s killed; %s became leader after %s", leader, got, d.Round(10*time.Millisecond))
		name, _ := l.waitChange(survivor, 30*time.Second)
		r.note("changes worked again %s after the kill", time.Since(killed).Round(10*time.Millisecond))
		if l.node(got).witness {
			l.fullLeader(survivor)
			r.note("the witness handed leadership to %s %s after the kill", survivor, time.Since(killed).Round(10*time.Millisecond))
		}
		l.waitDNS(survivor, name, "10.53.1.1")
		start := time.Now()
		l.start(leader)
		r.note("%s restarted and answered DNS after %s", leader, time.Since(start).Round(10*time.Millisecond))
		d = l.waitDNS(leader, name, "10.53.1.1")
		r.note("caught up with the change it missed %s later", d.Round(10*time.Millisecond))
		l.waitHealthy(survivor, "n1", "n2", "w")
	})

	l.scenario("follower server dies", func(r *result) {
		leader := l.fullLeader("n1")
		follower := l.other(leader, full...)
		l.kill(follower)
		start := time.Now()
		name := l.mustChange(leader)
		r.note("%s killed; a change on %s took %s", follower, leader, time.Since(start).Round(10*time.Millisecond))
		l.start(follower)
		d := l.waitDNS(follower, name, "10.53.1.1")
		r.note("%s caught up %s after restarting", follower, d.Round(10*time.Millisecond))
		l.waitHealthy(leader, "n1", "n2", "w")
	})

	l.scenario("witness dies", func(r *result) {
		l.kill("w")
		start := time.Now()
		l.mustChange("n1")
		l.mustChange("n2")
		r.note("witness killed; changes on both nodes kept working (%s)", time.Since(start).Round(10*time.Millisecond))
		l.start("w")
		l.waitHealthy("n1", "n1", "n2", "w")
	})

	l.scenario("witness and one server down", func(r *result) {
		l.kill("w")
		l.kill("n2")
		l.expectPaused("n1", r)
		// Sign-in must still work on the node that's left.
		start := time.Now()
		l.node("n1").sess = nil
		l.session("n1")
		r.note("sign-in on n1 still worked (%s)", time.Since(start).Round(10*time.Millisecond))
		l.start("w")
		_, d := l.waitChange("n1", 60*time.Second)
		r.note("witness back: changes worked again after %s", d.Round(10*time.Millisecond))
		l.start("n2")
		l.waitHealthy("n1", "n1", "n2", "w")
	})

	l.scenario("network split between the servers", func(r *result) {
		leader := l.fullLeader("n1")
		other := l.other(leader, full...)
		l.isolate(leader)
		got, d := l.waitLeader(other, leader, 30*time.Second)
		r.note("%s cut off; %s became leader after %s", leader, got, d.Round(10*time.Millisecond))
		name, _ := l.waitChange(other, 30*time.Second)
		l.waitDNS(other, name, "10.53.1.1")
		l.expectPaused(leader, r)
		// The cut-off node keeps answering with what it had.
		if err := lookup(l.node(leader).ip, probeName); err != nil {
			t.Fatalf("%s stopped answering while cut off: %v", leader, err)
		}
		l.heal(leader)
		d = l.waitDNS(leader, name, "10.53.1.1")
		r.note("link restored; %s caught up after %s", leader, d.Round(10*time.Millisecond))
		l.waitHealthy(other, "n1", "n2", "w")
		l.mustChange(leader)
	})

	l.scenario("all three restart at once", func(r *result) {
		for _, n := range []string{"n1", "n2", "w"} {
			l.stop(n)
		}
		start := time.Now()
		for _, n := range []string{"n1", "n2", "w"} {
			l.start(n)
		}
		r.note("both nodes answered DNS with their saved settings %s after start", time.Since(start).Round(10*time.Millisecond))
		l.waitChange("n1", 60*time.Second)
		r.note("changes worked %s after start", time.Since(start).Round(10*time.Millisecond))
		l.waitHealthy("n1", "n1", "n2", "w")
	})

	l.scenario("upgrade one at a time", func(r *result) {
		// The order the guide recommends: witness, follower, then leader.
		leader := l.fullLeader("n1")
		order := []string{"w", l.other(leader, full...), leader}
		for _, n := range order {
			start := time.Now()
			l.recreate(n)
			l.waitHealthy(l.other(n, full...), "n1", "n2", "w")
			r.note("%s replaced and back in %s", n, time.Since(start).Round(10*time.Millisecond))
			l.mustChange(l.other(n, full...))
		}
	})
}

// TestTwoNodesOnly covers two servers without a witness: what still works
// when one is down, "Never lead", and recovering after a server is lost.
func TestTwoNodesOnly(t *testing.T) {
	l := newLab(t)
	l.bootstrap("n1")
	l.probe.watch("n1")
	l.addNode("n2", "n1")
	l.probe.watch("n2")
	l.waitHealthy("n1", "n1", "n2")

	l.scenario("one of two down pauses changes", func(r *result) {
		l.kill("n2")
		l.expectPaused("n1", r)
		l.start("n2")
		_, d := l.waitChange("n1", 60*time.Second)
		r.note("n2 back: changes worked again after %s", d.Round(10*time.Millisecond))
		l.waitHealthy("n1", "n1", "n2")
	})

	l.scenario("never lead lets one node work alone", func(r *result) {
		if l.leaderName("n1") != "n1" {
			if _, err := l.api("n1").do("POST", "/api/v1/cluster/transfer", map[string]string{"to": l.node("n1").id}, nil); err != nil {
				t.Fatal(err)
			}
			l.waitFor("n1 leads", 20*time.Second, func() bool { return l.leaderName("n1") == "n1" })
		}
		if _, err := l.api("n1").do("PUT", "/api/v1/cluster/nodes/"+l.node("n2").id, map[string]any{"never_leader": true}, nil); err != nil {
			t.Fatal(err)
		}
		l.waitFor("n2 stops voting", 30*time.Second, func() bool {
			for _, m := range l.status("n1").Nodes {
				if m.Name == "n2" {
					return !m.Voter
				}
			}
			return false
		})
		l.kill("n2")
		l.mustChange("n1")
		r.note("n2 set to never lead and killed; changes on n1 kept working")
		l.start("n2")
		l.waitHealthy("n1", "n1", "n2")
		l.mustChange("n2")
		r.note("n2 back and caught up; its changes go through n1")
		if _, err := l.api("n1").do("PUT", "/api/v1/cluster/nodes/"+l.node("n2").id, map[string]any{"never_leader": false}, nil); err != nil {
			t.Fatal(err)
		}
		l.waitFor("n2 votes again", 30*time.Second, func() bool {
			for _, m := range l.status("n1").Nodes {
				if m.Name == "n2" {
					return m.Voter
				}
			}
			return false
		})
		l.waitHealthy("n1", "n1", "n2")
	})

	l.scenario("recover after a server is lost for good", func(r *result) {
		recover := func(name string, acceptRisk bool) error {
			_, err := l.session(name).do("POST", "/api/v1/cluster/recover", map[string]any{"password": adminPass, "accept_risk": acceptRisk}, nil)
			return err
		}
		if err := recover("n1", false); err == nil {
			t.Fatal("recovery went ahead while the cluster had a leader")
		}
		l.kill("n2")
		l.waitFor("n1 loses its leader", 30*time.Second, func() bool { return l.leaderName("n1") == "" })
		// n1 can't tell n2 being off from a broken link, so it asks.
		if err := recover("n1", false); err == nil {
			t.Fatal("recovery went ahead without asking whether n2 is really gone")
		}
		if err := recover("n1", true); err != nil {
			t.Fatalf("recover on n1: %v", err)
		}
		l.mustChange("n1")
		r.note("n2 killed; n1 asked for confirmation, then recovered alone and took changes")
		// The lost server comes back: it must not disturb n1, and n1's
		// dashboard must not count it.
		l.start("n2")
		time.Sleep(5 * time.Second)
		name, err := l.change("n1")
		if err != nil {
			t.Fatalf("change on n1 with the old n2 back: %v", err)
		}
		l.waitDNS("n1", name, "10.53.1.1")
		st := l.status("n1")
		if st.Voters != 1 {
			t.Fatalf("n1 counts %d voters after recovery, want 1", st.Voters)
		}
		l.waitFor("n2 sees it was left out", 30*time.Second, func() bool {
			st, err := l.tryStatus("n2")
			return err == nil && st.LeftOut
		})
		if err := recover("n2", true); err == nil {
			t.Fatal("the old n2 recovered on its own while n1 runs the cluster")
		}
		r.note("old n2 came back: it shows it was left out, and refuses to recover on its own")
		// Put n2 back with a new join code.
		code := l.joinCode("n1")
		if _, err := l.session("n2").do("POST", "/api/v1/cluster/join", map[string]string{"join_code": code, "host": "", "password": adminPass}, nil); err != nil {
			t.Fatalf("rejoin n2: %v", err)
		}
		l.node("n2").sess = nil // its accounts were replaced
		l.waitHealthy("n1", "n1", "n2")
		l.mustChange("n2")
		r.note("n2 rejoined with a new code and caught up")
	})

	l.scenario("split, then both sides try to recover", func(r *result) {
		recover := func(name string, acceptRisk bool) error {
			_, err := l.session(name).do("POST", "/api/v1/cluster/recover", map[string]any{"password": adminPass, "accept_risk": acceptRisk}, nil)
			return err
		}
		l.isolate("n2")
		l.waitFor("no leader on either side", 30*time.Second, func() bool { return l.leaderName("n1") == "" && l.leaderName("n2") == "" })
		err1 := recover("n1", false)
		err2 := recover("n2", false)
		r.note("recover on n1: %v; recover on n2: %v", errText(err1), errText(err2))
		if err1 == nil || err2 == nil {
			t.Errorf("a side of a split recovered without a warning that the other may still be running")
		}
		l.heal("n2")
		_, d := l.waitChange("n1", 60*time.Second)
		r.note("link restored without recovering: changes worked again after %s", d.Round(10*time.Millisecond))
		l.waitHealthy("n1", "n1", "n2")
	})
}

func errText(err error) string {
	if err == nil {
		return "went ahead"
	}
	return "refused (" + err.Error() + ")"
}
