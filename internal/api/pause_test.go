package api

import (
	"strings"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

func TestPauseFiltering(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()

	var v pauseView
	admin.want(200, "GET", "/api/v1/pause", nil, &v)
	if v.Paused || !v.CanPause || !v.FilteringEnabled {
		t.Fatalf("fresh state: %+v", v)
	}

	admin.want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 5}, &v)
	if !v.Paused || len(v.Pauses) != 1 || v.Pauses[0].Node != store.AllNodes || v.Pauses[0].Indefinite || v.Pauses[0].Remaining != 300 || v.Pauses[0].By != "admin" {
		t.Fatalf("after 5-minute pause: %+v", v)
	}
	if p := e.api.Store.State().Pauses[store.AllNodes]; p == nil || !p.Until.Equal(e.now.Add(5*time.Minute)) {
		t.Fatalf("stored pause: %+v", p)
	}

	// It ends on its own.
	e.now = e.now.Add(5*time.Minute + time.Second)
	admin.want(200, "GET", "/api/v1/pause", nil, &v)
	if v.Paused {
		t.Fatalf("pause should have ended: %+v", v)
	}

	// Until turned back on.
	admin.want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 0}, &v)
	e.now = e.now.Add(48 * time.Hour)
	admin.want(200, "GET", "/api/v1/pause", nil, &v)
	if !v.Paused || !v.Pauses[0].Indefinite {
		t.Fatalf("indefinite pause: %+v", v)
	}
	admin.want(200, "DELETE", "/api/v1/pause", nil, &v)
	if v.Paused || e.api.Store.State().Pauses != nil {
		t.Fatalf("after resume: %+v", v)
	}

	admin.want(400, "POST", "/api/v1/pause", map[string]any{}, nil)
	admin.want(400, "POST", "/api/v1/pause", map[string]any{"minutes": -1}, nil)
	admin.want(400, "POST", "/api/v1/pause", map[string]any{"minutes": 25 * 60}, nil)

	// Pausing is audited but isn't a settings change.
	st := e.api.Store.State()
	if len(st.ConfigVersions) != 0 {
		t.Fatalf("pause made %d settings versions", len(st.ConfigVersions))
	}
	var audited []string
	for _, a := range st.Audit {
		if a.Op == store.OpFilterPause || a.Op == store.OpFilterResume {
			audited = append(audited, a.Summary)
		}
	}
	want := []string{"paused filtering for 5 minutes", "paused filtering until turned back on", "turned filtering back on"}
	if len(audited) != len(want) {
		t.Fatalf("audit: %q", audited)
	}
	for i := range want {
		if audited[i] != want[i] {
			t.Fatalf("audit: %q", audited)
		}
	}
}

func TestPausePermissions(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	signIn := func(name, role string, perms []string) *client {
		admin.want(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": pw, "role": role, "perms": perms}, nil)
		c := e.client()
		c.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": name, "password": pw}, nil)
		var begin struct{ Secret string }
		c.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
		c.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, nil)
		return c
	}
	viewer := signIn("vic", "viewer", nil)
	var v pauseView
	viewer.want(200, "GET", "/api/v1/pause", nil, &v)
	if v.CanPause {
		t.Fatal("plain viewer offered pause")
	}
	viewer.want(403, "POST", "/api/v1/pause", map[string]any{"minutes": 5}, nil)
	viewer.want(403, "DELETE", "/api/v1/pause", nil, nil)

	// A viewer can be allowed to pause; managing lists implies it.
	signIn("val", "viewer", []string{store.PermPause}).want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 1}, nil)
	signIn("pat", "power", []string{store.PermLists}).want(200, "DELETE", "/api/v1/pause", nil, nil)
	signIn("pam", "power", []string{store.PermRules}).want(403, "POST", "/api/v1/pause", map[string]any{"minutes": 1}, nil)
}

func TestPauseOneNode(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	st := e.api.Store.State().Clone()
	st.Cluster.ID = "c1"
	for _, n := range []*store.Node{{ID: "n1", Name: "container1"}, {ID: "n2", Name: "container2"}, {ID: "w", Name: "witness", Witness: true}} {
		st.Cluster.Nodes[n.ID] = n
	}
	if err := e.api.Store.Replace(st); err != nil {
		t.Fatal(err)
	}

	var v pauseView
	admin.want(200, "GET", "/api/v1/pause", nil, &v)
	if len(v.Nodes) != 2 || v.Nodes[0].Name != "container1" {
		t.Fatalf("nodes offered: %+v", v.Nodes)
	}
	admin.want(400, "POST", "/api/v1/pause", map[string]any{"minutes": 5, "node": "w"}, nil)
	admin.want(400, "POST", "/api/v1/pause", map[string]any{"minutes": 5, "node": "nope"}, nil)
	admin.want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 5, "node": "n2"}, &v)
	if len(v.Pauses) != 1 || v.Pauses[0].Node != "n2" || v.Pauses[0].NodeName != "container2" {
		t.Fatalf("one-node pause: %+v", v.Pauses)
	}
	now := e.now
	if _, ok := e.api.Store.State().PauseFor("n1", now); ok {
		t.Fatal("container1 paused too")
	}
	if p, ok := e.api.Store.State().PauseFor("n2", now); !ok || !p.Until.Equal(now.Add(5*time.Minute)) {
		t.Fatal("container2 not paused")
	}

	// An every-node pause covers both; the longer one wins on container2.
	admin.want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 0}, &v)
	if len(v.Pauses) != 2 || v.Pauses[0].Node != store.AllNodes {
		t.Fatalf("pauses: %+v", v.Pauses)
	}
	if p, ok := e.api.Store.State().PauseFor("n2", now); !ok || !p.Until.IsZero() {
		t.Fatal("container2 should be off until turned back on")
	}

	// Resuming one node leaves the every-node pause.
	admin.want(200, "DELETE", "/api/v1/pause?node=n2", nil, &v)
	if len(v.Pauses) != 1 || v.Pauses[0].Node != store.AllNodes {
		t.Fatalf("after resuming container2: %+v", v.Pauses)
	}
	admin.want(200, "POST", "/api/v1/pause", map[string]any{"minutes": 1, "node": "n1"}, nil)
	admin.want(200, "DELETE", "/api/v1/pause", nil, &v)
	if v.Paused {
		t.Fatalf("resume all left: %+v", v.Pauses)
	}
	var audited []string
	for _, a := range e.api.Store.State().Audit {
		if a.Op == store.OpFilterPause || a.Op == store.OpFilterResume {
			audited = append(audited, a.Summary)
		}
	}
	want := []string{
		"paused filtering on container2 for 5 minutes", "paused filtering on all servers until turned back on",
		"turned filtering back on for container2", "paused filtering on container1 for 1 minute", "turned filtering back on for all servers",
	}
	if strings.Join(audited, "|") != strings.Join(want, "|") {
		t.Fatalf("audit: %q", audited)
	}
}
