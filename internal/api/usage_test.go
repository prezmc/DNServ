package api

import (
	"testing"

	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/usage"
)

func TestUsageChoice(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()

	var v usageView
	admin.want(200, "GET", "/api/v1/usage", nil, &v)
	if v.Choice != "" || e.api.Store.State().Usage.Sending(usage.Schema) {
		t.Fatalf("must start undecided and off: %+v", v)
	}
	admin.want(400, "PUT", "/api/v1/usage", map[string]any{}, nil)
	admin.want(200, "PUT", "/api/v1/usage", map[string]any{"send": true}, &v)
	if v.Choice != "yes" || !e.api.Store.State().Usage.Sending(usage.Schema) {
		t.Fatalf("after yes: %+v", v)
	}
	admin.want(200, "PUT", "/api/v1/usage", map[string]any{"send": false}, &v)
	if v.Choice != "no" || e.api.Store.State().Usage.Sending(usage.Schema) {
		t.Fatalf("after no: %+v", v)
	}
	// Not a settings change, but audited.
	st := e.api.Store.State()
	if len(st.ConfigVersions) != 0 {
		t.Fatal("usage choice made a settings version")
	}
	n := 0
	for _, a := range st.Audit {
		if a.Op == store.OpUsageChoice {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audited %d choices", n)
	}
}

func TestUsageStatsHoldNoNames(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin()
	s, err := e.api.UsageStats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := usage.Build(s, "dev", "", "2026-W46", "x")
	if r.Servers != 1 || r.UpstreamMode == "" {
		t.Fatalf("report: %+v", r)
	}
}

func TestUsageAskAgainOnNewSchema(t *testing.T) {
	u := store.UsagePrefs{Choice: "yes", Schema: usage.Schema - 1}
	if u.Sending(usage.Schema) {
		t.Fatal("an older yes must not cover a bigger report")
	}
}
