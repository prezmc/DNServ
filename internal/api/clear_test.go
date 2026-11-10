package api

import (
	"context"
	"testing"

	"github.com/prezmc/dnserv/internal/store"
)

func TestClearHistory(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var asked []string
	e.api.ClearHistory = func(_ context.Context, what string) []HistoryCleared {
		asked = append(asked, what)
		return []HistoryCleared{{Server: "node-a"}, {Server: "node-b", Error: "unreachable"}}
	}
	var out struct{ Servers []HistoryCleared }
	admin.want(200, "POST", "/api/v1/analytics/clear", map[string]any{"what": "performance"}, &out)
	if len(asked) != 1 || asked[0] != "performance" || len(out.Servers) != 2 || out.Servers[1].Error == "" {
		t.Fatalf("asked %v, got %+v", asked, out)
	}
	admin.want(400, "POST", "/api/v1/analytics/clear", map[string]any{"what": "everything"}, nil)

	var summary string
	for _, a := range e.api.Store.State().Audit {
		if a.Op == store.OpHistoryClear {
			summary = a.Summary
		}
	}
	if summary != "cleared performance stats on node-a" {
		t.Fatalf("audit summary %q", summary)
	}
}
