package api

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/store"
)

func TestPerformanceAndTopLists(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "alpha" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	admin, _ := e.setupAdmin()

	tv := netip.MustParseAddr("192.168.1.10")
	at := e.now.Add(-10 * time.Minute)
	for i := range 30 {
		hs.Record(querylog.Entry{Time: at, Client: tv, Name: "slow.example", Type: "A", Result: querylog.Answered, Rcode: "NOERROR", Duration: 80})
		hs.Record(querylog.Entry{Time: at, Client: tv, Name: "fast.example", Type: "AAAA", Result: querylog.Cached, Rcode: "NOERROR", Duration: 0.1})
		list := "HaGeZi Pro"
		if i%3 == 0 {
			list = "Custom rules"
		}
		hs.Record(querylog.Entry{Time: at, Client: tv, Name: "ads.example", Type: "A", Result: querylog.Blocked, Rcode: "NXDOMAIN", Duration: 0.05, List: list, Rule: "||ads.example^"})
	}
	hs.ObserveUpstream("https://cloudflare-dns.com/dns-query", at, 70*time.Millisecond, 0, nil)
	hs.Flush()

	var perf struct {
		View    analytics.PerfView `json:"view"`
		Domains []slowRow          `json:"domains"`
		Devices []slowRow          `json:"devices"`
	}
	admin.want(200, "GET", "/api/v1/analytics/performance?range=1h", nil, &perf)
	s := perf.View.Summary
	if s.Queries != 90 || s.Lookups != 30 || s.LookupAvg != 80 || s.CacheHit != 0.5 || s.Blocked != 30 {
		t.Fatalf("summary = %+v", s)
	}
	if len(perf.View.Upstreams) != 1 || perf.View.Upstreams[0].Node != "alpha" || perf.View.Upstreams[0].Tries != 1 {
		t.Fatalf("upstreams = %+v", perf.View.Upstreams)
	}
	if len(perf.Domains) != 1 || perf.Domains[0].Key != "slow.example" || perf.Domains[0].LookupAvg != 80 {
		t.Fatalf("domains = %+v", perf.Domains)
	}
	if len(perf.Devices) != 1 || perf.Devices[0].Queries != 90 {
		t.Fatalf("devices = %+v", perf.Devices)
	}

	var top struct{ Rows []topRow }
	admin.want(200, "GET", "/api/v1/analytics/top?by=lists&range=24h", nil, &top)
	if len(top.Rows) != 2 || top.Rows[0].Key != "HaGeZi Pro" || top.Rows[0].Total != 20 || top.Rows[1].Total != 10 || top.Rows[0].Now != nil {
		t.Fatalf("lists = %+v", top.Rows)
	}

	// Without querylog.view: response times, but no devices.
	var tok struct{ Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "wall", "perms": []string{store.PermDashboard}}, &tok)
	viewer := e.client()
	viewer.token = tok.Token
	var vp map[string]any
	viewer.want(200, "GET", "/api/v1/analytics/performance?range=24h", nil, &vp)
	if _, ok := vp["devices"]; ok {
		t.Fatal("viewer got devices")
	}
}
