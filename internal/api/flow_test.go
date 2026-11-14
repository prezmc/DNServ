package api

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/threat"
)

func TestTrafficMap(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "node-a" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	dir := t.TempDir()
	for n, c := range map[string]string{
		"trackers.json":  `{"categories":{"4":"advertising","9":"audio_video_player"},"trackers":{"dc":{"name":"DoubleClick","categoryId":4,"companyId":"google"},"nf":{"name":"Netflix","categoryId":9,"companyId":"netflix"}},"trackerDomains":{"doubleclick.net":"dc","nflxvideo.net":"nf"}}`,
		"companies.json": `{"companies":{"google":{"name":"Google"},"netflix":{"name":"Netflix"}}}`,
	} {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600)
	}
	in := threat.New(dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	in.Refresh(context.Background(), false)
	e.api.Intel = in
	admin, _ := e.setupAdmin()

	tv, phone := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.20")
	at := e.now.Add(-10 * time.Minute)
	rec := func(c netip.Addr, name, result, up string, n int) {
		for i := range n {
			hs.Record(querylog.Entry{Time: at.Add(time.Duration(i) * time.Second), Client: c, Name: name, Type: "A", Result: result, Upstream: up})
		}
	}
	rec(tv, "occ-0.nflxvideo.net", querylog.Answered, "https://dns.quad9.net/dns-query", 6)
	rec(tv, "occ-1.nflxvideo.net", querylog.Cached, "", 4)
	rec(phone, "www.example.co.uk", querylog.Answered, "tls://9.9.9.9:853", 3)
	rec(phone, "ad.doubleclick.net", querylog.Blocked, "", 2)
	hs.Flush()
	admin.want(201, "POST", "/api/v1/devices", map[string]any{"name": "Living room TV", "addrs": []string{"192.168.1.10"}}, nil)

	for _, group := range []string{"company", "type"} {
		var out struct {
			Nodes []*flowNode
			Links []flowLink
			Total int64
		}
		admin.want(200, "GET", "/api/v1/analytics/flow?range=24h&group="+group, nil, &out)
		if out.Total != 15 {
			t.Fatalf("%s: total = %d", group, out.Total)
		}
		byLabel := map[string]*flowNode{}
		for _, n := range out.Nodes {
			byLabel[n.Label] = n
		}
		for label, n := range map[string]int64{
			"Living room TV": 10, "node-a": 15, "Cache": 4, "dns.quad9.net (HTTPS)": 6, "9.9.9.9 (TLS)": 3, "Blocked": 2,
		} {
			if byLabel[label] == nil || byLabel[label].N != n {
				t.Errorf("%s: %q = %+v, want %d", group, label, byLabel[label], n)
			}
		}
		if group == "company" {
			if byLabel["Netflix"] == nil || byLabel["Netflix"].N != 10 || byLabel["example.co.uk"] == nil || byLabel["Advertising"] == nil {
				t.Errorf("services: %+v", out.Nodes)
			}
		} else if byLabel["Streaming"] == nil || byLabel["Streaming"].N != 10 || byLabel["Streaming"].Group != "Streaming" ||
			byLabel["Other"] == nil || byLabel["Ads and tracking"] == nil || byLabel["Ads and tracking"].Kind != "blocked" {
			t.Errorf("categories: %+v", out.Nodes)
		}
	}

	// Opening a category breaks it into its apps and sites.
	var out struct {
		Nodes []*flowNode
		Open  string
	}
	admin.want(200, "GET", "/api/v1/analytics/flow?range=24h&group=category&open=Streaming", nil, &out)
	byLabel := map[string]*flowNode{}
	for _, n := range out.Nodes {
		byLabel[n.Label] = n
	}
	if out.Open != "Streaming" || byLabel["Netflix"] == nil || byLabel["Netflix"].Parent != "Streaming" || byLabel["Netflix"].N != 10 ||
		byLabel["Streaming"] != nil || byLabel["Other"] == nil || len(byLabel["Netflix"].Domains) != 2 {
		t.Errorf("opened: %+v", out.Nodes)
	}
}

func TestCategoryOf(t *testing.T) {
	for name, want := range map[string]string{
		"www.facebook.com": threat.CatSocial, "occ-0-1.nflxvideo.net": threat.CatStreaming, "gateway.icloud.com": threat.CatOS,
		"a1.anker-in.com": threat.CatSmartHome, "e123.akamaiedge.net": threat.CatCDN, "17.in-addr.arpa": threat.CatNetwork,
		"resolver.arpa": threat.CatNetwork, "www.bbc.co.uk": threat.CatNews, "store.steampowered.com": threat.CatGaming,
		"example.org": threat.CatOther,
	} {
		if got := threat.CategoryOf(name, nil).Name; got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// The companies database fills in what DNServ's table doesn't know.
	if got := threat.CategoryOf("x.tracker.example", &threat.Type{Category: "Advertising", Company: "Ads Inc."}); got.Name != threat.CatAds || got.Service != "Ads" {
		t.Errorf("tracker = %+v", got)
	}
}

func TestShortCompany(t *testing.T) {
	for in, want := range map[string]string{"Apple Inc.": "Apple", "Microsoft Corporation": "Microsoft", "Meta Platforms, Inc.": "Meta Platforms", "Google": "Google", "Inc": "Inc"} {
		if got := shortCompany(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
