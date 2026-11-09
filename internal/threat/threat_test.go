package threat

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const trackers = `{"categories":{"4":"advertising","6":"site_analytics"},
 "trackers":{"doubleclick":{"name":"DoubleClick","categoryId":4,"url":"https://doubleclick.net","companyId":"google"},
             "ga":{"name":"Google Analytics","categoryId":6,"url":"","companyId":"google"}},
 "trackerDomains":{"doubleclick.net":"doubleclick","google-analytics.com":"ga","xkqzjvwpqrtxmbn.com":"ga"}}`
const companies = `{"companies":{"google":{"name":"Google","websiteUrl":"https://google.com"}}}`

// seeded writes cached copies so nothing is downloaded.
func seeded(t *testing.T) *Intel {
	dir := t.TempDir()
	files := map[string]string{
		"urlhaus.txt":      "# hosts\n127.0.0.1 malware.example\n",
		"threatfox.txt":    "127.0.0.1 c2.example\n127.0.0.1 malware.example\n",
		"phishingarmy.txt": "paypa1-login.example\n",
		"hagezi-tif.txt":   "# tif\nscam-shop.example\n",
		"trackers.json":    trackers,
		"companies.json":   companies,
	}
	for n, c := range files {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600)
	}
	in := New(dir, nil, quiet())
	in.SetEnabled(true)
	in.Refresh(context.Background(), false)
	return in
}

func TestScore(t *testing.T) {
	in := seeded(t)
	for _, tc := range []struct {
		name  string
		level string
		min   int
	}{
		{"malware.example", "high", 95}, // two malware feeds
		{"c2.example", "high", 90},
		{"paypa1-login.example", "high", 80},
		{"shop.scam-shop.example", "high", 70}, // wildcard feed covers subdomains
		{"www.example.com", "", 0},
		{"xn--pypal-4ve.com", "low", 15},
		{"qzxvkrtplmnbwqj.top", "medium", 40}, // random-looking on a risky TLD
		{"xkqzjvwpqrtxmbn.com", "", 0},        // random-looking but a known company's
	} {
		r := in.Score(tc.name)
		if r.Level != tc.level || r.Score < tc.min {
			t.Errorf("%s: %+v, want level %q score >= %d", tc.name, r, tc.level, tc.min)
		}
	}
	if r := in.Score("malware.example"); !strings.Contains(r.Reasons[0], "URLhaus") || !strings.Contains(r.Reasons[0], "ThreatFox") {
		t.Errorf("reasons = %v", r.Reasons)
	}
	in.SetTrusted([]string{"Example"})
	if r := in.Score("malware.example"); r.Score != 0 {
		t.Errorf("trusted still scored: %+v", r)
	}
}

func TestTypes(t *testing.T) {
	in := seeded(t)
	ty := in.TypeOf("stats.g.doubleclick.net")
	if ty == nil || ty.Category != "Advertising" || ty.Company != "Google" {
		t.Fatalf("type = %+v", ty)
	}
	if ty := in.TypeOf("www.google-analytics.com"); ty == nil || ty.Category != "Site analytics" {
		t.Fatalf("type = %+v", ty)
	}
	if in.TypeOf("example.org") != nil {
		t.Fatal("unknown domain typed")
	}
}

func TestDisableDropsFeeds(t *testing.T) {
	in := seeded(t)
	in.SetEnabled(false)
	in.Refresh(context.Background(), false)
	if r := in.Score("malware.example"); r.Score != 0 {
		t.Fatalf("still scored after turning off: %+v", r)
	}
	if in.TypeOf("doubleclick.net") == nil {
		t.Fatal("types should stay on")
	}
	if _, err := os.Stat(filepath.Join(in.dir, "urlhaus.txt")); err == nil {
		t.Fatal("feed file kept")
	}
}

func TestDownloadAndKeepLastCopy(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, "0.0.0.0 bad.example\n")
	}))
	defer srv.Close()
	old := Feeds
	defer func() { Feeds = old }()
	Feeds = []Feed{{ID: "test", Name: "Test feed", URL: srv.URL, Kind: KindMalware}}
	in := New(t.TempDir(), srv.Client(), quiet())
	in.SetEnabled(true)
	in.Refresh(context.Background(), false)
	if in.Score("bad.example").Level != "high" || in.Status()[0].Entries != 1 {
		t.Fatalf("status = %+v", in.Status())
	}
	fail = true
	os.Chtimes(filepath.Join(in.dir, "test.txt"), timeAgo(), timeAgo())
	in.Refresh(context.Background(), true)
	if in.Score("bad.example").Level != "high" || in.Status()[0].Error == "" {
		t.Fatalf("after failed refresh: %+v", in.Status())
	}
}

func timeAgo() time.Time { return time.Now().Add(-24 * time.Hour) }

func TestHeuristicsLeaveCommonNamesAlone(t *testing.T) {
	for _, n := range []string{"connectivitycheck.gstatic.com", "pagead2.googlesyndication.com", "e6858.dsce9.akamaiedge.net",
		"d3c3cq33003psk.cloudfront.net", "outlook.office365.com", "1e100.net", "s3.eu-west-1.amazonaws.com", "scontent-lhr8-1.cdninstagram.com",
		"firebaselogging-pa.googleapis.com", "settings-win.data.microsoft.com", "api.smartthings.com", "lb._dns-sd._udp.home.arpa"} {
		if s, why := heuristics(n); s != 0 {
			t.Errorf("%s scored %d: %v", n, s, why)
		}
	}
}
