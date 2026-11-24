package api

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/threat"
)

func TestAnalyze(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "alpha" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	dir := t.TempDir()
	for n, c := range map[string]string{
		"urlhaus.txt": "127.0.0.1 malware.example\n127.0.0.1 evil-cdn.example\n", "threatfox.txt": "", "phishingarmy.txt": "", "hagezi-tif.txt": "",
		"feodo.txt": "", "drop4.txt": "", "drop6.txt": "",
		"trackers.json":  `{"categories":{"4":"advertising"},"trackers":{"dc":{"name":"DoubleClick","categoryId":4,"companyId":"google"}},"trackerDomains":{"doubleclick.net":"dc"}}`,
		"companies.json": `{"companies":{"google":{"name":"Google"}}}`,
	} {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600)
	}
	in := threat.New(dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	in.SetEnabled(true)
	in.Refresh(context.Background(), false)
	e.api.Intel = in
	admin, _ := e.setupAdmin()

	phone := netip.MustParseAddr("192.168.1.30")
	rec := func(at time.Time, name string, res string, rrs ...dns.RR) {
		hs.Record(querylog.Entry{Time: at, Client: phone, Name: name, Type: "A", Result: res, Answer: rrs})
	}
	// Three times the game opened, it looked itself up, then the risky
	// name and an ad network; a mail check runs all the time regardless.
	var at time.Time
	for i, ago := range []time.Duration{50 * time.Minute, 30 * time.Minute, 10 * time.Minute} {
		at = e.now.Add(-ago)
		rec(at.Add(-4*time.Second), "sortgame.example", querylog.Answered)
		rec(at.Add(-3*time.Second), "api.sortgame.example", querylog.Answered)
		rec(at, "malware.example", querylog.Answered)
		rec(at.Add(time.Second), "ads.doubleclick.net", querylog.Blocked)
		if i == 2 {
			rec(at.Add(-20*time.Second), "news.example.org", querylog.Cached)
		}
	}
	for s := -300; s <= 300; s += 30 {
		for _, ago := range []time.Duration{50 * time.Minute, 30 * time.Minute, 10 * time.Minute} {
			rec(e.now.Add(-ago).Add(time.Duration(s)*time.Second+500*time.Millisecond), "mail.example.net", querylog.Cached)
		}
	}
	// A shop whose answer was a CNAME to another risky name.
	cn, _ := dns.NewRR("img.shop.example. 60 IN CNAME evil-cdn.example.")
	rec(e.now.Add(-5*time.Minute-time.Second), "img.shop.example", querylog.Answered, cn)
	rec(e.now.Add(-5*time.Minute), "evil-cdn.example", querylog.Answered)
	rec(e.now.Add(-5*time.Minute-2*time.Second), "games.example.org", querylog.Answered)
	hs.Flush()

	var got struct {
		Device     string
		Lookups    int
		Moments    int
		T          int64
		Guesses    []sourceGuess
		Companions []companion
		Timeline   []timelineRow
	}
	admin.want(200, "GET", "/api/v1/analytics/analyze?client=192.168.1.30&name=malware.example", nil, &got)
	if got.Lookups != 3 || got.Moments != 3 || got.T/1e6 != at.Unix() {
		t.Fatalf("lookups = %d, moments = %d, t = %d", got.Lookups, got.Moments, got.T)
	}
	if len(got.Guesses) == 0 || got.Guesses[0].Label != "sortgame.example" || got.Guesses[0].Confidence != "likely" || got.Guesses[0].Seen != 3 {
		t.Fatalf("guesses = %+v", got.Guesses)
	}
	for _, g := range got.Guesses {
		if g.Label == "example.net" && g.Confidence == "likely" {
			t.Fatalf("background mail check ranked likely: %+v", got.Guesses)
		}
	}
	if len(got.Companions) != 1 || got.Companions[0].Label != "Google" || got.Companions[0].Category != threat.CatAds {
		t.Fatalf("companions = %+v", got.Companions)
	}
	var target, before bool
	for _, r := range got.Timeline {
		if r.Target {
			target = r.Risk != nil && r.Risk.Level == "high"
		}
		if r.Name == "sortgame.example" && r.DT == -4 {
			before = true
		}
	}
	if !target || !before {
		t.Fatalf("timeline = %+v", got.Timeline)
	}

	// Asking about one moment: the CNAME points straight at the shop.
	at2 := e.now.Add(-5 * time.Minute).UnixMicro()
	admin.want(200, "GET", "/api/v1/analytics/analyze?client=192.168.1.30&name=evil-cdn.example&t="+strconv.FormatInt(at2, 10), nil, &got)
	if len(got.Guesses) == 0 || got.Guesses[0].Label != "shop.example" || got.Guesses[0].Reasons[0] != "its answer pointed to evil-cdn.example" {
		t.Fatalf("cname guesses = %+v", got.Guesses)
	}

	// Never looked up: nothing to go on, but not an error.
	admin.want(200, "GET", "/api/v1/analytics/analyze?client=192.168.1.30&name=quiet.example", nil, &got)
	if len(got.Guesses) != 0 || got.Lookups != 0 {
		t.Fatalf("quiet = %+v", got)
	}
	admin.want(400, "GET", "/api/v1/analytics/analyze?name=x.example", nil, nil)
}
