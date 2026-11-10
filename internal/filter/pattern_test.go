package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/prezmc/dnserv/internal/config"
)

func TestPatternRules(t *testing.T) {
	ix := buildIndex(t,
		[]string{`@@/^safe-[a-z]+\.ads\.example$/`},
		map[string]string{
			"list": "||ad-host-*.cloud.example^\n" +
				"|piwik.\n" +
				".tracker.example^\n" +
				"://mine.torrent.example^\n" +
				"/^[a-z]{5}-[a-z]{5}\\.xyz$/\n" +
				"||*.ads.example^\n" +
				"||top^$denyallow=good.top|fine.top\n" +
				"||evil-*^$denyallow=evil-but-ok.example\n" +
				"/^139\\.45\\.197\\.2(4[0-9]|5[0-4]):/\n" + // needs ":", can never match a name
				"||example.org/path^\n",
		})
	tests := []struct {
		name    string
		blocked bool
		allowed bool
	}{
		{"ad-host-7.cloud.example", true, false},
		{"x.ad-host-backup-1.cloud.example", true, false},
		{"ad-host.cloud.example", false, false},
		{"cloud.example", false, false},
		{"piwik.example.com", true, false},
		{"my.piwik.example.com", false, false},
		{"a.tracker.example", true, false},
		{"tracker.example", false, false},
		{"mine.torrent.example", true, false},
		{"x.mine.torrent.example", false, false},
		{"abcde-fghij.xyz", true, false},
		{"abcd-fghij.xyz", false, false},
		{"x.ads.example", true, false},
		{"safe-one.ads.example", false, true},
		{"anything.top", true, false},
		{"top", true, false},
		{"good.top", false, false},
		{"www.fine.top", false, false},
		{"evil-site.example", true, false},
		{"evil-but-ok.example", false, false},
		{"139.45.197.245", false, false},
		{"example.org", false, false},
	}
	for _, tt := range tests {
		m := ix.Lookup(tt.name)
		if m.Blocked != tt.blocked || m.Allowed != tt.allowed {
			t.Errorf("Lookup(%q) = %+v (rule %q), want blocked=%v allowed=%v", tt.name, m, m.Rule.Text(), tt.blocked, tt.allowed)
		}
	}
	if m := ix.Lookup("ad-host-7.cloud.example"); m.Rule.Text() != "||ad-host-*.cloud.example^" || m.Source != "list" {
		t.Errorf("rule shown = %q from %q", m.Rule.Text(), m.Source)
	}
}

func TestBadfilter(t *testing.T) {
	ix := buildIndex(t, nil, map[string]string{
		"a": "||off.example^\n||on.example^\n||ad-*.off.example^\n0.0.0.0 host.example\n",
		"b": "||off.example^$badfilter\n||ad-*.off.example^$badfilter\nhost.example$badfilter\n",
	})
	for name, want := range map[string]bool{"off.example": false, "ad-1.off.example": false, "on.example": true, "host.example": false} {
		if got := ix.Lookup(name).Blocked; got != want {
			t.Errorf("%s blocked = %v, want %v", name, got, want)
		}
	}
	if ix.Len() != 1 {
		t.Errorf("Len = %d, want 1", ix.Len())
	}
}

func TestPatternTiers(t *testing.T) {
	// A custom wildcard block beats a list allow; a list wildcard block
	// loses to a list allow.
	ix := buildIndex(t, []string{"||promo-*.shop.example^"}, map[string]string{
		"allowList": "||promo-1.shop.example^\n||cdn.example^\n",
		"list":      "||*.cdn.example^\n",
	})
	if !ix.Lookup("promo-1.shop.example").Blocked {
		t.Error("custom pattern should beat a list allow")
	}
	if m := ix.Lookup("img.cdn.example"); m.Blocked || !m.Allowed {
		t.Errorf("list allow should beat a list pattern: %+v", m)
	}
}

func TestAlsoOnPatterns(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	os.WriteFile(a, []byte("||ad-*.cloud.example^\n/^x[0-9]+\\.cloud\\.example$/\n||cloud.example^$badfilter\n"), 0o600)
	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "A", URL: a, Enabled: true}}
	e := NewEngine(cfg, dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := e.AlsoOn(context.Background(), "ad-1.cloud.example"); len(got) != 1 || got[0].Rule != "||ad-*.cloud.example^" {
		t.Errorf("ad-1 = %+v", got)
	}
	if got := e.AlsoOn(context.Background(), "x12.cloud.example"); len(got) != 1 {
		t.Errorf("x12 = %+v", got)
	}
}

// BenchmarkLookupPatterns is BenchmarkLookup with 1,000 pattern rules,
// about what the AdGuard DNS filter and Dandelion Sprout's list hold.
func BenchmarkLookupPatterns(b *testing.B) {
	bl := NewBuilder()
	src := bl.AddSource("big", TierList)
	for i := 0; i < 1_000_000; i++ {
		bl.Add(src, Rule{Domain: fmt.Sprintf("host%d.tracker%d.example", i, i%5000), Kind: Suffix})
	}
	for i := 0; i < 1000; i++ {
		var line string
		switch i % 4 {
		case 0:
			line = fmt.Sprintf("||ad%d-*.cdn%d.example^", i, i)
		case 1:
			line = fmt.Sprintf("|stats%d.", i)
		case 2:
			line = fmt.Sprintf(`/^t%d[a-z]{3}\.example$/`, i)
		default:
			line = fmt.Sprintf("||*.metric%d.net^", i)
		}
		rules, ok, _ := ParseLine(line)
		if !ok {
			b.Fatalf("%q did not parse", line)
		}
		bl.Add(src, rules[0])
	}
	ix := bl.Build()
	names := []string{"www.google.com", "a.b.c.host42.tracker42.example", "cdn.example.net", "host999999.tracker4999.example",
		"ad12-x.cdn12.example", "stats5.example.com", "i.instagram.com", "gateway.icloud.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.Lookup(names[i%len(names)])
	}
}
