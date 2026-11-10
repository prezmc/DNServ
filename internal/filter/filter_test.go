package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prezmc/dnserve/internal/config"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		line string
		want []Rule
	}{
		{"||ads.example.com^", []Rule{{"ads.example.com", Suffix, false}}},
		{"@@||good.example.com^", []Rule{{"good.example.com", Suffix, true}}},
		{"||x.example^$important", []Rule{{"x.example", Suffix, false}}},
		{"*.track.example", []Rule{{"track.example", SubOnly, false}}},
		{"Plain.Example.", []Rule{{"plain.example", Exact, false}}},
		{"0.0.0.0 a.example b.example # comment", []Rule{{"a.example", Exact, false}, {"b.example", Exact, false}}},
		{"127.0.0.1 localhost", nil},
		{"! comment", nil},
		{"# comment", nil},
		{"", nil},
		{"/ads[0-9]+/", nil},
		{"example.com##.banner", nil},
		{"||x.example^$client=1.2.3.4", nil},
		{"bad domain with spaces", nil},
	}
	for _, tt := range tests {
		got, _, _ := ParseLine(tt.line)
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("ParseLine(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func buildIndex(t *testing.T, custom []string, lists map[string]string) *Index {
	t.Helper()
	b := NewBuilder()
	c := b.AddSource("custom", TierCustom)
	for _, l := range custom {
		rules, ok, _ := ParseLine(l)
		if !ok {
			t.Fatalf("bad custom rule %q", l)
		}
		for _, r := range rules {
			b.Add(c, r)
		}
	}
	for name, body := range lists {
		src := b.AddSource(name, TierList)
		allow := strings.HasPrefix(name, "allow")
		if _, err := ParseList(strings.NewReader(body), func(r Rule) {
			r.Allow = r.Allow || allow
			b.Add(src, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return b.Build()
}

func TestIndexLookup(t *testing.T) {
	ix := buildIndex(t,
		[]string{"@@||cdn.ads.example^", "||mine.example^"},
		map[string]string{
			"listA":  "||ads.example^\n0.0.0.0 exact.example\n*.wild.example\n||mine.example^\n",
			"allowB": "allowed.ads.example\n",
		})

	tests := []struct {
		name            string
		blocked, allow  bool
		source, ruleTxt string
	}{
		{"ads.example", true, false, "listA", "||ads.example^"},
		{"x.y.ads.example", true, false, "listA", "||ads.example^"},
		{"cdn.ads.example", false, true, "custom", "@@||cdn.ads.example^"},
		{"img.cdn.ads.example", false, true, "custom", "@@||cdn.ads.example^"},
		{"allowed.ads.example", false, true, "allowB", "@@allowed.ads.example"},
		{"exact.example", true, false, "listA", "exact.example"},
		{"sub.exact.example", false, false, "", ""},
		{"wild.example", false, false, "", ""},
		{"a.wild.example", true, false, "listA", "*.wild.example"},
		{"mine.example", true, false, "custom", "||mine.example^"},
		{"notads.example", false, false, "", ""},
		{"example", false, false, "", ""},
	}
	for _, tt := range tests {
		m := ix.Lookup(tt.name)
		if m.Blocked != tt.blocked || m.Allowed != tt.allow || m.Source != tt.source || (tt.ruleTxt != "" && m.Rule.Text() != tt.ruleTxt) {
			t.Errorf("Lookup(%q) = %+v (rule %q), want blocked=%v allowed=%v source=%q rule=%q",
				tt.name, m, m.Rule.Text(), tt.blocked, tt.allow, tt.source, tt.ruleTxt)
		}
	}
	if ix.Len() != 6 {
		t.Errorf("Len = %d, want 6", ix.Len())
	}
}

func TestCustomBlockBeatsListAllow(t *testing.T) {
	ix := buildIndex(t, []string{"||bad.example^"}, map[string]string{"allowList": "||bad.example^\n"})
	if m := ix.Lookup("bad.example"); !m.Blocked {
		t.Fatalf("custom block should beat a list allow, got %+v", m)
	}
}

func TestEngineDownloadsAndFallsBackToCache(t *testing.T) {
	body := "||ads.example^\n"
	fail := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		io.WriteString(w, body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	local := filepath.Join(dir, "local.txt")
	os.WriteFile(local, []byte("0.0.0.0 local.example\n"), 0o600)

	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "remote", URL: ts.URL, Enabled: true}, {Name: "local", URL: local, Enabled: true}, {Name: "off", URL: ts.URL + "/x", Enabled: false}}
	cfg.Rules = []string{"@@||ok.ads.example^"}
	e := NewEngine(cfg, dir, ts.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := e.Rebuild(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !e.Lookup("x.ads.example").Blocked || !e.Lookup("local.example").Blocked || e.Lookup("ok.ads.example").Blocked {
		t.Fatal("unexpected lookups after first build")
	}
	if n := len(e.Status()); n != 2 {
		t.Fatalf("status has %d lists, want 2 (disabled list skipped)", n)
	}

	// Upstream goes down: a forced refresh must keep the cached copy.
	fail = true
	if err := e.Rebuild(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !e.Lookup("ads.example").Blocked {
		t.Fatal("cached list was not used after download failure")
	}
	for _, st := range e.Status() {
		if st.Name == "remote" && (!st.FromCache || st.Error != "") {
			t.Fatalf("remote status = %+v, want from cache without error", st)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	bl := NewBuilder()
	src := bl.AddSource("big", TierList)
	for i := 0; i < 1_000_000; i++ {
		bl.Add(src, Rule{Domain: fmt.Sprintf("host%d.tracker%d.example", i, i%5000), Kind: Suffix})
	}
	ix := bl.Build()
	names := []string{"www.google.com", "a.b.c.host42.tracker42.example", "cdn.example.net", "host999999.tracker4999.example"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.Lookup(names[i%len(names)])
	}
}

func TestBlockBypass(t *testing.T) {
	cfg := config.Default().Filtering
	cfg.BlockBypass = true
	cfg.Rules = []string{"@@||dns.quad9.net^"}
	e := NewEngine(cfg, t.TempDir(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.Rebuild(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if m := e.Lookup("dns.google"); !m.Blocked || m.Source != "Bypass protection" {
		t.Fatalf("dns.google = %+v", m)
	}
	if !e.Lookup("mask.icloud.com").Blocked {
		t.Fatal("iCloud Private Relay should be blocked")
	}
	if e.Lookup("dns.quad9.net").Blocked {
		t.Fatal("a custom allow must override bypass protection")
	}
}

func TestAlsoOn(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt"), filepath.Join(dir, "allow.txt")
	os.WriteFile(a, []byte("! list A\n||doubleclick.net^\nads.example\n"), 0o600)
	os.WriteFile(b, []byte("0.0.0.0 stats.g.doubleclick.net\n0.0.0.0 Other.DoubleClick.net\n"), 0o600)
	os.WriteFile(c, []byte("@@||g.doubleclick.net^\n"), 0o600)
	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "List A", URL: a, Enabled: true}, {Name: "List B", URL: b, Enabled: true}, {Name: "Off", URL: a}}
	cfg.Allowlists = []config.ListConfig{{Name: "Allow", URL: c, Enabled: true}}
	cfg.Rules = []string{"||stats.g.doubleclick.net^"}
	e := NewEngine(cfg, dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := e.AlsoOn(context.Background(), "stats.g.doubleclick.net")
	want := []ListHit{
		{List: "Custom rules", Rule: "||stats.g.doubleclick.net^"},
		{List: "Allow", Rule: "@@||g.doubleclick.net^", Allowlist: true},
		{List: "List A", Rule: "||doubleclick.net^"},
		{List: "List B", Rule: "stats.g.doubleclick.net"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("also on = %+v", got)
	}
	if got := e.AlsoOn(context.Background(), "other.doubleclick.net"); len(got) != 2 || got[1].List != "List B" {
		t.Fatalf("uppercase line = %+v", got)
	}
}

// BenchmarkAlsoOn reads a 1,000,000-line list.
func BenchmarkAlsoOn(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "big.txt")
	var sb strings.Builder
	for i := range 1_000_000 {
		fmt.Fprintf(&sb, "||host%d.example%d.com^\n", i, i%5000)
	}
	os.WriteFile(path, []byte(sb.String()), 0o600)
	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "Big", URL: path, Enabled: true}}
	e := NewEngine(cfg, dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.ResetTimer()
	for range b.N {
		e.AlsoOn(context.Background(), "host42.example42.com")
	}
}

func TestDownloadURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/blocklistproject/Lists/raw/master/adguard/porn-ags.txt": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/porn-ags.txt",
		"https://github.com/o/r/blob/main/a/b.txt":                                  "https://raw.githubusercontent.com/o/r/main/a/b.txt",
		"https://github.com/o/r/raw/refs/heads/main/list.txt":                       "https://raw.githubusercontent.com/o/r/refs/heads/main/list.txt",
		"https://github.com/o/r/releases/download/v1/list.txt":                      "https://github.com/o/r/releases/download/v1/list.txt",
		"https://raw.githubusercontent.com/o/r/main/list.txt":                       "https://raw.githubusercontent.com/o/r/main/list.txt",
		"https://example.com/o/r/raw/main/list.txt":                                 "https://example.com/o/r/raw/main/list.txt",
		"https://github.com/o/r/raw/main":                                           "https://github.com/o/r/raw/main",
	} {
		if got := DownloadURL(in); got != want {
			t.Errorf("DownloadURL(%q) = %q, want %q", in, got, want)
		}
	}
}
