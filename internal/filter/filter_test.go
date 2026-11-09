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
