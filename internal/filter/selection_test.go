package filter

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/prezmc/dnserv/internal/config"
)

func TestSelectionLookup(t *testing.T) {
	b := NewBuilder()
	custom := b.AddSourceKey("Custom rules", TierCustom, "custom", true)
	ads := b.AddSourceKey("Ads", TierList, "list:https://ads", true)
	adult := b.AddSourceKey("Adult", TierList, "list:https://adult", false) // groups only
	allow := b.AddSourceKey("Allow", TierList, "list:https://allow", true)
	add := func(src uint16, line string) {
		rs, ok, _ := ParseLine(line)
		if !ok {
			t.Fatalf("bad rule %q", line)
		}
		for _, r := range rs {
			b.Add(src, r)
		}
	}
	add(custom, "||mine.example^")
	add(custom, "@@||both.example^")
	add(ads, "||ads.example^")
	add(ads, "||both.example^")
	add(adult, "||both.example^")
	add(adult, "||adult.example^")
	add(adult, "||ad-*.example^")
	add(allow, "@@||ok.adult.example^")
	ix := b.Build()

	household := func(n string) Match { return ix.Lookup(n) }
	sel := func(s *Selection) func(string) Match {
		return func(n string) Match { return ix.LookupMask(n, s.Mask(ix)) }
	}
	kids := sel(&Selection{Lists: map[string]bool{"https://ads": true, "https://adult": true, "https://allow": true}})
	work := sel(&Selection{NoHousehold: true}) // household lists, no custom rules
	adultOnly := sel(&Selection{Lists: map[string]bool{"https://adult": true}, NoHousehold: true})

	cases := []struct {
		look    func(string) Match
		name    string
		blocked bool
		allowed bool
		source  string
	}{
		{household, "x.adult.example", false, false, ""}, // group-only list
		{household, "ad-1.example", false, false, ""},
		{household, "ads.example", true, false, "Ads"},
		{household, "both.example", false, true, "Custom rules"}, // custom allow beats lists
		{household, "mine.example", true, false, "Custom rules"},
		{kids, "x.adult.example", true, false, "Adult"},
		{kids, "ad-1.example", true, false, "Adult"},
		{kids, "ok.adult.example", false, true, "Allow"},
		{kids, "both.example", false, true, "Custom rules"},
		{work, "mine.example", false, false, ""},
		{work, "both.example", true, false, "Ads"}, // without the custom allow the lists block it
		{work, "x.adult.example", false, false, ""},
		{adultOnly, "ads.example", false, false, ""},
		{adultOnly, "both.example", true, false, "Adult"},
	}
	for i, c := range cases {
		m := c.look(c.name)
		if m.Blocked != c.blocked || m.Allowed != c.allowed || m.Source != c.source {
			t.Errorf("case %d %s: got blocked=%v allowed=%v source=%q", i, c.name, m.Blocked, m.Allowed, m.Source)
		}
	}
	if !(&Selection{Lists: map[string]bool{}, NoHousehold: true}).Empty() || (&Selection{NoHousehold: true}).Empty() {
		t.Error("Empty")
	}
}

func TestClientTargets(t *testing.T) {
	cases := []struct {
		in      string
		rest    string
		clients []string
		has     bool
		err     bool
	}{
		{"||a.example^", "||a.example^", nil, false, false},
		{"||a.example^$client=Kids", "||a.example^", []string{"Kids"}, true, false},
		{"@@||a.example^$client='Sam\\'s laptop'|192.168.1.20", "@@||a.example^", []string{"Sam's laptop", "192.168.1.20"}, true, false},
		{"||a.example^$important,client=\"Kids, big\"", "||a.example^$important", []string{"Kids, big"}, true, false},
		{"||a.example^$client=~Kids", "", nil, true, true},
		{"||a.example^$client=", "", nil, true, true},
		{"$client=Kids", "", nil, true, true},
		{"/a\\$b/", "/a\\$b/", nil, false, false},
	}
	for _, c := range cases {
		rest, clients, has, err := ClientTargets(c.in)
		if has != c.has || (err != nil) != c.err || err == nil && (rest != c.rest || !slices.Equal(clients, c.clients)) {
			t.Errorf("%q: got %q %q %v %v", c.in, rest, clients, has, err)
		}
	}
}

func TestEngineGroupLists(t *testing.T) {
	dir := t.TempDir()
	ads, adult := filepath.Join(dir, "ads.txt"), filepath.Join(dir, "adult.txt")
	os.WriteFile(ads, []byte("||ads.example^\n"), 0o600)
	os.WriteFile(adult, []byte("||adult.example^\n"), 0o600)
	cfg := config.Default().Filtering
	cfg.Lists = []config.ListConfig{{Name: "Ads", URL: ads, Enabled: true}, {Name: "Adult", URL: adult}}
	cfg.Rules = []string{"||mine.example^", "||kids-only.example^$client=Kids"}
	e := NewEngine(cfg, dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !e.SetGroupLists([]string{adult}) || e.SetGroupLists([]string{adult}) {
		t.Fatal("SetGroupLists change reporting")
	}
	if err := e.Rebuild(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(e.Status()) != 2 || !e.Status()[1].GroupsOnly || e.Status()[0].GroupsOnly {
		t.Fatalf("status: %+v", e.Status())
	}
	kids := &Selection{Lists: map[string]bool{adult: true}}
	switch {
	case e.Lookup("adult.example").Blocked, !e.Lookup("ads.example").Blocked, !e.Lookup("mine.example").Blocked:
		t.Error("household lookups")
	case !e.LookupFor("adult.example", kids).Blocked, e.LookupFor("ads.example", kids).Blocked, !e.LookupFor("mine.example", kids).Blocked:
		t.Error("kids lookups")
	case e.Lookup("kids-only.example").Blocked:
		t.Error("a $client rule applied to everyone")
	}
}

func BenchmarkLookupMask(b *testing.B) {
	bl := NewBuilder()
	var srcs []uint16
	for i := 0; i < 6; i++ {
		srcs = append(srcs, bl.AddSourceKey("list", TierList, "list:"+itoa(i), i%2 == 0))
	}
	for i := 0; i < 300000; i++ {
		d := "host" + itoa(i) + ".example.com"
		bl.Add(srcs[i%6], Rule{Domain: d, Kind: Suffix})
		bl.Add(srcs[(i+1)%6], Rule{Domain: d, Kind: Suffix}) // most lists overlap
	}
	ix := bl.Build()
	sel := &Selection{Lists: map[string]bool{"1": true, "3": true}}
	names := []string{"a.b.host12345.example.com", "www.notlisted.example.org", "host7.example.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.LookupMask(names[i%3], sel.Mask(ix))
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
