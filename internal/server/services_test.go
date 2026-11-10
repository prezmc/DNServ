package server

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/policy"
	"github.com/prezmc/dnserv/internal/store"
)

func TestGroupServices(t *testing.T) {
	s, addr := newTestServer(t, nil, &fakeResolver{})
	st := &store.State{
		Groups: map[string]*store.Group{"kids": {ID: "kids", Name: "Kids", Services: []string{"tiktok"},
			Schedules: []store.Schedule{{Name: "Always", Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: "00:00", End: "23:59", Services: []string{"roblox"}}}}},
		Devices: map[string]*store.Device{"me": {ID: "me", Name: "Me", Addrs: []string{"127.0.0.1"}, Group: "kids"}},
	}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.tiktok.com", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("group service not blocked: %v", r)
	}
	if r := query(t, addr, "setup.rbxcdn.com", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("schedule service not blocked: %v", r)
	}
	st.Groups["kids"].Rules = []string{"@@||tiktok.com^"}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.tiktok.com", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("the group's own allow rule should win over its service: %v", r)
	}
}

// recordingResolver answers A queries and remembers the last name asked.
type recordingResolver struct {
	fakeResolver
	last chan string
}

func (r *recordingResolver) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	select {
	case r.last <- q.Question[0].Name:
	default:
	}
	return r.fakeResolver.Exchange(ctx, q)
}

func TestSafeSearch(t *testing.T) {
	up := &recordingResolver{last: make(chan string, 16)}
	s, addr := newTestServer(t, nil, up)
	if r := query(t, addr, "www.google.co.uk", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatalf("safe search off: want the plain answer, got %v", r)
	}
	if got := <-up.last; got != "www.google.co.uk." {
		t.Fatalf("upstream asked for %s", got)
	}

	fc := config.Default().Filtering
	fc.SafeSearch = true
	if err := s.Apply(nil, []string{"127.0.0.0/8"}, fc, true); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"www.google.co.uk": "forcesafesearch.google.com.",
		"google.de":        "forcesafesearch.google.com.",
		"www.bing.com":     "strict.bing.com.",
		"duckduckgo.com":   "safe.duckduckgo.com.",
		"www.youtube.com":  "restrictmoderate.youtube.com.",
	} {
		r := query(t, addr, name, dns.TypeA, "udp")
		c, ok := r.Answer[0].(*dns.CNAME)
		if !ok || c.Target != want || len(r.Answer) != 2 || r.Question[0].Name != dns.Fqdn(name) {
			t.Fatalf("%s: want CNAME to %s then an address, got %v", name, want, r)
		}
		select { // the first name for each target reaches upstream; later ones are cached
		case got := <-up.last:
			if got != want {
				t.Fatalf("%s: upstream asked for %s, want %s", name, got, want)
			}
		default:
		}
	}
	if r := query(t, addr, "mail.google.com", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatalf("other Google names are left alone: %v", r)
	}

	st := &store.State{
		Groups:  map[string]*store.Group{"adults": {ID: "adults", Name: "Adults", SafeSearch: "off"}},
		Devices: map[string]*store.Device{"me": {ID: "me", Name: "Me", Addrs: []string{"127.0.0.1"}, Group: "adults"}},
	}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.bing.com", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatalf("a group with safe search off gets the plain answer: %v", r)
	}
}

func TestSafeSearchTarget(t *testing.T) {
	for name, want := range map[string]string{
		"google.com": "forcesafesearch.google.com", "www.google.com.au": "forcesafesearch.google.com",
		"google.example.com": "", "maps.google.com": "", "www.google.c0m": "", "googleusercontent.com": "",
	} {
		if got := safeSearchTarget(name); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestServiceCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, sv := range filter.Services {
		if seen[sv.ID] || sv.Name == "" || sv.Category == "" || len(sv.Domains) == 0 {
			t.Errorf("bad catalog entry %+v", sv)
		}
		seen[sv.ID] = true
		for _, d := range sv.Domains {
			if rules, ok, _ := filter.ParseLine("||" + d + "^"); !ok || rules[0].Domain != d {
				t.Errorf("%s: bad domain %q", sv.ID, d)
			}
		}
	}
}
