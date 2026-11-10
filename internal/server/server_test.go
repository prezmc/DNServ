package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserve/internal/cache"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/policy"
	"github.com/prezmc/dnserve/internal/querylog"
	"github.com/prezmc/dnserve/internal/store"
)

// fakeResolver answers A queries with 192.0.2.1 and counts calls.
type fakeResolver struct {
	calls atomic.Int64
	fail  atomic.Bool
	delay time.Duration
}

func (f *fakeResolver) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.fail.Load() {
		return nil, errors.New("upstream down")
	}
	r := new(dns.Msg)
	r.SetReply(q)
	if q.Question[0].Qtype == dns.TypeA {
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}}
	}
	return r, nil
}

type staticFilter struct{ ix *filter.Index }

func (s staticFilter) Lookup(n string) filter.Match { return s.ix.Lookup(n) }

func newTestServer(t testing.TB, mutate func(*config.Config), r Resolver) (*Server, string) {
	t.Helper()
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:0"}
	cfg.Upstream.Timeout = time.Second
	if mutate != nil {
		mutate(&cfg)
	}
	b := filter.NewBuilder()
	src := b.AddSource("test", filter.TierList)
	b.Add(src, filter.Rule{Domain: "ads.example", Kind: filter.Suffix})

	c := cache.New(cache.Options{MaxEntries: 1000, ServeStale: time.Hour, Prefetch: true})
	s, err := New(cfg, c, staticFilter{b.Build()}, r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	udp, _ := s.Addrs()
	return s, udp[0]
}

func query(t *testing.T, addr, name string, qtype uint16, network string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network, Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return r
}

func TestForwardAndCache(t *testing.T) {
	up := &fakeResolver{}
	_, addr := newTestServer(t, nil, up)

	r := query(t, addr, "www.example.com", dns.TypeA, "udp")
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("unexpected response: %v", r)
	}
	r = query(t, addr, "WWW.Example.com", dns.TypeA, "udp")
	if len(r.Answer) != 1 || r.Question[0].Name != "WWW.Example.com." {
		t.Fatalf("cached response should echo the client's question: %v", r)
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream calls = %d, want 1 (second answer from cache)", n)
	}
}

func TestBlockModes(t *testing.T) {
	for _, mode := range []string{"null_ip", "nxdomain", "refused"} {
		t.Run(mode, func(t *testing.T) {
			up := &fakeResolver{}
			_, addr := newTestServer(t, func(c *config.Config) { c.Filtering.BlockMode = mode }, up)
			r := query(t, addr, "tracker.ads.example", dns.TypeA, "udp")
			switch mode {
			case "null_ip":
				if len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
					t.Fatalf("want 0.0.0.0, got %v", r)
				}
			case "nxdomain":
				if r.Rcode != dns.RcodeNameError || len(r.Ns) != 1 {
					t.Fatalf("want NXDOMAIN with SOA, got %v", r)
				}
			case "refused":
				if r.Rcode != dns.RcodeRefused {
					t.Fatalf("want REFUSED, got %v", r)
				}
			}
			if up.calls.Load() != 0 {
				t.Fatal("blocked query must not reach upstream")
			}
		})
	}
}

func TestServeStaleWhenUpstreamFails(t *testing.T) {
	up := &fakeResolver{}
	s, addr := newTestServer(t, nil, up)
	query(t, addr, "stale.example", dns.TypeA, "udp")

	// Age the entry past its TTL, then take upstream down.
	key := func() string {
		m := new(dns.Msg)
		m.SetQuestion("stale.example.", dns.TypeA)
		return cache.Key(m)
	}()
	expired := new(dns.Msg)
	expired.SetQuestion("stale.example.", dns.TypeA)
	expired.Response = true
	expired.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "stale.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(192, 0, 2, 9)}}
	s.cache.Set(key, expired)
	time.Sleep(1100 * time.Millisecond)
	up.fail.Store(true)

	r := query(t, addr, "stale.example", dns.TypeA, "udp")
	if len(r.Answer) != 1 || r.Answer[0].Header().Ttl != cache.StaleTTL {
		t.Fatalf("want stale answer with TTL %d, got %v", cache.StaleTTL, r)
	}
}

func TestServfailWhenNoCacheAndUpstreamDown(t *testing.T) {
	up := &fakeResolver{}
	up.fail.Store(true)
	_, addr := newTestServer(t, nil, up)
	if r := query(t, addr, "down.example", dns.TypeA, "udp"); r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL, got %v", r)
	}
}

func TestLocalNamesStayLocal(t *testing.T) {
	up := &fakeResolver{}
	_, addr := newTestServer(t, nil, up)
	for _, tc := range []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{"printer", dns.TypeA, dns.RcodeNameError},
		{"nas.lan", dns.TypeA, dns.RcodeNameError},
		{"box.home.arpa", dns.TypeAAAA, dns.RcodeNameError},
		{"1.1.168.192.in-addr.arpa", dns.TypePTR, dns.RcodeNameError},
		{"5.0.0.10.in-addr.arpa", dns.TypePTR, dns.RcodeNameError},
		{"localhost", dns.TypeA, dns.RcodeSuccess},
	} {
		if r := query(t, addr, tc.name, tc.qtype, "udp"); r.Rcode != tc.rcode {
			t.Errorf("%s: rcode %s, want %s", tc.name, dns.RcodeToString[r.Rcode], dns.RcodeToString[tc.rcode])
		}
	}
	// A public reverse lookup is forwarded.
	query(t, addr, "8.8.8.8.in-addr.arpa", dns.TypePTR, "udp")
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1 (only the public PTR)", up.calls.Load())
	}
}

func TestACLRefusesOutsideClients(t *testing.T) {
	up := &fakeResolver{}
	_, addr := newTestServer(t, func(c *config.Config) { c.DNS.AllowedNets = []string{"10.0.0.0/8"} }, up)
	if r := query(t, addr, "example.com", dns.TypeA, "udp"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("loopback client outside allowed_nets should be refused, got %v", r)
	}
}

func TestTCPAndConcurrentDedup(t *testing.T) {
	up := &fakeResolver{delay: 100 * time.Millisecond}
	s, _ := newTestServer(t, nil, up)
	_, tcp := s.Addrs()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			query(t, tcp[0], "same.example", dns.TypeA, "tcp")
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream calls = %d, want 1 (identical concurrent queries collapsed)", n)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(5)
	ip := clientAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)})
	now := time.Now()
	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.allow(ip, now) {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("burst allowed %d, want 10 (2x qps)", allowed)
	}
	if !rl.allow(ip, now.Add(time.Second)) {
		t.Fatal("tokens should refill after a second")
	}
}

// routerResolver plays a LAN router that knows device names.
type routerResolver struct{ calls atomic.Int64 }

func (r *routerResolver) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	m := new(dns.Msg)
	m.SetReply(q)
	qq := q.Question[0]
	switch {
	case qq.Qtype == dns.TypePTR && qq.Name == "10.1.168.192.in-addr.arpa.":
		m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "kids-ipad.lan."}}
	case qq.Qtype == dns.TypeA && qq.Name == "nas.lan.":
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 168, 1, 5)}}
	default:
		m.Rcode = dns.RcodeNameError
	}
	return m, nil
}

func TestLocalNamesGoToRouter(t *testing.T) {
	up, router := &fakeResolver{}, &routerResolver{}
	s, addr := newTestServer(t, nil, up)
	s.SetLocalDNS(router)
	if r := query(t, addr, "nas.lan", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatalf("nas.lan via router: %v", r)
	}
	if r := query(t, addr, "10.1.168.192.in-addr.arpa", dns.TypePTR, "udp"); len(r.Answer) != 1 {
		t.Fatalf("private PTR via router: %v", r)
	}
	if name := s.LookupName(context.Background(), netip.MustParseAddr("192.168.1.10")); name != "kids-ipad.lan" {
		t.Fatalf("LookupName = %q", name)
	}
	if up.calls.Load() != 0 {
		t.Fatal("local names leaked upstream")
	}
	s.SetLocalDNS(nil)
	if r := query(t, addr, "nas.lan", dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("after clearing the router, nas.lan should be NXDOMAIN: %v", r)
	}
}

func TestQueryLogRecords(t *testing.T) {
	s, addr := newTestServer(t, nil, &fakeResolver{})
	ql := querylog.New(100)
	s.SetQueryLog(ql)
	query(t, addr, "www.example.com", dns.TypeA, "udp")
	query(t, addr, "x.ads.example", dns.TypeA, "udp")
	got := ql.Query(querylog.Filter{})
	if len(got) != 2 {
		t.Fatalf("logged %d queries", len(got))
	}
	if b := got[0]; b.Name != "x.ads.example" || b.Result != querylog.Blocked || b.Rule != "||ads.example^" || b.List != "test" || !b.Client.IsLoopback() {
		t.Fatalf("blocked entry: %+v", b)
	}
	if a := got[1]; a.Result != querylog.Answered || a.Answers != 1 || a.Type != "A" {
		t.Fatalf("answered entry: %+v", a)
	}
}

func TestGroupPolicies(t *testing.T) {
	s, addr := newTestServer(t, nil, &fakeResolver{})
	st := &store.State{
		Groups: map[string]*store.Group{
			"kids": {ID: "kids", Name: "Kids", Rules: []string{"||games.example^"}},
			"work": {ID: "work", Name: "Work", SkipBlocklists: true},
		},
		Devices: map[string]*store.Device{"me": {ID: "me", Name: "Me", Addrs: []string{"127.0.0.1"}, Group: "kids"}},
	}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "games.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("group rule not applied: %v", r)
	}
	if r := query(t, addr, "x.ads.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("shared list not applied to group: %v", r)
	}
	st.Devices["me"].Group = "work"
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "x.ads.example", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("work group should skip shared lists: %v", r)
	}
	if r := query(t, addr, "games.example", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("kids rule leaked to work: %v", r)
	}
	s.SetPolicy(nil)
	if r := query(t, addr, "x.ads.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("no policy: shared list should apply: %v", r)
	}
}

func isBlocked(r *dns.Msg) bool {
	if r.Rcode == dns.RcodeNameError {
		return true
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.IsUnspecified() {
			return true
		}
	}
	return false
}

func TestPauseFiltering(t *testing.T) {
	up := &fakeResolver{}
	s, addr := newTestServer(t, nil, up)
	if r := query(t, addr, "tracker.ads.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatal("want blocked before the pause")
	}
	s.SetPause(true, time.Time{})
	if r := query(t, addr, "tracker.ads.example", dns.TypeA, "udp"); isBlocked(r) || up.calls.Load() != 1 {
		t.Fatalf("paused: want a real answer, got %v", r)
	}
	if r := query(t, addr, "use-application-dns.net", dns.TypeA, "udp"); r.Rcode == dns.RcodeNameError {
		t.Fatal("paused: Firefox canary still blocked")
	}
	s.SetPause(true, time.Now().Add(-time.Second)) // already over
	if r := query(t, addr, "tracker.ads.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatal("expired pause still lets blocked names through")
	}
	s.SetPause(true, time.Now().Add(time.Minute))
	if r := query(t, addr, "x.ads.example", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatal("timed pause not applied")
	}
	s.SetPause(false, time.Time{})
	if r := query(t, addr, "x.ads.example", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatal("want blocked after resume")
	}
}

// cnameResolver answers every name with a CNAME to target, then an A.
type cnameResolver struct{ target string }

func (c cnameResolver) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(q)
	n := q.Question[0].Name
	if q.Question[0].Qtype == dns.TypeA {
		r.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "edge.example.net."},
			&dns.CNAME{Hdr: dns.RR_Header{Name: "edge.example.net.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: dns.Fqdn(c.target)},
			&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(c.target), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 7)},
		}
	}
	return r, nil
}

func TestCNAMEBlocking(t *testing.T) {
	s, addr := newTestServer(t, nil, cnameResolver{target: "Cdn.Ads.Example"})
	for i := 0; i < 2; i++ { // the second answer comes from the cache
		if r := query(t, addr, "assets.news.example", dns.TypeA, "udp"); !isBlocked(r) {
			t.Fatalf("alias of a blocked name answered (try %d): %v", i, r)
		}
	}
	st := &store.State{
		Groups:  map[string]*store.Group{"g": {ID: "g", Name: "G", Rules: []string{"@@||assets.news.example^"}}},
		Devices: map[string]*store.Device{"me": {ID: "me", Name: "Me", Addrs: []string{"127.0.0.1"}, Group: "g"}},
	}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "assets.news.example", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("an allowed name must not be blocked by its CNAME: %v", r)
	}
	st.Groups["g"].Rules = nil
	st.Groups["g"].SkipBlocklists = true
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "assets.news.example", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("a group that skips blocklists must skip them for CNAMEs too: %v", r)
	}

	_, addr2 := newTestServer(t, nil, cnameResolver{target: "cdn.good.example"})
	if r := query(t, addr2, "assets.news.example", dns.TypeA, "udp"); isBlocked(r) || len(r.Answer) != 3 {
		t.Fatalf("alias of an unblocked name should be answered: %v", r)
	}
}

func TestAnswerIPBlocking(t *testing.T) {
	s, addr := newTestServer(t, nil, &fakeResolver{}) // answers 192.0.2.1
	st := &store.State{
		Groups:  map[string]*store.Group{"g": {ID: "g", Name: "G", Rules: []string{"||2.1^"}}},
		Devices: map[string]*store.Device{"me": {ID: "me", Name: "Me", Addrs: []string{"127.0.0.1"}, Group: "g"}},
	}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.example.com", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("a rule for part of an address must not block it: %v", r)
	}
	st.Groups["g"].Rules = []string{"||192.0.2.1^"}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.example.com", dns.TypeA, "udp"); !isBlocked(r) {
		t.Fatalf("an answer with a listed address should be blocked: %v", r)
	}
	st.Groups["g"].Rules = []string{"||192.0.2.1^", "@@||www.example.com^"}
	s.SetPolicy(policy.Build(st))
	if r := query(t, addr, "www.example.com", dns.TypeA, "udp"); isBlocked(r) {
		t.Fatalf("an allowed name keeps its answer: %v", r)
	}
}
