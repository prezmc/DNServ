package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserve/internal/cache"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
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

func newTestServer(t *testing.T, mutate func(*config.Config), r Resolver) (*Server, string) {
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
