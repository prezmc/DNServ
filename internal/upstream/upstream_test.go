package upstream

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startUDP(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func answerA(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 7)}}
	w.WriteMsg(r)
}

func TestPlainUDP(t *testing.T) {
	addr := startUDP(t, answerA)
	g, err := NewGroup([]string{"udp://" + addr}, nil, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r, err := g.Exchange(context.Background(), q)
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("exchange: %v %v", r, err)
	}
}

func TestFailover(t *testing.T) {
	good := startUDP(t, answerA)
	// 127.0.0.1:1 refuses connections; the group must fall through to good.
	g, err := NewGroup([]string{"udp://127.0.0.1:1", "udp://" + good}, nil, 300*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	for i := 0; i < 3; i++ {
		if _, err := g.Exchange(context.Background(), q); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	st := g.Stats()
	if st[0].Failures == 0 || st[1].Queries < 3 {
		t.Fatalf("stats = %+v", st)
	}
	// After a failure the healthy server is ordered first.
	if g.order()[0].ex.String() != "udp://"+good {
		t.Fatal("healthy upstream should be tried first after failures")
	}
}

func TestDoH(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil || q.Id != 0 {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 8)}}
		b, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL + "/dns-query")
	d := newDoH(u, NewBootstrap(nil, time.Second), time.Second)
	d.client = ts.Client()
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	r, err := d.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Id != q.Id || len(r.Answer) != 1 {
		t.Fatalf("got %v, want answer with the original ID", r)
	}
}

func TestBootstrapResolves(t *testing.T) {
	addr := startUDP(t, answerA)
	b := NewBootstrap([]string{addr}, time.Second)
	ips, err := b.Resolve(context.Background(), "doh.example")
	if err != nil || len(ips) == 0 || ips[0] != "192.0.2.7" {
		t.Fatalf("resolve = %v, %v", ips, err)
	}
	if ips, _ := b.Resolve(context.Background(), "1.1.1.1"); ips[0] != "1.1.1.1" {
		t.Fatal("IP literals must pass through")
	}
}

func TestObserver(t *testing.T) {
	good := startUDP(t, answerA)
	g, err := NewGroup([]string{"udp://127.0.0.1:1", "udp://" + good}, nil, 300*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	type call struct {
		server string
		rcode  int
		err    bool
	}
	var calls []call
	g.SetObserver(func(server string, _ time.Time, d time.Duration, rcode int, err error) {
		calls = append(calls, call{server, rcode, err != nil})
	})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if _, err := g.Exchange(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !calls[0].err || calls[0].rcode != -1 || calls[1].err || calls[1].server != "udp://"+good || calls[1].rcode != dns.RcodeSuccess {
		t.Fatalf("calls = %+v", calls)
	}
}

type instant struct{ resp *dns.Msg }

func (i instant) Exchange(context.Context, *dns.Msg) (*dns.Msg, error) { return i.resp, nil }
func (instant) String() string                                         { return "udp://192.0.2.1:53" }

// BenchmarkGroupExchange measures the group's own overhead per exchange,
// with and without an observer, against an upstream that answers at once.
func BenchmarkGroupExchange(b *testing.B) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	for _, obs := range []bool{false, true} {
		name := "plain"
		if obs {
			name = "observed"
		}
		b.Run(name, func(b *testing.B) {
			g := &Group{members: []*member{{ex: instant{resp}}}}
			if obs {
				ch := make(chan time.Duration, 1024)
				g.SetObserver(func(_ string, _ time.Time, d time.Duration, _ int, _ error) {
					select {
					case ch <- d:
					default:
					}
				})
			}
			b.ReportAllocs()
			for b.Loop() {
				g.Exchange(context.Background(), q)
			}
		})
	}
}

// A server that failed once, or was slow once, must be measured again and
// win back first place; before probes it never got another query.
func TestRecoversAfterFailure(t *testing.T) {
	oldEvery, oldBackoff := probeEvery, failBackoff
	probeEvery, failBackoff = 20*time.Millisecond, time.Hour
	t.Cleanup(func() { probeEvery, failBackoff = oldEvery, oldBackoff })

	var drop atomic.Bool
	fast := startUDP(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if drop.Load() {
			return // no answer: the client times out
		}
		answerA(w, q)
	})
	slow := startUDP(t, func(w dns.ResponseWriter, q *dns.Msg) {
		time.Sleep(15 * time.Millisecond)
		answerA(w, q)
	})
	g, err := NewGroup([]string{"udp://" + fast, "udp://" + slow}, nil, 100*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ask := func() {
		t.Helper()
		if _, err := g.Exchange(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	ask() // fast answers
	ask() // slow, not measured yet, goes first once
	drop.Store(true)
	ask() // fast times out, slow answers
	if g.order()[0].ex.String() != "udp://"+slow {
		t.Fatal("after a failure the other server should be first")
	}
	drop.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for g.order()[0].ex.String() != "udp://"+fast {
		if time.Now().After(deadline) {
			t.Fatalf("the fast server never got first place back: %+v", g.Stats())
		}
		time.Sleep(25 * time.Millisecond)
		ask()
	}
}

func TestStrategies(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	var hits [3]atomic.Int64
	addrs := make([]string, 3)
	for i := range addrs {
		// The last is fastest, but slow enough that the others get the
		// query before parallel mode cancels them.
		delay := time.Duration(3-i) * 20 * time.Millisecond
		addrs[i] = "udp://" + startUDP(t, func(w dns.ResponseWriter, q *dns.Msg) {
			hits[i].Add(1)
			time.Sleep(delay)
			answerA(w, q)
		})
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	run := func(s Strategy, n int) [3]int64 {
		t.Helper()
		for i := range hits {
			hits[i].Store(0)
		}
		g, err := NewGroup(addrs, nil, time.Second, quiet)
		if err != nil {
			t.Fatal(err)
		}
		g.SetStrategy(s)
		for i := 0; i < n; i++ {
			if _, err := g.Exchange(context.Background(), q); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(100 * time.Millisecond) // let parallel stragglers land
		return [3]int64{hits[0].Load(), hits[1].Load(), hits[2].Load()}
	}
	if h := run(InOrder, 4); h != [3]int64{4, 0, 0} {
		t.Errorf("in order: %v", h)
	}
	if h := run(RoundRobin, 6); h != [3]int64{2, 2, 2} {
		t.Errorf("round robin: %v", h)
	}
	if h := run(Parallel, 3); h != [3]int64{3, 3, 3} {
		t.Errorf("parallel: %v", h)
	}
	// Parallel answers as fast as the fastest server.
	g, _ := NewGroup(addrs, nil, time.Second, quiet)
	g.SetStrategy(Parallel)
	start := time.Now()
	if _, err := g.Exchange(context.Background(), q); err != nil || time.Since(start) > 50*time.Millisecond {
		t.Errorf("parallel took %v (err %v)", time.Since(start), err)
	}
	if g.SetStrategy("bogus"); g.strategy != Fastest {
		t.Errorf("unknown strategy should mean fastest, got %q", g.strategy)
	}
}

func TestHedgesSlowServer(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	var slowHits, fastHits atomic.Int64
	var stall atomic.Bool
	slow := startUDP(t, func(w dns.ResponseWriter, q *dns.Msg) {
		slowHits.Add(1)
		if stall.Load() {
			time.Sleep(500 * time.Millisecond)
		}
		answerA(w, q)
	})
	fast := startUDP(t, func(w dns.ResponseWriter, q *dns.Msg) {
		fastHits.Add(1)
		answerA(w, q)
	})
	g, err := NewGroup([]string{"udp://" + slow, "udp://" + fast}, nil, 2*time.Second, quiet)
	if err != nil {
		t.Fatal(err)
	}
	g.SetStrategy(InOrder)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	// Healthy: only the first server is asked.
	for i := 0; i < 3; i++ {
		if _, err := g.Exchange(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	if fastHits.Load() != 0 {
		t.Fatalf("second server asked %d times while the first was quick", fastHits.Load())
	}
	// The first stalls: the second is asked after the hedge delay, and its
	// answer comes back long before the first's (or the timeout).
	stall.Store(true)
	start := time.Now()
	_, from, err := g.ExchangeFrom(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 300*time.Millisecond || from != "udp://"+fast {
		t.Fatalf("took %v, answered by %s", took, from)
	}
}
