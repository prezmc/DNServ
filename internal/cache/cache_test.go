package cache

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newTestCache(o Options) (*Cache, *clock) {
	c := New(o)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	c.now = clk.now
	return c, clk
}

func answer(name string, ttl uint32) (*dns.Msg, *dns.Msg) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)}}
	return q, r
}

func TestFreshStaleExpired(t *testing.T) {
	c, clk := newTestCache(Options{MaxEntries: 100, ServeStale: time.Minute})
	q, r := answer("a.example", 60)
	k := Key(q)
	c.Set(k, r)

	clk.add(20 * time.Second)
	res := c.Get(k)
	if res.State != Fresh || res.Msg.Answer[0].Header().Ttl != 40 {
		t.Fatalf("got state %v ttl %d, want fresh ttl 40", res.State, res.Msg.Answer[0].Header().Ttl)
	}

	clk.add(70 * time.Second) // 30s past expiry, inside the stale window
	res = c.Get(k)
	if res.State != Stale || !res.Refresh || res.Msg.Answer[0].Header().Ttl != StaleTTL {
		t.Fatalf("got %+v, want stale with refresh", res)
	}
	if again := c.Get(k); again.Refresh {
		t.Fatal("refresh must be handed out once while one is in flight")
	}

	clk.add(time.Minute) // past the stale window
	if res = c.Get(k); res.State != Miss {
		t.Fatalf("got state %v, want miss", res.State)
	}
}

func TestPrefetch(t *testing.T) {
	c, clk := newTestCache(Options{MaxEntries: 100, Prefetch: true})
	q, r := answer("p.example", 100)
	k := Key(q)
	c.Set(k, r)
	c.Get(k)
	c.Get(k)
	clk.add(95 * time.Second)
	res := c.Get(k)
	if res.State != Fresh || !res.Refresh {
		t.Fatalf("expected prefetch signal, got %+v", res)
	}
	c.Set(k, r) // refresh lands
	clk.add(10 * time.Second)
	if res = c.Get(k); res.State != Fresh {
		t.Fatalf("entry should be fresh after refresh, got %v", res.State)
	}
}

func TestNegativeAndUncacheable(t *testing.T) {
	c, _ := newTestCache(Options{MaxEntries: 100, NegativeTTL: 30 * time.Second})
	q, _ := answer("nx.example", 0)
	nx := new(dns.Msg)
	nx.SetRcode(q, dns.RcodeNameError)
	nx.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Minttl: 900}}
	c.Set(Key(q), nx)
	if ttl, _ := c.ttlFor(nx); ttl != 30*time.Second {
		t.Fatalf("negative ttl = %v, want capped 30s", ttl)
	}
	if c.Get(Key(q)).State != Fresh {
		t.Fatal("NXDOMAIN with SOA should be cached")
	}

	q2, _ := answer("fail.example", 0)
	sf := new(dns.Msg)
	sf.SetRcode(q2, dns.RcodeServerFailure)
	c.Set(Key(q2), sf)
	if c.Get(Key(q2)).State != Miss {
		t.Fatal("SERVFAIL must not be cached")
	}
}

func TestKeySeparatesDOBitAndCase(t *testing.T) {
	q1 := new(dns.Msg)
	q1.SetQuestion("Example.COM.", dns.TypeA)
	q2 := new(dns.Msg)
	q2.SetQuestion("example.com.", dns.TypeA)
	if Key(q1) != Key(q2) {
		t.Fatal("key must be case-insensitive")
	}
	q2.SetEdns0(1232, true)
	if Key(q1) == Key(q2) {
		t.Fatal("DO bit must be part of the key")
	}
}

func TestEviction(t *testing.T) {
	c, _ := newTestCache(Options{MaxEntries: shards}) // one entry per shard
	for i := 0; i < 1000; i++ {
		q, r := answer(string(rune('a'+i%26))+time.Duration(i).String()+".example", 60)
		c.Set(Key(q), r)
	}
	if n := c.Len(); n > shards {
		t.Fatalf("len = %d, want <= %d", n, shards)
	}
}

func TestSaveLoad(t *testing.T) {
	c, clk := newTestCache(Options{MaxEntries: 100, ServeStale: time.Minute})
	q, r := answer("keep.example", 60)
	q2, r2 := answer("old.example", 1)
	c.Set(Key(q), r)
	c.Set(Key(q2), r2)
	clk.add(5 * time.Minute) // old.example is beyond ttl+stale; keep.example too
	c.Set(Key(q), r)         // refreshed

	path := filepath.Join(t.TempDir(), "cache.gob")
	n, err := c.Save(path)
	if err != nil || n != 1 {
		t.Fatalf("save = %d, %v; want 1 entry", n, err)
	}
	c2, clk2 := newTestCache(Options{MaxEntries: 100, ServeStale: time.Minute})
	clk2.t = clk.t.Add(10 * time.Second)
	if n, err := c2.Load(path); err != nil || n != 1 {
		t.Fatalf("load = %d, %v", n, err)
	}
	res := c2.Get(Key(q))
	if res.State != Fresh || res.Msg.Answer[0].Header().Ttl != 50 {
		t.Fatalf("reloaded entry = %+v", res)
	}
}

func BenchmarkGetHit(b *testing.B) {
	c := New(Options{MaxEntries: 100_000})
	q, r := answer("bench.example", 3600)
	k := Key(q)
	c.Set(k, r)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Get(k)
		}
	})
}
