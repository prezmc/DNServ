package analytics

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prezmc/dnserv/internal/querylog"
)

func TestCacheMiss(t *testing.T) {
	s := open(t, 30, 90)
	up := func(sec int, name string, ttl uint32) querylog.Entry {
		e := entry(0, "192.168.1.10", name, querylog.Answered)
		e.Time = base.Add(time.Duration(sec) * time.Second)
		e.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)}}
		return e
	}
	hit := func(sec int, name string) querylog.Entry {
		e := entry(0, "192.168.1.10", name, querylog.Cached)
		e.Time = base.Add(time.Duration(sec) * time.Second)
		return e
	}
	s.Record(up(0, "short.example", 20))   // first
	s.Record(hit(10, "short.example"))     // hit
	s.Record(up(100, "short.example", 20)) // short cache time ran out
	s.Record(up(0, "long.example", 300))   // first
	s.Record(up(900, "long.example", 300)) // expired
	s.Record(up(950, "long.example", 300)) // asked again while it should be cached
	f := entry(0, "192.168.1.10", "broken.example", querylog.Failed)
	f.Time = base.Add(5 * time.Second)
	s.Record(f)                              // failed
	s.Record(up(30, "broken.example", 3600)) // after a failure
	s.Flush()

	q := Query{Kind: KindCache, From: base.Add(-time.Minute), To: base.Add(time.Hour)}
	r := Merge(q, []*Result{run(t, s, q)})
	want := map[string]int64{MissFirst: 2, MissShort: 1, MissExpired: 1, MissEarly: 1, MissFailed: 2}
	got := map[string]int64{}
	for _, m := range r.Misses {
		if m.Name == "" {
			got[m.Reason] = m.N
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	var short Miss
	for _, m := range r.Misses {
		if m.Reason == MissShort && m.Name == "short.example" {
			short = m
		}
	}
	if short.N != 1 || short.TTL != 20 {
		t.Errorf("short.example = %+v", short)
	}
}
