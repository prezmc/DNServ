package querylog

import (
	"net/netip"
	"testing"
	"time"
)

func TestRingAndFilters(t *testing.T) {
	l := New(3)
	a, b := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.11")
	t0 := time.Unix(1_800_000_000, 0)
	for i, e := range []Entry{
		{Client: a, Name: "one.example", Result: Answered},
		{Client: b, Name: "ads.example", Result: Blocked},
		{Client: a, Name: "two.example", Result: Cached, Allowed: true},
		{Client: a, Name: "ads.tracker.example", Result: Blocked},
	} {
		e.Time = t0.Add(time.Duration(i) * time.Second)
		l.Add(e)
	}
	if l.Len() != 3 {
		t.Fatalf("len %d, want 3 (ring size)", l.Len())
	}
	all := l.Query(Filter{})
	if len(all) != 3 || all[0].Name != "ads.tracker.example" || all[2].Name != "ads.example" {
		t.Fatalf("newest-first order wrong: %+v", all)
	}
	if got := l.Query(Filter{Clients: []netip.Addr{a}}); len(got) != 2 {
		t.Fatalf("client filter: %d", len(got))
	}
	if got := l.Query(Filter{Result: Blocked, Search: "ADS"}); len(got) != 2 {
		t.Fatalf("result+search filter: %d", len(got))
	}
	if got := l.Query(Filter{Result: "allowed"}); len(got) != 1 || got[0].Name != "two.example" {
		t.Fatalf("allowed filter: %+v", got)
	}
	if got := l.Query(Filter{Before: all[0].ID, Limit: 1}); len(got) != 1 || got[0].ID != all[1].ID {
		t.Fatalf("paging: %+v", got)
	}
	cs := l.Clients()
	if len(cs) != 2 || cs[0].Addr != a || cs[0].Queries != 3 || cs[0].Blocked != 1 || cs[1].Blocked != 1 {
		t.Fatalf("clients: %+v", cs)
	}
}

func BenchmarkAdd(b *testing.B) {
	l := New(20000)
	e := Entry{Client: netip.MustParseAddr("192.168.1.10"), Name: "example.com", Result: Cached, Time: time.Now()}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Add(e)
		}
	})
}
