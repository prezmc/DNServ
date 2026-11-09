package server

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserve/internal/policy"
	"github.com/prezmc/dnserve/internal/querylog"
	"github.com/prezmc/dnserve/internal/store"
)

// BenchmarkHandle measures the in-process query path (no sockets) with the
// query log on, for the answers that dominate home traffic.
func BenchmarkHandle(b *testing.B) {
	client := netip.MustParseAddr("192.168.1.20")
	for _, tc := range []struct {
		name   string
		qname  string
		groups bool
	}{
		{"cached", "www.example.com.", false},
		{"blocked", "x.ads.example.", false},
		{"cached-in-group", "www.example.com.", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s, _ := newTestServer(b, nil, &fakeResolver{})
			s.SetQueryLog(querylog.New(20000))
			if tc.groups {
				st := &store.State{
					Groups: map[string]*store.Group{"kids": {ID: "kids", Name: "Kids", Rules: []string{"||games.example^"},
						Schedules: []store.Schedule{{Name: "Bedtime", Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: "03:00", End: "03:01", BlockAll: true}}}},
					Devices: map[string]*store.Device{},
				}
				for i := 0; i < 50; i++ {
					st.Devices[fmt.Sprint(i)] = &store.Device{ID: fmt.Sprint(i), Name: fmt.Sprint(i), Addrs: []string{fmt.Sprintf("192.168.1.%d", i)}, Group: "kids"}
				}
				s.SetPolicy(policy.Build(st))
			}
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, dns.TypeA)
			s.Handle(req.Copy(), client, true) // warm the cache
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					s.Handle(req.Copy(), client, true)
				}
			})
		})
	}
}
