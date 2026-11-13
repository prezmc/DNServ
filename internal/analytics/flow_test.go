package analytics

import (
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/querylog"
)

func TestFlow(t *testing.T) {
	for _, tc := range []struct {
		name string
		span time.Duration // short ranges read individual queries
	}{{"hourly", 24 * time.Hour}, {"raw", 2 * time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			s := open(t, 30, 90)
			for i := range 20 {
				e := entry(i, "192.168.1.10", "example.com", querylog.Answered)
				e.Upstream = "https://dns.quad9.net/dns-query"
				if i%4 == 0 {
					e.Upstream = "tls://9.9.9.9:853"
				}
				s.Record(e)
				s.Record(entry(i, "192.168.1.11", "example.com", querylog.Cached))
			}
			// Answered before servers were recorded.
			s.Record(entry(30, "192.168.1.11", "old.example", querylog.Answered))
			s.Record(entry(31, "192.168.1.11", "ads.tracker.net", querylog.Blocked))
			s.Record(entry(32, "192.168.1.12", "nas.home", querylog.Local))
			s.Flush()

			r := run(t, s, Query{Kind: KindFlow, From: base.Add(-time.Minute), To: base.Add(-time.Minute + tc.span)})
			if len(r.Flows) != 1 || r.Flows[0].Node != "node-a" {
				t.Fatalf("flows = %+v", r.Flows)
			}
			f := r.Flows[0]
			paths := map[string]int64{}
			for _, p := range f.Paths {
				paths[p.Key] = p.N
			}
			want := map[string]int64{
				PathUp + "https://dns.quad9.net/dns-query": 15, PathUp + "tls://9.9.9.9:853": 5, PathUp: 1,
				PathCache: 20, PathBlocked: 1, PathLocal: 1,
			}
			for k, n := range want {
				if paths[k] != n {
					t.Errorf("path %q = %d, want %d (all %v)", k, paths[k], n, paths)
				}
			}
			clients := map[string]int64{}
			for _, c := range f.Clients {
				clients[c.Key] += c.N
				if c.Key == "192.168.1.12" && c.Kind != FlowInternal {
					t.Errorf("local lookup counted as %s", c.Kind)
				}
			}
			if clients["192.168.1.10"] != 20 || clients["192.168.1.11"] != 22 || clients["192.168.1.12"] != 1 {
				t.Errorf("clients = %v", clients)
			}
			var tls int64
			for _, n := range f.Names {
				if n.Path == PathUp+"tls://9.9.9.9:853" && n.Name == "example.com" {
					tls = n.N
				}
			}
			if tls != 5 {
				t.Errorf("names = %+v", f.Names)
			}

			// One device: only its lookups, with the servers that answered
			// it (both ranges, since the hourly totals don't say).
			r = run(t, s, Query{Kind: KindFlow, From: base.Add(-time.Minute), To: base.Add(-time.Minute + tc.span), Clients: []string{"192.168.1.10"}})
			f = r.Flows[0]
			paths = map[string]int64{}
			for _, p := range f.Paths {
				paths[p.Key] = p.N
			}
			if len(paths) != 2 || paths[PathUp+"https://dns.quad9.net/dns-query"] != 15 || paths[PathUp+"tls://9.9.9.9:853"] != 5 {
				t.Errorf("one device's paths = %v", paths)
			}
			if len(f.Clients) != 1 || f.Clients[0].Key != "192.168.1.10" || f.Clients[0].N != 20 {
				t.Errorf("one device's clients = %+v", f.Clients)
			}
		})
	}
}

func TestTopRows(t *testing.T) {
	rows := topRows(map[string]int64{"a": 5, "b": 3, "c": 1, "d": 1}, 2)
	if len(rows) != 3 || rows[0].Key != "a" || rows[2].Key != "" || rows[2].N != 2 {
		t.Fatalf("rows = %+v", rows)
	}
}
