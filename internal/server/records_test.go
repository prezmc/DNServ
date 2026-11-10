package server

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/config"
)

func TestLocalRecords(t *testing.T) {
	up := &fakeResolver{}
	s, addr := newTestServer(t, nil, up)
	s.SetRecords(NewRecords([]config.Record{
		{Name: "NAS.home.", Value: "192.168.1.20"},
		{Name: "nas.home", Value: "fd00::20"},
		{Name: "files.home", Value: "nas.home"},
		{Name: "*.lab.home", Value: "192.168.1.30"},
		{Name: "printer.lan", Value: "192.168.1.40"},
		{Name: "tv.home", Value: "www.example.com"},
		{Name: "ads.example", Value: "192.168.1.50"},
	}))

	r := query(t, addr, "nas.home", dns.TypeA, "udp")
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.20" || !r.Authoritative {
		t.Fatalf("A: %v", r)
	}
	if r := query(t, addr, "nas.home", dns.TypeAAAA, "udp"); len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "fd00::20" {
		t.Fatalf("AAAA: %v", r)
	}
	// A type the name doesn't have: no data, not forwarded.
	if r := query(t, addr, "printer.lan", dns.TypeAAAA, "udp"); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("no AAAA: %v", r)
	}
	// Alias to a local name.
	r = query(t, addr, "files.home", dns.TypeA, "udp")
	if len(r.Answer) != 2 || r.Answer[0].(*dns.CNAME).Target != "nas.home." || r.Answer[1].Header().Name != "nas.home." {
		t.Fatalf("local alias: %v", r)
	}
	// Wildcard covers names below it, not the name itself.
	if r := query(t, addr, "a.b.lab.home", dns.TypeA, "udp"); len(r.Answer) != 1 || r.Answer[0].Header().Name != "a.b.lab.home." {
		t.Fatalf("wildcard: %v", r)
	}
	if r := query(t, addr, "lab.home", dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("wildcard parent: %v", r)
	}
	// Reverse lookup.
	if r := query(t, addr, "20.1.168.192.in-addr.arpa", dns.TypePTR, "udp"); len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != "nas.home." {
		t.Fatalf("PTR: %v", r)
	}
	// A local record wins over a blocklist.
	if r := query(t, addr, "ads.example", dns.TypeA, "udp"); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.50" {
		t.Fatalf("record over blocklist: %v", r)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("local records went upstream %d times", up.calls.Load())
	}
	// Alias to a public name is looked up upstream.
	r = query(t, addr, "tv.home", dns.TypeA, "udp")
	if len(r.Answer) != 2 || r.Answer[1].(*dns.A).A.String() != "192.0.2.1" || up.calls.Load() != 1 {
		t.Fatalf("public alias: %v", r)
	}
	s.SetRecords(NewRecords(nil))
	if r := query(t, addr, "nas.home", dns.TypeA, "udp"); len(r.Answer) != 0 {
		t.Fatalf("cleared: %v", r)
	}
}

func TestNormalizeRecords(t *testing.T) {
	for _, bad := range [][]config.Record{
		{{Name: "bad name", Value: "1.2.3.4"}},
		{{Name: "a.home", Value: "not valid!"}},
		{{Name: "a.home", Value: "a.home"}},
		{{Name: "a.home", Value: "b.home"}, {Name: "a.home", Value: "1.2.3.4"}},
		{{Name: "a.home", Value: "1.2.3.4"}, {Name: "a.home", Value: "b.home"}},
		{{Name: "a.home", Value: "1.2.3.4"}, {Name: "A.home.", Value: "1.2.3.4"}},
		{{Name: "x.*.home", Value: "1.2.3.4"}},
		{{Name: "localhost", Value: "1.2.3.4"}},
	} {
		if _, err := config.NormalizeRecords(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	got, err := config.NormalizeRecords([]config.Record{{Name: " Nas.Home. ", Value: "::ffff:192.168.1.2"}, {Name: "*.lab.home", Value: "NAS.home."}})
	if err != nil || got[0].Name != "nas.home" || got[0].Value != "192.168.1.2" || got[1].Value != "nas.home" {
		t.Fatalf("normalize: %+v %v", got, err)
	}
}
