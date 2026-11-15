package analytics

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/querylog"
)

func withA(e querylog.Entry, ip string) querylog.Entry {
	e.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: e.Name + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
	e.Answers = 1
	return e
}

func testCountry(a netip.Addr) string {
	switch {
	case a.Is4() && a.As4()[0] == 1:
		return "AU"
	case a.Is4() && a.As4()[0] == 5:
		return "RU"
	}
	return ""
}

func TestCountries(t *testing.T) {
	s := open(t, 30, 90)
	// Before location data: recorded without a country, then backfilled.
	s.Record(withA(entry(1, "192.168.1.10", "old.example", querylog.Answered), "5.1.1.1"))
	s.Flush()
	s.SetCountry(testCountry)
	for i := range 4 {
		s.Record(withA(entry(i+2, "192.168.1.10", "news.example", querylog.Answered), "1.2.3.4"))
	}
	s.Record(withA(entry(3, "192.168.1.11", "bad.example", querylog.Cached), "5.6.7.8"))
	s.Record(withA(entry(4, "192.168.1.11", "local.example", querylog.Answered), "192.168.1.5"))
	s.Record(entry(5, "192.168.1.11", "ads.example", querylog.Blocked))
	s.Flush()
	s.BackfillCountries()
	s.bg.Wait()

	day := Query{From: base.Add(-time.Hour), To: base.Add(23 * time.Hour)}
	for _, raw := range []bool{true, false} {
		q := day
		if raw {
			q.To = base.Add(time.Hour) // short: from individual queries
		}
		q.Kind, q.By = KindTop, TopCountries
		r := run(t, s, q)
		if len(r.Rows) != 2 || r.Rows[0].Key != "AU" || r.Rows[0].Total != 4 || r.Rows[1].Key != "RU" || r.Rows[1].Total != 2 {
			t.Fatalf("raw %v: rows %+v", raw, r.Rows)
		}
		q.By, q.Country = TopDomains, "RU"
		r = run(t, s, q)
		if len(r.Rows) != 2 {
			t.Fatalf("raw %v: RU domains %+v", raw, r.Rows)
		}
		q.Clients = []string{"192.168.1.11"}
		q.Kind, q.By = KindTop, TopCountries
		q.Country = ""
		r = run(t, s, q)
		if len(r.Rows) != 1 || r.Rows[0].Key != "RU" || r.Rows[0].Total != 1 {
			t.Fatalf("raw %v: one device %+v", raw, r.Rows)
		}
	}
	q := day
	q.Kind, q.Country, q.Limit = KindSearch, "AU", 100
	if r := run(t, s, q); len(r.Entries) != 4 || r.Entries[0].Name != "news.example" {
		t.Fatalf("search %+v", r.Entries)
	}
	q = day
	q.Kind, q.By = KindFlow, TopCountries
	r := run(t, s, q)
	got := map[string]string{}
	for _, n := range r.Flows[0].Names {
		got[n.Name] = n.CC
	}
	if got["news.example"] != "AU" || got["bad.example"] != "RU" || got["ads.example"] != "" {
		t.Fatalf("flow %v", got)
	}
	q.Country = "au"
	if _, err := s.Run(t.Context(), q); err == nil {
		t.Fatal("lower-case country accepted")
	}
	if err := s.ClearCountries(); err != nil {
		t.Fatal(err)
	}
	q = day
	q.Kind, q.By = KindTop, TopCountries
	if r := run(t, s, q); len(r.Rows) != 0 {
		t.Fatalf("after clear %+v", r.Rows)
	}
}
