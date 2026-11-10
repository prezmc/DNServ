package analytics

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/querylog"
)

func TestHistQuantile(t *testing.T) {
	var h Hist
	for i := 0; i < 90; i++ {
		h.Add(0.8) // (0.5, 1]
	}
	for i := 0; i < 10; i++ {
		h.Add(40) // (30, 50]
	}
	if q := h.Quantile(.5, 45); q <= 0.5 || q > 1 {
		t.Fatalf("p50 = %v", q)
	}
	if q := h.Quantile(.95, 45); q <= 30 || q > 45 {
		t.Fatalf("p95 = %v", q)
	}
	var empty Hist
	if empty.Quantile(.5, 0) != 0 {
		t.Fatal("empty quantile")
	}
	var slow Hist
	slow.Add(9000)
	if q := slow.Quantile(.99, 9000); q < 5000 || q > 9000 {
		t.Fatalf("open bucket p99 = %v", q)
	}
}

func timed(min int, result string, ms float64) querylog.Entry {
	e := entry(min, "192.168.1.10", "example.com", result)
	e.Duration = ms
	if result == querylog.Failed {
		e.Rcode = "SERVFAIL"
	}
	return e
}

func TestPerfRecordAndRun(t *testing.T) {
	s := open(t, 30, 90)
	for i := range 20 {
		s.Record(timed(i, querylog.Answered, 20))
		s.Record(timed(i, querylog.Cached, 0.1))
	}
	s.Record(timed(3, querylog.Failed, 4000))
	s.Record(timed(3, querylog.Blocked, 0.05))
	s.ObserveUpstream("https://cloudflare-dns.com/dns-query", base.Add(time.Minute), 18*time.Millisecond, 0, nil)
	s.ObserveUpstream("https://cloudflare-dns.com/dns-query", base.Add(time.Minute), 2*time.Second, -1, context.DeadlineExceeded)
	s.ObserveUpstream("https://cloudflare-dns.com/dns-query", base.Add(2*time.Minute), time.Millisecond, -1, errors.New("refused"))
	s.ObserveUpstream("https://cloudflare-dns.com/dns-query", base.Add(2*time.Minute), 30*time.Millisecond, 2, nil)
	s.Flush()
	// Recording again into the same slot adds to it.
	s.Record(timed(1, querylog.Answered, 20))
	s.Flush()

	r := run(t, s, Query{Kind: KindPerf, From: base, To: base.Add(time.Hour), Step: 300, Limit: 10})
	p := r.Perf
	if p == nil || len(p.Series) != 4 {
		t.Fatalf("series = %+v", p)
	}
	var tot PerfPoint
	for i := range p.Series {
		tot.merge(&p.Series[i])
	}
	if tot.All.N != 43 || tot.Upstream.N != 21 || tot.Cached != 20 || tot.Failed != 1 || tot.Blocked != 1 || tot.Servfail != 1 {
		t.Fatalf("totals = %+v", tot)
	}
	if tot.Upstream.Avg() != 20 || tot.All.Max != 4000 {
		t.Fatalf("avg %v max %v", tot.Upstream.Avg(), tot.All.Max)
	}
	if a := p.Types["A"]; a == nil || a.N != 43 {
		t.Fatalf("types = %+v", p.Types)
	}
	if len(p.Upstreams) != 1 {
		t.Fatalf("upstreams = %+v", p.Upstreams)
	}
	u := p.Upstreams[0]
	if u.Node != "node-a" || u.Total.Tries != 4 || u.Total.Timeouts != 1 || u.Total.Errors != 1 || u.Total.Servfail != 1 || u.Total.Stat.N != 2 {
		t.Fatalf("upstream = %+v", u.Total)
	}
	if len(p.Domains) != 1 || p.Domains[0].Key != "example.com" || p.Domains[0].N != 21 {
		t.Fatalf("domains = %+v", p.Domains)
	}
	if p.Devices != nil {
		t.Fatal("devices without asking")
	}

	q := Query{Kind: KindPerf, From: base, To: base.Add(time.Hour), Step: 3600, Devices: true, Baseline: 86400}
	r = run(t, s, q)
	if len(r.Perf.Devices) != 1 || r.Perf.Devices[0].Cached != 20 || r.Perf.Devices[0].Upstream != 21 || r.Perf.Devices[0].Failed != 1 {
		t.Fatalf("devices = %+v", r.Perf.Devices)
	}
	if len(r.Perf.Baseline) != 0 {
		t.Fatalf("baseline should be empty: %+v", r.Perf.Baseline)
	}

	// Two nodes merge: series add up, upstreams stay per node.
	other := *r
	otherPerf := *r.Perf
	otherPerf.Upstreams = []UpSeries{{Node: "node-b", Server: u.Server, Total: UpPoint{Tries: 1}}}
	other.Perf = &otherPerf
	m := Merge(q, []*Result{r, &other})
	if m.Perf.Series[0].All.N != 86 || len(m.Perf.Upstreams) != 2 || m.Perf.Devices[0].N != 86 {
		t.Fatalf("merged = %+v", m.Perf)
	}

	v := Report(m.Perf, 3600, 1)
	if v.Summary.Queries != 86 || math.Abs(v.Summary.CacheHit-40.0/(40+42+2)) > 1e-9 || v.Summary.Failed != 2 {
		t.Fatalf("summary = %+v", v.Summary)
	}
	if v.Summary.LookupP50 < 15 || v.Summary.LookupP50 > 20 {
		t.Fatalf("lookup p50 = %v", v.Summary.LookupP50)
	}
	if len(v.Dist) != HistLen || len(v.Upstreams) != 2 {
		t.Fatalf("view = %+v", v)
	}
}

func TestPerfPrune(t *testing.T) {
	s := open(t, 1, 2)
	s.now = func() time.Time { return base.AddDate(0, 0, 5) }
	s.Record(timed(0, querylog.Answered, 5))
	s.ObserveUpstream("udp://1.1.1.1:53", base, time.Millisecond, 0, nil)
	s.Flush()
	s.prune()
	var n int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM perf) + (SELECT COUNT(*) FROM upstream_perf)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d perf rows left", n)
	}
}

// steady builds hourly points with usual lookups of about 20 ms.
func steady(from int64, hours int) []PerfPoint {
	var out []PerfPoint
	for i := range hours {
		p := PerfPoint{T: from + int64(i)*3600, Cached: 300}
		for j := range 100 {
			ms := 15.0 + float64(j%10)
			p.Upstream.add(ms)
			p.All.add(ms)
		}
		for range 300 {
			p.All.add(0.1)
		}
		out = append(out, p)
	}
	return out
}

func TestAnomalies(t *testing.T) {
	start := base.Unix()
	p := &Perf{Baseline: steady(start-7*86400, 7*24), Series: steady(start, 24)}
	v := Report(p, 3600, 24)
	if len(v.Anomalies) != 0 || v.UsualFrom != "before" || v.Usual == nil {
		t.Fatalf("steady traffic flagged: %+v (usual from %q)", v.Anomalies, v.UsualFrom)
	}

	// Hours 10 and 11 slow, hour 15 failing, hour 20 a surge, and an
	// upstream timing out in hour 12.
	for _, h := range []int{10, 11} {
		pt := &p.Series[h]
		pt.Upstream = PerfStat{}
		for range 100 {
			pt.Upstream.add(400)
		}
	}
	p.Series[15].Failed = 50
	for range 5000 {
		p.Series[20].All.add(0.1)
	}
	p.Series[20].Cached += 5000
	p.Upstreams = []UpSeries{{Node: "node-a", Server: "tls://9.9.9.9:853", Points: []UpPoint{{T: start + 12*3600, Tries: 20, Timeouts: 8, Stat: PerfStat{N: 12}}}}}
	v = Report(p, 3600, 24)
	kinds := map[string]Anomaly{}
	for _, a := range v.Anomalies {
		kinds[a.Kind] = a
	}
	if a, ok := kinds["slow"]; !ok || a.T != start+10*3600 || a.End != start+11*3600 || a.Severity != "bad" || !strings.Contains(a.Detail, "usually") {
		t.Fatalf("slow = %+v (all %+v)", a, v.Anomalies)
	}
	if a, ok := kinds["failures"]; !ok || a.T != start+15*3600 {
		t.Fatalf("failures = %+v", a)
	}
	if _, ok := kinds["surge"]; !ok {
		t.Fatalf("no surge: %+v", v.Anomalies)
	}
	if a, ok := kinds["upstream-fail"]; !ok || a.Server != "tls://9.9.9.9:853" || a.Severity != "bad" || !strings.Contains(a.Detail, "8 timeouts") {
		t.Fatalf("upstream = %+v", a)
	}
	if len(v.Anomalies) != 4 || v.Anomalies[0].Kind != "surge" {
		t.Fatalf("anomalies = %+v", v.Anomalies)
	}

	// A new install with no history only flags clearly slow lookups.
	fresh := &Perf{Series: steady(start, 3)}
	if v := Report(fresh, 3600, 3); len(v.Anomalies) != 0 || v.Usual != nil {
		t.Fatalf("fresh = %+v", v)
	}
}

// History from before response times were tracked is rolled up once.
func TestPerfBackfill(t *testing.T) {
	path := t.TempDir() + "/history.db"
	logger := open(t, 30, 90).log
	s, err := Open(path, func() string { return "n" }, 30, 90, logger)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		s.Record(timed(i, querylog.Answered, 12))
	}
	s.Flush()
	s.Close()
	// Make it look like a database from the previous version.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE perf; DROP TABLE upstream_perf; DROP TABLE meta`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	count := func(s *Store) int64 {
		var n sql.NullInt64
		s.db.QueryRow(`SELECT SUM(n) FROM perf`).Scan(&n)
		return n.Int64
	}
	for round := range 2 { // a second start must not count them again
		s, err = Open(path, func() string { return "n" }, 30, 90, logger)
		if err != nil {
			t.Fatal(err)
		}
		e := timed(0, querylog.Answered, 12) // new since the update
		e.Time = time.Now()
		s.Record(e)
		s.Flush()
		s.bg.Wait()
		if got := count(s); got != int64(51+round) {
			t.Fatalf("round %d: %d queries in perf, want %d", round, got, 51+round)
		}
		s.Close()
	}
}
