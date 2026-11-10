package analytics

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
)

// PerfSummary is the response times of a period, ready to show.
type PerfSummary struct {
	Queries int64   `json:"queries"`
	Avg     float64 `json:"avg_ms"`
	P50     float64 `json:"p50_ms"`
	P95     float64 `json:"p95_ms"`
	P99     float64 `json:"p99_ms"`
	Max     float64 `json:"max_ms"`
	// Lookups answered by asking upstream (cache misses).
	Lookups   int64   `json:"lookups"`
	LookupAvg float64 `json:"lookup_avg_ms"`
	LookupP50 float64 `json:"lookup_p50_ms"`
	LookupP95 float64 `json:"lookup_p95_ms"`
	LookupP99 float64 `json:"lookup_p99_ms"`
	// CacheHit is the share of queries that needed resolving (not blocked
	// or local) answered from the cache.
	CacheHit float64 `json:"cache_hit"`
	Failed   int64   `json:"failed"`
	FailRate float64 `json:"fail_rate"`
	Blocked  int64   `json:"blocked"`
	Nxdomain int64   `json:"nxdomain"`
	// PerHour is the average number of queries per hour.
	PerHour float64 `json:"per_hour"`
}

// PerfRow is one bucket of the response-time chart.
type PerfRow struct {
	T         int64   `json:"t"`
	Queries   int64   `json:"queries"`
	Avg       float64 `json:"avg_ms"`
	P50       float64 `json:"p50_ms"`
	P95       float64 `json:"p95_ms"`
	P99       float64 `json:"p99_ms"`
	Lookups   int64   `json:"lookups"`
	LookupAvg float64 `json:"lookup_avg_ms"`
	LookupP95 float64 `json:"lookup_p95_ms"`
	CacheHit  float64 `json:"cache_hit"`
	Failed    int64   `json:"failed"`
}

// DistRow is one histogram bucket: queries that took up to Le ms (0 for
// the open last bucket).
type DistRow struct {
	Le      float64 `json:"le"`
	All     int64   `json:"all"`
	Lookups int64   `json:"lookups"`
}

// TypeRow is the response times of one record type.
type TypeRow struct {
	Type    string  `json:"type"`
	Queries int64   `json:"queries"`
	Avg     float64 `json:"avg_ms"`
	P95     float64 `json:"p95_ms"`
}

// UpstreamRow is how one upstream server performed for one node.
type UpstreamRow struct {
	Node     string  `json:"node"`
	Server   string  `json:"server"`
	Tries    int64   `json:"tries"`
	Answered int64   `json:"answered"`
	Errors   int64   `json:"errors"`
	Timeouts int64   `json:"timeouts"`
	Servfail int64   `json:"servfail"`
	Avg      float64 `json:"avg_ms"`
	P50      float64 `json:"p50_ms"`
	P95      float64 `json:"p95_ms"`
	Max      float64 `json:"max_ms"`
	FailRate float64 `json:"fail_rate"`
	UsualAvg float64 `json:"usual_avg_ms,omitempty"`
	UsualP95 float64 `json:"usual_p95_ms,omitempty"`
	Series   []UpRow `json:"series"`
}

// UpRow is one bucket of an upstream server's chart.
type UpRow struct {
	T      int64   `json:"t"`
	Tries  int64   `json:"tries"`
	Failed int64   `json:"failed"` // errors and timeouts
	Avg    float64 `json:"avg_ms"`
	P95    float64 `json:"p95_ms"`
}

// Anomaly is something unusual in the period. T and End bound the buckets
// it covers (End is the start of the last one).
type Anomaly struct {
	T        int64  `json:"t"`
	End      int64  `json:"end"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // "warn" or "bad"
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// Node and Server are set for upstream anomalies.
	Node   string `json:"node,omitempty"`
	Server string `json:"server,omitempty"`
}

// PerfView is the performance page's data.
type PerfView struct {
	Summary PerfSummary `json:"summary"`
	// Usual is the baseline period (or, without one, the typical bucket of
	// this period), for comparison. Nil when there is too little history.
	Usual     *PerfSummary  `json:"usual,omitempty"`
	UsualFrom string        `json:"usual_from,omitempty"` // "before" or "period"
	Series    []PerfRow     `json:"series"`
	Dist      []DistRow     `json:"dist"`
	Types     []TypeRow     `json:"types"`
	Upstreams []UpstreamRow `json:"upstreams"`
	Anomalies []Anomaly     `json:"anomalies"`
}

func ratio(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func summarize(pts []PerfPoint, hours float64) PerfSummary {
	var t PerfPoint
	for i := range pts {
		t.merge(&pts[i])
	}
	s := PerfSummary{
		Queries: t.All.N, Avg: t.All.Avg(), P50: t.All.Q(.5), P95: t.All.Q(.95), P99: t.All.Q(.99), Max: t.All.Max,
		Lookups: t.Upstream.N, LookupAvg: t.Upstream.Avg(), LookupP50: t.Upstream.Q(.5), LookupP95: t.Upstream.Q(.95), LookupP99: t.Upstream.Q(.99),
		CacheHit: ratio(t.Cached, t.Cached+t.Upstream.N+t.Failed), Failed: t.Failed, FailRate: ratio(t.Failed, t.All.N),
		Blocked: t.Blocked, Nxdomain: t.Nxdomain,
	}
	if hours > 0 {
		s.PerHour = float64(t.All.N) / hours
	}
	return s
}

func row(p *PerfPoint) PerfRow {
	return PerfRow{
		T: p.T, Queries: p.All.N, Avg: p.All.Avg(), P50: p.All.Q(.5), P95: p.All.Q(.95), P99: p.All.Q(.99),
		Lookups: p.Upstream.N, LookupAvg: p.Upstream.Avg(), LookupP95: p.Upstream.Q(.95),
		CacheHit: ratio(p.Cached, p.Cached+p.Upstream.N+p.Failed), Failed: p.Failed,
	}
}

// Thresholds for anomalies. Buckets with fewer queries than these are too
// small to judge.
const (
	minLookups   = 10  // upstream answers, for "slow lookups"
	minFailures  = 5   // failed queries, for "lookups failing"
	minUpFails   = 3   // failed exchanges, for an upstream server
	minCacheBase = 100 // queries needing an answer, for "cache hit rate"
	minSurge     = 500 // queries per hour, for "query surge"
)

// stats is a median and a robust spread (scaled MAD) of some values.
type stats struct{ med, spread float64 }

func robust(v []float64) (stats, bool) {
	if len(v) < 6 {
		return stats{}, false
	}
	v = slices.Clone(v)
	sort.Float64s(v)
	med := v[len(v)/2]
	dev := make([]float64, len(v))
	for i, x := range v {
		dev[i] = math.Abs(x - med)
	}
	sort.Float64s(dev)
	return stats{med, 1.4826 * dev[len(dev)/2]}, true
}

func fmtMs(ms float64) string {
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.1f s", ms/1000)
	case ms >= 10:
		return fmt.Sprintf("%.0f ms", ms)
	case ms >= 1:
		return fmt.Sprintf("%.1f ms", ms)
	}
	return fmt.Sprintf("%.2f ms", ms)
}

func pct(f float64) string {
	if f > 0 && f < 0.001 {
		return "<0.1%"
	}
	return fmt.Sprintf("%.1f%%", 100*f)
}

// Report turns a merged perf answer into the page's data. step is the
// series bucket size in seconds, hours the length of the period.
func Report(p *Perf, step int64, hours float64) *PerfView {
	if p == nil {
		p = &Perf{}
	}
	v := &PerfView{Summary: summarize(p.Series, hours), Series: []PerfRow{}, Dist: []DistRow{}, Types: []TypeRow{}, Upstreams: []UpstreamRow{}, Anomalies: []Anomaly{}}
	var all, up Hist
	for i := range p.Series {
		v.Series = append(v.Series, row(&p.Series[i]))
		all.merge(&p.Series[i].All.Hist)
		up.merge(&p.Series[i].Upstream.Hist)
	}
	for i := range all {
		le := 0.0
		if i < len(bounds) {
			le = bounds[i]
		}
		v.Dist = append(v.Dist, DistRow{Le: le, All: all[i], Lookups: up[i]})
	}
	for t, st := range p.Types {
		v.Types = append(v.Types, TypeRow{Type: t, Queries: st.N, Avg: st.Avg(), P95: st.Q(.95)})
	}
	slices.SortFunc(v.Types, func(a, b TypeRow) int {
		if a.Queries != b.Queries {
			if a.Queries > b.Queries {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Type, b.Type)
	})
	for _, u := range p.Upstreams {
		r := UpstreamRow{
			Node: u.Node, Server: u.Server, Tries: u.Total.Tries, Answered: u.Total.Stat.N,
			Errors: u.Total.Errors, Timeouts: u.Total.Timeouts, Servfail: u.Total.Servfail,
			Avg: u.Total.Stat.Avg(), P50: u.Total.Stat.Q(.5), P95: u.Total.Stat.Q(.95), Max: u.Total.Stat.Max,
			FailRate: ratio(u.Total.Errors+u.Total.Timeouts, u.Total.Tries), Series: []UpRow{},
		}
		if u.Usual.Stat.N > 0 {
			r.UsualAvg, r.UsualP95 = u.Usual.Stat.Avg(), u.Usual.Stat.Q(.95)
		}
		for i := range u.Points {
			pt := &u.Points[i]
			r.Series = append(r.Series, UpRow{T: pt.T, Tries: pt.Tries, Failed: pt.Errors + pt.Timeouts, Avg: pt.Stat.Avg(), P95: pt.Stat.Q(.95)})
		}
		v.Upstreams = append(v.Upstreams, r)
	}

	// What is usual: the baseline period before this one when there is
	// enough of it, otherwise the typical bucket of this period.
	base, baseStep := p.Baseline, int64(3600)
	v.UsualFrom = "before"
	if countBusy(base) < 12 {
		base, baseStep = p.Series, step
		v.UsualFrom = "period"
	}
	if countBusy(base) >= 6 {
		u := summarize(base, float64(len(base))*float64(baseStep)/3600)
		v.Usual = &u
	} else {
		v.UsualFrom = ""
	}
	v.Anomalies = anomalies(p, base, step, baseStep)
	return v
}

// countBusy counts buckets with enough queries to compare against.
func countBusy(pts []PerfPoint) int {
	n := 0
	for i := range pts {
		if pts[i].All.N >= 20 {
			n++
		}
	}
	return n
}

func anomalies(p *Perf, base []PerfPoint, step, baseStep int64) []Anomaly {
	var lookP95, failRate, perHour, cacheHit []float64
	for i := range base {
		b := &base[i]
		if b.All.N < 20 {
			continue
		}
		if b.Upstream.N >= minLookups {
			lookP95 = append(lookP95, b.Upstream.Q(.95))
		}
		failRate = append(failRate, ratio(b.Failed, b.All.N))
		perHour = append(perHour, float64(b.All.N)*3600/float64(baseStep))
		if n := b.Cached + b.Upstream.N + b.Failed; n >= minCacheBase {
			cacheHit = append(cacheHit, ratio(b.Cached, n))
		}
	}
	var out []Anomaly
	add := func(a Anomaly) {
		// Join with the same kind of anomaly in the bucket before.
		for i := len(out) - 1; i >= 0; i-- {
			o := &out[i]
			if o.Kind == a.Kind && o.Node == a.Node && o.Server == a.Server && o.End+step == a.T {
				o.End = a.T
				if a.Severity == "bad" {
					o.Severity = "bad"
				}
				o.Detail = a.Detail // the latest bucket's numbers
				return
			}
		}
		out = append(out, a)
	}
	ls, haveLook := robust(lookP95)
	fs, haveFail := robust(failRate)
	hs, haveRate := robust(perHour)
	cs, haveCache := robust(cacheHit)
	for i := range p.Series {
		pt := &p.Series[i]
		if pt.Upstream.N >= minLookups {
			p95 := pt.Upstream.Q(.95)
			usual := 0.0
			if haveLook {
				usual = ls.med
			}
			limit := math.Max(math.Max(2*usual, usual+4*ls.spread), usual+25)
			if !haveLook {
				limit = 250 // no history yet: only flag clearly slow lookups
			}
			if p95 > limit {
				sev := "warn"
				if p95 > math.Max(4*usual, usual+100) && (haveLook || p95 > 1000) {
					sev = "bad"
				}
				d := fmt.Sprintf("95%% of lookups the cache couldn't answer took up to %s", fmtMs(p95))
				if haveLook {
					d += fmt.Sprintf(" (usually %s)", fmtMs(usual))
				}
				add(Anomaly{T: pt.T, End: pt.T, Kind: "slow", Severity: sev, Title: "Slow lookups", Detail: d + "."})
			}
		}
		if pt.Failed >= minFailures && pt.All.N > 0 {
			rate := ratio(pt.Failed, pt.All.N)
			usual := 0.0
			if haveFail {
				usual = fs.med
			}
			if rate > math.Max(0.01, 3*usual+0.005) {
				sev := "warn"
				if rate > math.Max(0.1, 5*usual) {
					sev = "bad"
				}
				d := fmt.Sprintf("%d queries got SERVFAIL (%s of queries", pt.Failed, pct(rate))
				if haveFail {
					d += ", usually " + pct(usual)
				}
				add(Anomaly{T: pt.T, End: pt.T, Kind: "failures", Severity: sev, Title: "Lookups failing", Detail: d + ")."})
			}
		}
		if haveRate && step <= 3600 {
			rate := float64(pt.All.N) * 3600 / float64(step)
			if rate >= minSurge && rate > math.Max(4*hs.med, hs.med+6*hs.spread) {
				add(Anomaly{T: pt.T, End: pt.T, Kind: "surge", Severity: "warn", Title: "Query surge",
					Detail: fmt.Sprintf("%.0f queries an hour (usually about %.0f). A device may be stuck retrying, or something new is very chatty.", rate, hs.med)})
			}
		}
		if haveCache {
			if n := pt.Cached + pt.Upstream.N + pt.Failed; n >= minCacheBase {
				hit := ratio(pt.Cached, n)
				if hit < cs.med-math.Max(0.25, 4*cs.spread) {
					add(Anomaly{T: pt.T, End: pt.T, Kind: "cache", Severity: "warn", Title: "Fewer cache hits",
						Detail: fmt.Sprintf("%s of queries came from the cache (usually %s). This is normal just after a restart or a cache flush.", pct(hit), pct(cs.med))})
				}
			}
		}
	}
	for _, u := range p.Upstreams {
		usualAvg := u.Usual.Stat.Avg()
		for i := range u.Points {
			pt := &u.Points[i]
			if f := pt.Errors + pt.Timeouts; f >= minUpFails && ratio(f, pt.Tries) >= 0.05 {
				sev := "warn"
				if ratio(f, pt.Tries) >= 0.25 {
					sev = "bad"
				}
				var parts []string
				if pt.Timeouts > 0 {
					parts = append(parts, plural(pt.Timeouts, "timeout"))
				}
				if pt.Errors > 0 {
					parts = append(parts, plural(pt.Errors, "error"))
				}
				add(Anomaly{T: pt.T, End: pt.T, Kind: "upstream-fail", Severity: sev, Node: u.Node, Server: u.Server, Title: "Upstream server failing",
					Detail: fmt.Sprintf("%s in %s (%s). DNServ moves on to the next server when there is one.", strings.Join(parts, " and "), plural(pt.Tries, "try"), pct(ratio(f, pt.Tries)))})
			}
			if usualAvg > 0 && pt.Stat.N >= minLookups && u.Usual.Stat.N >= 50 {
				if avg := pt.Stat.Avg(); avg > math.Max(3*usualAvg, usualAvg+50) {
					add(Anomaly{T: pt.T, End: pt.T, Kind: "upstream-slow", Severity: "warn", Node: u.Node, Server: u.Server, Title: "Upstream server slow",
						Detail: fmt.Sprintf("Answered in %s on average (usually %s).", fmtMs(avg), fmtMs(usualAvg))})
				}
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Anomaly) int {
		if a.End != b.End {
			if a.End > b.End {
				return -1
			}
			return 1
		}
		return 0
	})
	if out == nil {
		out = []Anomaly{}
	}
	return out
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if strings.HasSuffix(word, "y") {
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}
