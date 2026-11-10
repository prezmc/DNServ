package server

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// latency buckets in seconds, for a Prometheus histogram.
var buckets = [...]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}

// Metrics are cumulative counters exported in Prometheus text format.
type Metrics struct {
	outcomes       [OutError + 1]atomic.Int64
	refused        atomic.Int64
	rateLimited    atomic.Int64
	upstreamErrors atomic.Int64

	rcodes [24]atomic.Int64 // rcodes 0-23 fit in the base header + EDNS

	// histogram per outcome
	hist [OutError + 1]histogram
}

type histogram struct {
	counts [len(buckets) + 1]atomic.Int64
	sumNS  atomic.Int64
}

// NewMetrics creates an empty set.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) observe(o Outcome, resp *dns.Msg, d time.Duration) {
	m.outcomes[o].Add(1)
	h := &m.hist[o]
	sec := d.Seconds()
	i := sort.SearchFloat64s(buckets[:], sec)
	h.counts[i].Add(1)
	h.sumNS.Add(int64(d))
	if resp != nil && resp.Rcode >= 0 && resp.Rcode < len(m.rcodes) {
		m.rcodes[resp.Rcode].Add(1)
	}
}

var outcomeNames = [...]string{"upstream", "cached", "stale", "blocked", "local", "error"}

// Counts returns queries per outcome name.
func (m *Metrics) Counts() map[string]int64 {
	out := map[string]int64{}
	for i, n := range outcomeNames {
		out[n] = m.outcomes[i].Load()
	}
	out["refused_acl"] = m.refused.Load()
	out["rate_limited"] = m.rateLimited.Load()
	return out
}

// WritePrometheus writes the server metrics.
func (m *Metrics) WritePrometheus(w io.Writer) {
	fmt.Fprintln(w, "# HELP dnserv_queries_total DNS queries answered, by outcome.")
	fmt.Fprintln(w, "# TYPE dnserv_queries_total counter")
	for i, n := range outcomeNames {
		fmt.Fprintf(w, "dnserv_queries_total{outcome=%q} %d\n", n, m.outcomes[i].Load())
	}
	fmt.Fprintln(w, "# HELP dnserv_refused_total Queries refused because the client is not in allowed_nets.")
	fmt.Fprintln(w, "# TYPE dnserv_refused_total counter")
	fmt.Fprintf(w, "dnserv_refused_total %d\n", m.refused.Load())
	fmt.Fprintln(w, "# HELP dnserv_rate_limited_total Queries dropped by the per-client rate limit.")
	fmt.Fprintln(w, "# TYPE dnserv_rate_limited_total counter")
	fmt.Fprintf(w, "dnserv_rate_limited_total %d\n", m.rateLimited.Load())
	fmt.Fprintln(w, "# HELP dnserv_upstream_errors_total Upstream exchanges that failed on every server.")
	fmt.Fprintln(w, "# TYPE dnserv_upstream_errors_total counter")
	fmt.Fprintf(w, "dnserv_upstream_errors_total %d\n", m.upstreamErrors.Load())

	fmt.Fprintln(w, "# HELP dnserv_responses_total Responses by rcode.")
	fmt.Fprintln(w, "# TYPE dnserv_responses_total counter")
	for c := range m.rcodes {
		if n := m.rcodes[c].Load(); n > 0 {
			fmt.Fprintf(w, "dnserv_responses_total{rcode=%q} %d\n", dns.RcodeToString[c], n)
		}
	}

	fmt.Fprintln(w, "# HELP dnserv_query_duration_seconds Time to answer a query, by outcome.")
	fmt.Fprintln(w, "# TYPE dnserv_query_duration_seconds histogram")
	for i, n := range outcomeNames {
		h := &m.hist[i]
		var cum int64
		for b, le := range buckets {
			cum += h.counts[b].Load()
			fmt.Fprintf(w, "dnserv_query_duration_seconds_bucket{outcome=%q,le=\"%g\"} %d\n", n, le, cum)
		}
		cum += h.counts[len(buckets)].Load()
		fmt.Fprintf(w, "dnserv_query_duration_seconds_bucket{outcome=%q,le=\"+Inf\"} %d\n", n, cum)
		fmt.Fprintf(w, "dnserv_query_duration_seconds_sum{outcome=%q} %g\n", n, float64(h.sumNS.Load())/1e9)
		fmt.Fprintf(w, "dnserv_query_duration_seconds_count{outcome=%q} %d\n", n, cum)
	}
}

// rateLimiter is a per-client token bucket, refilled at qps per second with
// a burst of 2*qps.
type rateLimiter struct {
	qps     float64
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	sweep   time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(qps int) *rateLimiter {
	return &rateLimiter{qps: float64(qps), buckets: map[netip.Addr]*bucket{}}
}

func (r *rateLimiter) allow(a netip.Addr, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.sweep) > time.Minute {
		for k, b := range r.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(r.buckets, k)
			}
		}
		r.sweep = now
	}
	b, ok := r.buckets[a]
	if !ok {
		b = &bucket{tokens: 2 * r.qps, last: now}
		r.buckets[a] = b
	}
	b.tokens = min(2*r.qps, b.tokens+now.Sub(b.last).Seconds()*r.qps)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
