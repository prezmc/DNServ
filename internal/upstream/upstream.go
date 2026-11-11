// Package upstream sends queries the node can't answer itself to upstream
// resolvers over DNS over HTTPS, DNS over TLS, or plain UDP/TCP.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Exchanger resolves one query.
type Exchanger interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
	String() string
}

// New builds an exchanger for one upstream URL.
func New(raw string, boot *Bootstrap, timeout time.Duration) (Exchanger, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "https":
		return newDoH(u, boot, timeout), nil
	case "tls":
		return newDoT(u, boot, timeout), nil
	case "udp", "tcp":
		return newPlain(u, timeout), nil
	}
	return nil, fmt.Errorf("unsupported upstream scheme %q", u.Scheme)
}

// Strategy is how a Group picks which upstream to ask.
type Strategy string

const (
	// Fastest asks the server with the lowest measured answer time, and
	// the others in that order if it fails. The default.
	Fastest Strategy = "fastest"
	// InOrder asks the servers in the order they are listed: the first is
	// the main one, the rest are fallbacks.
	InOrder Strategy = "in_order"
	// RoundRobin takes turns, spreading queries evenly over the servers.
	RoundRobin Strategy = "round_robin"
	// Parallel asks every server at once and uses the first answer: the
	// quickest answers, for several times the upstream traffic.
	Parallel Strategy = "parallel"
)

// Strategies lists the valid strategies.
var Strategies = []Strategy{Fastest, InOrder, RoundRobin, Parallel}

// Group tries upstreams by its strategy and fails over on error. A server
// that fails is moved behind the healthy ones for a while.
type Group struct {
	members  []*member
	strategy Strategy
	next     atomic.Uint64 // round robin turn
	log      *slog.Logger
	obs      atomic.Pointer[Observer]
	label    string // names the group in place of the answering server
}

// SetLabel makes ExchangeFrom name the group as label rather than the
// server that answered (for the local Unbound, "Recursive (Unbound)").
// Call it before the group is used.
func (g *Group) SetLabel(label string) { g.label = label }

// SetStrategy sets how servers are picked. Call it before the group is
// used; an unknown or empty strategy means Fastest.
func (g *Group) SetStrategy(s Strategy) {
	if !slices.Contains(Strategies, s) {
		s = Fastest
	}
	g.strategy = s
}

// Observer is told about every exchange with an upstream server: which
// one, when it started, how long it took, the answer's rcode and the
// error, if any. It runs on the exchange's goroutine, so it must not block.
type Observer func(server string, start time.Time, d time.Duration, rcode int, err error)

// SetObserver sets (or with nil, clears) the group's observer.
func (g *Group) SetObserver(o Observer) {
	if o == nil {
		g.obs.Store(nil)
		return
	}
	g.obs.Store(&o)
}

type member struct {
	ex Exchanger
	// ewma is the answer time in microseconds (0 = not measured yet).
	ewma atomic.Int64
	// downUntil (unix nanoseconds) puts the member behind every healthy one
	// after a failure, for failBackoff or until a probe gets an answer.
	downUntil atomic.Int64
	// last (unix nanoseconds) is when the member was last sent a query,
	// for probing the ones that aren't first in line.
	last     atomic.Int64
	failures atomic.Int64
	queries  atomic.Int64
}

// NewGroup creates a group from upstream URLs.
func NewGroup(urls []string, bootstrap []string, timeout time.Duration, log *slog.Logger) (*Group, error) {
	boot := NewBootstrap(bootstrap, timeout)
	g := &Group{log: log, strategy: Fastest}
	for _, s := range urls {
		ex, err := New(s, boot, timeout)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", s, err)
		}
		m := &member{ex: ex}
		g.members = append(g.members, m)
	}
	if len(g.members) == 0 {
		return nil, errors.New("no upstream servers configured")
	}
	return g, nil
}

var (
	// failBackoff is how long a failed member waits behind the healthy
	// ones, unless a probe gets an answer from it sooner.
	failBackoff = 30 * time.Second
	// probeEvery is how often each member that isn't first in line is
	// sent a copy of a live query in the background, so its latency stays
	// current and a server that was slow or down once can win again.
	// Without it a member that fell behind would never be measured again.
	probeEvery = 10 * time.Second
)

// Exchange sends q to the fastest healthy upstream, then the others in
// order of measured latency until one answers.
func (g *Group) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	resp, _, err := g.ExchangeFrom(ctx, q)
	return resp, err
}

// ExchangeFrom is Exchange that also says which server answered.
func (g *Group) ExchangeFrom(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	order := g.order()
	if g.strategy == Parallel && len(order) > 1 {
		return g.parallel(ctx, order, q)
	}
	if g.strategy == Fastest && len(order) > 1 {
		g.probe(order[1:], q)
	}
	var errs []error
	for _, m := range order {
		if ctx.Err() != nil {
			break
		}
		resp, err := g.try(ctx, m, q)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.ex, err))
			continue
		}
		return resp, g.name(m), nil
	}
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	return nil, "", errors.Join(errs...)
}

// try sends q to one member and records how it went.
func (g *Group) try(ctx context.Context, m *member, q *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	m.last.Store(start.UnixNano())
	resp, err := m.ex.Exchange(ctx, q)
	took := time.Since(start)
	if err != nil && ctx.Err() != nil {
		// Given up on (the client left, or another server answered
		// first): says nothing about this server.
		return nil, err
	}
	m.queries.Add(1)
	if o := g.obs.Load(); o != nil {
		rcode := -1
		if resp != nil {
			rcode = resp.Rcode
		}
		(*o)(m.ex.String(), start, took, rcode, err)
	}
	if err != nil {
		m.failures.Add(1)
		m.downUntil.Store(time.Now().Add(failBackoff).UnixNano())
		return nil, err
	}
	m.downUntil.Store(0)
	m.observe(int64(took / time.Microsecond))
	return resp, nil
}

// probe sends a copy of q, in the background, to each of the given members
// that hasn't been asked anything for probeEvery. Members never asked yet
// are left out: they sort first until they are measured. The client's
// answer never waits for a probe.
func (g *Group) probe(ms []*member, q *dns.Msg) {
	now := time.Now().UnixNano()
	for _, m := range ms {
		last := m.last.Load()
		if last == 0 || now-last < int64(probeEvery) || !m.last.CompareAndSwap(last, now) {
			continue
		}
		go func(m *member, q *dns.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
			defer cancel()
			g.try(ctx, m, q)
		}(m, q.Copy())
	}
}

// probeTimeout bounds a background probe; the exchanger's own timeout
// normally ends it first.
const probeTimeout = 10 * time.Second

func (m *member) observe(us int64) {
	if us < 1 {
		us = 1 // 0 means "not measured yet"
	}
	for {
		old := m.ewma.Load()
		var next int64
		if old == 0 {
			next = us
		} else {
			next = old + (us-old)/5 // alpha = 0.2
		}
		if m.ewma.CompareAndSwap(old, next) {
			return
		}
	}
}

// parallel asks every healthy member at once (every member, if none is
// healthy) and returns the first answer.
func (g *Group) parallel(ctx context.Context, order []*member, q *dns.Msg) (*dns.Msg, string, error) {
	now := time.Now().UnixNano()
	ask := order[:0:0]
	for _, m := range order {
		if m.downUntil.Load() <= now {
			ask = append(ask, m)
		}
	}
	if len(ask) == 0 {
		ask = order
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		m    *member
		resp *dns.Msg
		err  error
	}
	results := make(chan result, len(ask))
	for _, m := range ask {
		go func(m *member, q *dns.Msg) {
			resp, err := g.try(ctx, m, q)
			results <- result{m, resp, err}
		}(m, q.Copy())
	}
	var errs []error
	for range ask {
		r := <-results
		if r.err == nil {
			return r.resp, g.name(r.m), nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.m.ex, r.err))
	}
	return nil, "", errors.Join(errs...)
}

func (g *Group) name(m *member) string {
	if g.label != "" {
		return g.label
	}
	return m.ex.String()
}

// order returns the members in the order to try them: healthy ones first,
// then by the group's strategy. For Fastest a member not measured yet
// counts as fastest, so each one is tried early on.
func (g *Group) order() []*member {
	out := make([]*member, len(g.members))
	copy(out, g.members)
	if len(out) < 2 {
		return out
	}
	if g.strategy == RoundRobin {
		k := int(g.next.Add(1)-1) % len(out)
		out = append(out[k:], out[:k]...)
	}
	now := time.Now().UnixNano()
	down := func(m *member) bool { return m.downUntil.Load() > now }
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := down(out[i]), down(out[j])
		if di != dj {
			return dj
		}
		if g.strategy == Fastest || g.strategy == "" {
			return out[i].ewma.Load() < out[j].ewma.Load()
		}
		return false // keep the listed (or rotated) order
	})
	return out
}

// Stat describes one upstream for health and metrics.
type Stat struct {
	Server    string  `json:"server"`
	LatencyMS float64 `json:"latency_ms"`
	Queries   int64   `json:"queries"`
	Failures  int64   `json:"failures"`
}

// Stats returns per-upstream counters.
func (g *Group) Stats() []Stat {
	out := make([]Stat, 0, len(g.members))
	for _, m := range g.members {
		out = append(out, Stat{
			Server:    m.ex.String(),
			LatencyMS: float64(m.ewma.Load()) / 1000,
			Queries:   m.queries.Load(),
			Failures:  m.failures.Load(),
		})
	}
	return out
}
