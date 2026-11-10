// Package upstream sends queries the node can't answer itself to upstream
// resolvers over DNS over HTTPS, DNS over TLS, or plain UDP/TCP.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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

// Group tries upstreams fastest-first and fails over on error.
type Group struct {
	members []*member
	log     *slog.Logger
	obs     atomic.Pointer[Observer]
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
	// ewma latency in microseconds; failures add a penalty.
	ewma     atomic.Int64
	failures atomic.Int64
	queries  atomic.Int64
}

// NewGroup creates a group from upstream URLs.
func NewGroup(urls []string, bootstrap []string, timeout time.Duration, log *slog.Logger) (*Group, error) {
	boot := NewBootstrap(bootstrap, timeout)
	g := &Group{log: log}
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

const failurePenalty = int64(2 * time.Second / time.Microsecond)

// Exchange sends q to the fastest healthy upstream, then the others in
// order of measured latency until one answers.
func (g *Group) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	order := g.order()
	var errs []error
	for _, m := range order {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		resp, err := m.ex.Exchange(ctx, q)
		took := time.Since(start)
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
			m.observe(failurePenalty)
			errs = append(errs, fmt.Errorf("%s: %w", m.ex, err))
			continue
		}
		m.observe(int64(took / time.Microsecond))
		return resp, nil
	}
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	return nil, errors.Join(errs...)
}

func (m *member) observe(us int64) {
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

func (g *Group) order() []*member {
	out := make([]*member, len(g.members))
	copy(out, g.members)
	if len(out) > 1 {
		sort.SliceStable(out, func(i, j int) bool { return out[i].ewma.Load() < out[j].ewma.Load() })
	}
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
