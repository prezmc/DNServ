// Package querylog keeps the most recent DNS queries in memory, plus a
// running summary per client, for the dashboard's recent-queries view
// and device list. Long-term history (SQLite) comes with analytics.
package querylog

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Result values.
const (
	Answered = "answered" // from upstream
	Cached   = "cached"
	Stale    = "stale"
	Blocked  = "blocked"
	Local    = "local"
	Failed   = "failed"
)

// Entry is one query.
type Entry struct {
	ID       uint64     `json:"id"`
	Time     time.Time  `json:"time"`
	Client   netip.Addr `json:"client"`
	Name     string     `json:"name"`
	Type     string     `json:"type"`
	Result   string     `json:"result"`
	Rcode    string     `json:"rcode"`
	Answers  int        `json:"answers"`
	Rule     string     `json:"rule,omitempty"` // matching rule for blocked or allowed names
	List     string     `json:"list,omitempty"` // where the rule came from
	Allowed  bool       `json:"allowed,omitempty"`
	Duration float64    `json:"ms"`
}

// Client summarizes one device's recent activity.
type Client struct {
	Addr      netip.Addr `json:"addr"`
	Queries   int64      `json:"queries"`
	Blocked   int64      `json:"blocked"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// maxClients bounds the per-client table (allowed_nets already limits
// who can query).
const maxClients = 4096

// Log is a fixed-size ring of recent queries. It is safe for concurrent
// use; Add is cheap enough for the query path.
type Log struct {
	mu      sync.Mutex
	buf     []Entry
	n       int    // entries stored (<= len(buf))
	next    uint64 // id of the next entry
	clients map[netip.Addr]*Client
}

// New keeps the last size queries.
func New(size int) *Log {
	return &Log{buf: make([]Entry, max(size, 1)), next: 1, clients: map[netip.Addr]*Client{}}
}

// Add records a query.
func (l *Log) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.ID = l.next
	l.buf[int(l.next%uint64(len(l.buf)))] = e
	l.next++
	l.n = min(l.n+1, len(l.buf))

	c, ok := l.clients[e.Client]
	if !ok {
		if len(l.clients) >= maxClients {
			l.evictOldest()
		}
		c = &Client{Addr: e.Client, FirstSeen: e.Time}
		l.clients[e.Client] = c
	}
	c.Queries++
	if e.Result == Blocked {
		c.Blocked++
	}
	c.LastSeen = e.Time
}

func (l *Log) evictOldest() {
	var oldest *Client
	for _, c := range l.clients {
		if oldest == nil || c.LastSeen.Before(oldest.LastSeen) {
			oldest = c
		}
	}
	if oldest != nil {
		delete(l.clients, oldest.Addr)
	}
}

// Filter selects entries. Zero values match everything.
type Filter struct {
	Clients []netip.Addr // any of these
	Search  string       // substring of the name
	Result  string       // a Result value, or "allowed" for names an allow rule let through
	Before  uint64       // only entries with a smaller id (for paging)
	Limit   int          // default 100, at most 1000
}

// Query returns matching entries, newest first.
func (l *Log) Query(f Filter) []Entry {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	f.Limit = min(f.Limit, 1000)
	f.Search = strings.ToLower(strings.TrimSpace(f.Search))
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []Entry{}
	for i := 0; i < l.n && len(out) < f.Limit; i++ {
		id := l.next - 1 - uint64(i)
		e := l.buf[int(id%uint64(len(l.buf)))]
		if f.Before != 0 && e.ID >= f.Before {
			continue
		}
		if len(f.Clients) > 0 && !slices.Contains(f.Clients, e.Client) {
			continue
		}
		if f.Search != "" && !strings.Contains(e.Name, f.Search) {
			continue
		}
		if f.Result == "allowed" {
			if !e.Allowed {
				continue
			}
		} else if f.Result != "" && e.Result != f.Result {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Clients returns every client seen, most recently active first.
func (l *Log) Clients() []Client {
	l.mu.Lock()
	out := make([]Client, 0, len(l.clients))
	for _, c := range l.clients {
		out = append(out, *c)
	}
	l.mu.Unlock()
	slices.SortFunc(out, func(a, b Client) int { return b.LastSeen.Compare(a.LastSeen) })
	return out
}

// Len is the number of entries held.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

// Cap is how many entries the log keeps.
func (l *Log) Cap() int { return len(l.buf) }
