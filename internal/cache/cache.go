// Package cache is the node's in-memory DNS answer cache, with prefetch of
// popular entries, serve-stale (RFC 8767) and persistence across restarts.
package cache

import (
	"container/list"
	"encoding/gob"
	"errors"
	"hash/maphash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const shards = 64

// StaleTTL is the TTL given to answers served stale (RFC 8767 section 4).
const StaleTTL = 30

// State is the result of a lookup.
type State uint8

const (
	Miss State = iota
	Fresh
	Stale
)

// Options configure a cache.
type Options struct {
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
	ServeStale  time.Duration
	Prefetch    bool
}

// Cache is a sharded LRU keyed by question and DNSSEC flags.
type Cache struct {
	opt    Options
	seed   maphash.Seed
	shards [shards]shard
	now    func() time.Time

	hits, misses, stale, prefetches atomic.Int64
	// evicted counts answers pushed out to make room while still usable
	// (fresh, or within the serve-stale window): a sign the cache is too
	// small.
	evicted atomic.Int64
	// size is the number of answers asked for (the shards together may
	// hold a few fewer, from rounding).
	size atomic.Int64
}

type shard struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	max   int
}

type entry struct {
	key      string
	msg      *dns.Msg
	stored   time.Time
	ttl      time.Duration
	hits     uint32
	fetching bool
}

// New creates a cache.
func New(opt Options) *Cache {
	c := &Cache{opt: opt, seed: maphash.MakeSeed(), now: time.Now}
	per := max(opt.MaxEntries/shards, 1)
	for i := range c.shards {
		c.shards[i] = shard{items: map[string]*list.Element{}, lru: list.New(), max: per}
	}
	c.size.Store(int64(max(opt.MaxEntries, shards)))
	return c
}

// Key builds the cache key for a query.
func Key(q *dns.Msg) string {
	if len(q.Question) != 1 {
		return ""
	}
	qq := q.Question[0]
	var b strings.Builder
	b.Grow(len(qq.Name) + 8)
	b.WriteString(strings.ToLower(qq.Name))
	b.WriteByte(byte(qq.Qtype >> 8))
	b.WriteByte(byte(qq.Qtype))
	b.WriteByte(byte(qq.Qclass >> 8))
	b.WriteByte(byte(qq.Qclass))
	var flags byte
	if o := q.IsEdns0(); o != nil && o.Do() {
		flags |= 1
	}
	if q.CheckingDisabled {
		flags |= 2
	}
	b.WriteByte(flags)
	return b.String()
}

func (c *Cache) shard(key string) *shard {
	return &c.shards[maphash.String(c.seed, key)%shards]
}

// Result is what Get returns.
type Result struct {
	State State
	// Msg is a copy ready to send, with TTLs decremented. Nil on Miss.
	Msg *dns.Msg
	// Refresh is true when the caller should refresh this entry in the
	// background (prefetch for Fresh, revalidation for Stale). Only one
	// caller per entry is told to refresh at a time; it must call Done.
	Refresh bool
}

// Get looks up a key.
func (c *Cache) Get(key string) Result {
	if key == "" {
		return Result{}
	}
	s := c.shard(key)
	now := c.now()
	s.mu.Lock()
	el, ok := s.items[key]
	if !ok {
		s.mu.Unlock()
		c.misses.Add(1)
		return Result{}
	}
	e := el.Value.(*entry)
	age := now.Sub(e.stored)
	remaining := e.ttl - age
	var res Result
	switch {
	case remaining > 0:
		e.hits++
		s.lru.MoveToFront(el)
		res.State = Fresh
		res.Msg = withTTL(e.msg, uint32(remaining/time.Second), age)
		// Prefetch when under 10% of the TTL remains on a popular entry.
		if c.opt.Prefetch && !e.fetching && e.hits >= 2 && e.ttl >= 10*time.Second && remaining < e.ttl/10 {
			e.fetching = true
			res.Refresh = true
		}
	case c.opt.ServeStale > 0 && -remaining < c.opt.ServeStale:
		s.lru.MoveToFront(el)
		res.State = Stale
		res.Msg = withStaleTTL(e.msg)
		if !e.fetching {
			e.fetching = true
			res.Refresh = true
		}
	default:
		s.lru.Remove(el)
		delete(s.items, key)
	}
	s.mu.Unlock()

	switch res.State {
	case Fresh:
		c.hits.Add(1)
		if res.Refresh {
			c.prefetches.Add(1)
		}
	case Stale:
		c.stale.Add(1)
	default:
		c.misses.Add(1)
	}
	return res
}

// Done clears the in-flight refresh mark after a failed refresh, so a later
// lookup can try again. A successful refresh calls Set, which replaces the
// entry.
func (c *Cache) Done(key string) {
	s := c.shard(key)
	s.mu.Lock()
	if el, ok := s.items[key]; ok {
		el.Value.(*entry).fetching = false
	}
	s.mu.Unlock()
}

// Set stores a response. Responses that should not be cached (truncated,
// server failures, zero TTL) are ignored.
func (c *Cache) Set(key string, m *dns.Msg) {
	if key == "" || m == nil || m.Truncated {
		return
	}
	ttl, ok := c.ttlFor(m)
	if !ok {
		c.Done(key)
		return
	}
	c.set(key, m.Copy(), c.now(), ttl)
}

func (c *Cache) set(key string, m *dns.Msg, stored time.Time, ttl time.Duration) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		e := el.Value.(*entry)
		e.msg, e.stored, e.ttl, e.fetching = m, stored, ttl, false
		s.lru.MoveToFront(el)
		return
	}
	el := s.lru.PushFront(&entry{key: key, msg: m, stored: stored, ttl: ttl})
	s.items[key] = el
	for s.lru.Len() > s.max {
		last := s.lru.Back()
		s.lru.Remove(last)
		old := last.Value.(*entry)
		delete(s.items, old.key)
		if stored.Sub(old.stored) <= old.ttl+c.opt.ServeStale {
			c.evicted.Add(1)
		}
	}
}

// ttlFor picks the cache lifetime: the smallest TTL in the response,
// clamped; for negative answers, the SOA minimum capped by NegativeTTL.
func (c *Cache) ttlFor(m *dns.Msg) (time.Duration, bool) {
	switch m.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return 0, false
	}
	var (
		minTTL uint32 = ^uint32(0)
		found  bool
	)
	consider := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			found = true
			minTTL = min(minTTL, rr.Header().Ttl)
		}
	}
	negative := m.Rcode == dns.RcodeNameError || len(m.Answer) == 0
	if negative {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				found = true
				minTTL = min(soa.Hdr.Ttl, soa.Minttl)
			}
		}
		if !found {
			return 0, false
		}
		ttl := time.Duration(minTTL) * time.Second
		if c.opt.NegativeTTL > 0 {
			ttl = min(ttl, c.opt.NegativeTTL)
		}
		return ttl, ttl > 0
	}
	consider(m.Answer)
	consider(m.Ns)
	if !found {
		return 0, false
	}
	ttl := time.Duration(minTTL) * time.Second
	if ttl < c.opt.MinTTL {
		ttl = c.opt.MinTTL
	}
	if c.opt.MaxTTL > 0 && ttl > c.opt.MaxTTL {
		ttl = c.opt.MaxTTL
	}
	return ttl, ttl > 0
}

// withTTL copies m, rewriting record TTLs: each is reduced by age (records
// with longer TTLs than the cached lifetime keep their relative lifetime),
// capped at ttl.
func withTTL(m *dns.Msg, ttl uint32, age time.Duration) *dns.Msg {
	out := m.Copy()
	ageS := uint32(age / time.Second)
	fix := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			t := h.Ttl
			if t > ageS {
				t -= ageS
			} else {
				t = 0
			}
			h.Ttl = min(t, ttl)
		}
	}
	fix(out.Answer)
	fix(out.Ns)
	fix(out.Extra)
	return out
}

// withStaleTTL copies m with every record TTL set to StaleTTL.
func withStaleTTL(m *dns.Msg) *dns.Msg {
	out := m.Copy()
	for _, rrs := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range rrs {
			if h := rr.Header(); h.Rrtype != dns.TypeOPT {
				h.Ttl = StaleTTL
			}
		}
	}
	return out
}

// Flush drops every entry (after an upstream change, so answers from
// the old path aren't served).
func (c *Cache) Flush() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.items = map[string]*list.Element{}
		s.lru.Init()
		s.mu.Unlock()
	}
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += len(s.items)
		s.mu.Unlock()
	}
	return n
}

// Stats are cumulative counters.
type Stats struct {
	Entries    int   `json:"entries"`
	Hits       int64 `json:"hits"`
	Misses     int64 `json:"misses"`
	Stale      int64 `json:"stale"`
	Prefetches int64 `json:"prefetches"`
	Max        int   `json:"max"`     // how many answers it can hold
	Evicted    int64 `json:"evicted"` // still-usable answers pushed out for room
}

// Stats returns cumulative counters.
func (c *Cache) Stats() Stats {
	return Stats{Entries: c.Len(), Hits: c.hits.Load(), Misses: c.misses.Load(), Stale: c.stale.Load(), Prefetches: c.prefetches.Load(),
		Max: c.capacity(), Evicted: c.evicted.Load()}
}

func (c *Cache) capacity() int { return int(c.size.Load()) }

// Resize changes how many answers the cache can hold, dropping the least
// recently used ones if it now holds too many.
func (c *Cache) Resize(maxEntries int) {
	c.size.Store(int64(max(maxEntries, shards)))
	per := max(maxEntries/shards, 1)
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.max = per
		for s.lru.Len() > s.max {
			last := s.lru.Back()
			s.lru.Remove(last)
			delete(s.items, last.Value.(*entry).key)
		}
		s.mu.Unlock()
	}
}

// Fill says how full the cache is: entries held, and how many of them
// are still fresh or still usable when upstream is down (the rest have
// expired and wait to be replaced). It walks every entry, so it is for
// status pages, not the query path.
type Fill struct {
	Entries int   `json:"entries"`
	Fresh   int   `json:"fresh"`
	Usable  int   `json:"usable"` // fresh plus serve-stale
	Max     int   `json:"max"`
	Evicted int64 `json:"evicted"`
}

func (c *Cache) Fill() Fill {
	now := c.now()
	f := Fill{Max: c.capacity(), Evicted: c.evicted.Load()}
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for _, el := range s.items {
			e := el.Value.(*entry)
			age := now.Sub(e.stored)
			f.Entries++
			if age <= e.ttl {
				f.Fresh++
			}
			if age <= e.ttl+c.opt.ServeStale {
				f.Usable++
			}
		}
		s.mu.Unlock()
	}
	return f
}

// --- persistence ---

type persisted struct {
	Key    string
	Msg    []byte
	Stored time.Time
	TTL    time.Duration
}

const persistVersion = 1

// Save writes all entries still usable (fresh, or within the stale window)
// to path atomically.
func (c *Cache) Save(path string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "cache-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	enc := gob.NewEncoder(tmp)
	if err := enc.Encode(persistVersion); err != nil {
		tmp.Close()
		return 0, err
	}
	now := c.now()
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for el := s.lru.Back(); el != nil; el = el.Prev() { // oldest first, so reload keeps LRU order
			e := el.Value.(*entry)
			if now.Sub(e.stored) > e.ttl+c.opt.ServeStale {
				continue
			}
			b, err := e.msg.Pack()
			if err != nil {
				continue
			}
			if err := enc.Encode(persisted{Key: e.key, Msg: b, Stored: e.stored, TTL: e.ttl}); err != nil {
				s.mu.Unlock()
				tmp.Close()
				return n, err
			}
			n++
		}
		s.mu.Unlock()
	}
	if err := tmp.Close(); err != nil {
		return n, err
	}
	return n, os.Rename(tmp.Name(), path)
}

// Load restores entries saved by Save, dropping any no longer usable.
func (c *Cache) Load(path string) (int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	var ver int
	if err := dec.Decode(&ver); err != nil || ver != persistVersion {
		return 0, nil // unknown format: start cold
	}
	now := c.now()
	n := 0
	for {
		var p persisted
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		if now.Sub(p.Stored) > p.TTL+c.opt.ServeStale {
			continue
		}
		m := new(dns.Msg)
		if err := m.Unpack(p.Msg); err != nil {
			continue
		}
		c.set(p.Key, m, p.Stored, p.TTL)
		n++
	}
}
