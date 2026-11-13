package analytics

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Why lookups weren't answered from the cache. Each lookup that went
// upstream (or failed) is put down to one reason, by looking at the same
// name and record type's earlier lookups on this server:
const (
	MissFirst   = "first"   // the first lookup of it in the period
	MissShort   = "short"   // the last answer's cache time was under a minute and had run out
	MissExpired = "expired" // the last answer's cache time (a minute or more) had run out
	MissEarly   = "early"   // asked again while the last answer should still have been cached
	MissFailed  = "failed"  // the lookup failed; failures aren't cached
	MissUnknown = "unknown" // no cache time recorded (older history, or no answer records)
)

// shortTTL is where a cache time counts as very short.
const shortTTL = 60

// Miss counts cache misses: for one reason (Name "") or one domain and
// reason.
type Miss struct {
	Reason string `json:"reason"`
	Name   string `json:"name,omitempty"`
	N      int64  `json:"n"`
	TTL    int64  `json:"ttl,omitempty"` // the shortest cache time seen, seconds
}

// maxMissNames is how many domains a node reports for each reason.
const maxMissNames = 25

// cacheMiss works out why lookups missed the cache, from this node's
// individual queries.
func (s *Store) cacheMiss(ctx context.Context, q *Query, res *Result) error {
	if days, _ := s.Retention(); days == 0 {
		return nil
	}
	args := []any{q.From.UnixMicro(), q.To.UnixMicro(), codeAnswered, codeCached, codeStale, codeFailed}
	w := ` WHERE t >= ? AND t < ? AND result IN (?, ?, ?, ?)`
	if len(q.Clients) > 0 {
		w += ` AND client IN (` + placeholders(len(q.Clients)) + `)`
		for _, c := range q.Clients {
			args = append(args, c)
		}
	}
	type key struct{ reason, name string }
	byName := map[key]*Miss{}
	totals := map[string]int64{}
	var hits int64
	var (
		curName, curType string
		fillUntil        int64 // unix micro until which the last answer should be cached
		lastTTL          int64 = -1
		lastFailed       bool
		seen             bool
	)
	add := func(reason, name string, ttl int64) {
		totals[reason]++
		k := key{reason, name}
		m := byName[k]
		if m == nil {
			m = &Miss{Reason: reason, Name: name, TTL: -1}
			byName[k] = m
		}
		m.N++
		if ttl >= 0 && (m.TTL < 0 || ttl < m.TTL) {
			m.TTL = ttl
		}
	}
	err := collect(ctx, s.db, `SELECT name, qtype, t, result, COALESCE(ttl, -1) FROM queries`+w+` ORDER BY name, qtype, t`, args, func(r *sql.Rows) error {
		var name, qtype string
		var t, ttl int64
		var result int
		if err := r.Scan(&name, &qtype, &t, &result, &ttl); err != nil {
			return err
		}
		if name != curName || qtype != curType {
			curName, curType, fillUntil, lastTTL, lastFailed, seen = name, qtype, 0, -1, false, false
		}
		switch result {
		case codeCached, codeStale:
			hits++
		case codeFailed:
			add(MissFailed, name, -1)
			lastFailed = true
		default: // went upstream
			switch {
			case !seen:
				add(MissFirst, name, ttl)
			case lastFailed:
				add(MissFailed, name, lastTTL)
			case lastTTL < 0:
				add(MissUnknown, name, -1)
			case t < fillUntil:
				add(MissEarly, name, lastTTL)
			case lastTTL < shortTTL:
				add(MissShort, name, lastTTL)
			default:
				add(MissExpired, name, lastTTL)
			}
			lastFailed = false
			if ttl >= 0 {
				lastTTL, fillUntil = ttl, t+ttl*int64(time.Second/time.Microsecond)
			} else {
				lastTTL, fillUntil = -1, 0
			}
		}
		seen = true
		return nil
	})
	if err != nil {
		return err
	}
	res.Counts = &Counts{Cached: hits}
	for reason, n := range totals {
		res.Misses = append(res.Misses, Miss{Reason: reason, N: n})
	}
	// The domains behind each reason, most misses first.
	per := map[string][]*Miss{}
	for _, m := range byName {
		per[m.Reason] = append(per[m.Reason], m)
	}
	for _, list := range per {
		slices.SortFunc(list, func(a, b *Miss) int {
			if a.N != b.N {
				return int(b.N - a.N)
			}
			return strings.Compare(a.Name, b.Name)
		})
		for _, m := range list[:min(len(list), maxMissNames)] {
			mm := *m
			if mm.TTL < 0 {
				mm.TTL = 0
			}
			res.Misses = append(res.Misses, mm)
		}
	}
	return nil
}

// mergeMisses adds up misses from several nodes.
func mergeMisses(parts []*Result) []Miss {
	type key struct{ reason, name string }
	all := map[key]*Miss{}
	for _, p := range parts {
		if p == nil {
			continue
		}
		for _, m := range p.Misses {
			k := key{m.Reason, m.Name}
			if cur := all[k]; cur != nil {
				cur.N += m.N
				if m.TTL > 0 && (cur.TTL == 0 || m.TTL < cur.TTL) {
					cur.TTL = m.TTL
				}
			} else {
				c := m
				all[k] = &c
			}
		}
	}
	out := make([]Miss, 0, len(all))
	for _, m := range all {
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b Miss) int {
		if a.N != b.N {
			return int(b.N - a.N)
		}
		if c := strings.Compare(a.Reason, b.Reason); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// answerTTL is the shortest cache time in an answer, or nil when it has
// no records.
func answerTTL(rrs []dns.RR) any {
	ttl := int64(-1)
	for _, rr := range rrs {
		if t := int64(rr.Header().Ttl); ttl < 0 || t < ttl {
			ttl = t
		}
	}
	if ttl < 0 {
		return nil
	}
	return ttl
}
