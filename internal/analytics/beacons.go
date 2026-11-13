package analytics

import (
	"context"
	"database/sql"
	"slices"
	"strings"
)

// Repeating lookups: a device asking for the same name on a steady beat
// (every 30 seconds, every 5 minutes), which is how analytics, telemetry
// and tracking code usually behaves. Found from the individual queries,
// one device and name at a time.

// Beacon is one device looking a name up on a steady beat.
type Beacon struct {
	Name    string  `json:"name"`
	Client  string  `json:"client"`
	N       int64   `json:"n"`       // lookups in the period
	Period  int64   `json:"period"`  // typical seconds between them
	Regular float64 `json:"regular"` // share of gaps close to the period, 0-1
	Blocked int64   `json:"blocked"`
}

const (
	beaconMinLookups = 12       // fewer than this can't show a pattern
	beaconMinPeriod  = 5        // seconds; faster is a burst, not a beat
	beaconMaxGap     = 6 * 3600 // seconds; longer gaps are breaks, not beats
	beaconRegular    = 0.6      // at least this share of gaps near the period
	maxBeacons       = 500      // per node
)

// beacons finds repeating lookups in this node's individual queries.
func (s *Store) beacons(ctx context.Context, q *Query, res *Result) error {
	if days, _ := s.Retention(); days == 0 {
		return nil
	}
	args := []any{q.From.UnixMicro(), q.To.UnixMicro()}
	w := ` WHERE t >= ? AND t < ?`
	if len(q.Clients) > 0 {
		w += ` AND client IN (` + placeholders(len(q.Clients)) + `)`
		for _, c := range q.Clients {
			args = append(args, c)
		}
	}
	var (
		curClient, curName string
		times              []int64
		blocked            int64
		out                []Beacon
	)
	flush := func() {
		if b, ok := beat(times); ok {
			b.Name, b.Client, b.Blocked = curName, curClient, blocked
			out = append(out, b)
		}
		times, blocked = times[:0], 0
	}
	err := collect(ctx, s.db, `SELECT client, name, t / 1000000, result FROM queries`+w+` ORDER BY client, name, t`, args, func(r *sql.Rows) error {
		var client, name string
		var t int64
		var result int
		if err := r.Scan(&client, &name, &t, &result); err != nil {
			return err
		}
		if client != curClient || name != curName {
			flush()
			curClient, curName = client, name
		}
		// Retries within the same second are one lookup.
		if n := len(times); n == 0 || t-times[n-1] >= 1 {
			times = append(times, t)
		}
		if result == codeBlocked {
			blocked++
		}
		return nil
	})
	if err != nil {
		return err
	}
	flush()
	slices.SortFunc(out, func(a, b Beacon) int {
		if a.N != b.N {
			return int(b.N - a.N)
		}
		return strings.Compare(a.Name+a.Client, b.Name+b.Client)
	})
	res.Beacons = out[:min(len(out), maxBeacons)]
	return nil
}

// beat says whether lookup times (unix seconds, ascending) come on a
// steady beat, and what it is.
func beat(times []int64) (Beacon, bool) {
	if len(times) < beaconMinLookups {
		return Beacon{}, false
	}
	gaps := make([]int64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		if g := times[i] - times[i-1]; g <= beaconMaxGap {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) < beaconMinLookups-1 {
		return Beacon{}, false
	}
	sorted := slices.Clone(gaps)
	slices.Sort(sorted)
	period := sorted[len(sorted)/2]
	if period < beaconMinPeriod {
		return Beacon{}, false
	}
	// A gap counts when it is within a quarter of the period (at least
	// 2 seconds either way, for short beats).
	tol := max(period/4, 2)
	near := 0
	for _, g := range gaps {
		if g >= period-tol && g <= period+tol {
			near++
		}
	}
	regular := float64(near) / float64(len(gaps))
	if regular < beaconRegular {
		return Beacon{}, false
	}
	return Beacon{N: int64(len(times)), Period: period, Regular: regular}, true
}

// mergeBeacons combines nodes' findings: a device that used both servers
// is listed once, with the beat seen on the server it used most.
func mergeBeacons(parts []*Result) []Beacon {
	type key struct{ name, client string }
	all := map[key]*Beacon{}
	for _, p := range parts {
		if p == nil {
			continue
		}
		for _, b := range p.Beacons {
			k := key{b.Name, b.Client}
			cur := all[k]
			if cur == nil {
				c := b
				all[k] = &c
				continue
			}
			if b.N > cur.N {
				cur.Period, cur.Regular = b.Period, b.Regular
			}
			cur.N += b.N
			cur.Blocked += b.Blocked
		}
	}
	out := make([]Beacon, 0, len(all))
	for _, b := range all {
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b Beacon) int {
		if a.N != b.N {
			return int(b.N - a.N)
		}
		return strings.Compare(a.Name+a.Client, b.Name+b.Client)
	})
	return out
}
