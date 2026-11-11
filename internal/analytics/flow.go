package analytics

import (
	"cmp"
	"context"
	"database/sql"
	"slices"
	"strings"
)

// Traffic map paths: how a lookup was answered. Answers from upstream are
// "up:" followed by the server that answered ("up:" alone for answers
// recorded before servers were).
const (
	PathCache   = "cache" // including stale answers
	PathBlocked = "blocked"
	PathLocal   = "local"
	PathFailed  = "failed"
	PathUp      = "up:"
)

// Limits on what one node sends for the traffic map; the rest is summed.
const (
	flowClients = 300
	flowNames   = 1500 // per path
)

// Flow is one node's traffic map: which devices asked, how lookups were
// answered and which domains they were for.
type Flow struct {
	Node    string       `json:"node"`
	Clients []FlowClient `json:"clients"` // Key "" sums the devices left out
	Paths   []FlowRow    `json:"paths"`
	Names   []FlowName   `json:"names"` // Name "" sums a path's domains left out
}

// Kinds of lookup on the traffic map.
const (
	FlowInternet = "internet" // answered from upstream or the cache
	FlowInternal = "internal" // local names and reverse lookups
	FlowBlocked  = "blocked"
)

// KindOf says which kind of lookup a stored result is.
func KindOf(code int) string {
	switch code {
	case codeBlocked:
		return FlowBlocked
	case codeLocal:
		return FlowInternal
	}
	return FlowInternet
}

// PathKind says which kind of lookup a path carries.
func PathKind(path string) string {
	switch path {
	case PathBlocked:
		return FlowBlocked
	case PathLocal:
		return FlowInternal
	}
	return FlowInternet
}

// FlowClient is how many lookups of one kind a device made.
type FlowClient struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
	N    int64  `json:"n"`
}

// FlowRow is a count for one key.
type FlowRow struct {
	Key string `json:"key"`
	N   int64  `json:"n"`
}

// FlowName is how often a domain was answered by one path.
type FlowName struct {
	Name string `json:"name"`
	Path string `json:"path"`
	N    int64  `json:"n"`
}

func (s *Store) flow(ctx context.Context, q *Query, res *Result) error {
	f := Flow{Node: s.node()}
	src, args, ok := s.source(q)
	if !ok {
		res.Flows = []Flow{f}
		return nil
	}
	raw := strings.Contains(src, "FROM queries")

	// Devices, split by the kind of lookup so the map can leave a kind out.
	type ck struct {
		client string
		kind   string
	}
	clients, perClient := map[string]int64{}, map[ck]int64{}
	if err := collect(ctx, s.db, `SELECT client, result, SUM(n) FROM `+src+` GROUP BY client, result`, args, func(r *sql.Rows) error {
		var c string
		var code int
		var n int64
		if err := r.Scan(&c, &code, &n); err != nil {
			return err
		}
		clients[c] += n
		perClient[ck{c, KindOf(code)}] += n
		return nil
	}); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, r := range topRows(clients, flowClients) {
		keep[r.Key] = r.Key != ""
	}
	rest := map[string]int64{}
	for k, n := range perClient {
		if keep[k.client] {
			f.Clients = append(f.Clients, FlowClient{Key: k.client, Kind: k.kind, N: n})
		} else {
			rest[k.kind] += n
		}
	}
	for kind, n := range rest {
		f.Clients = append(f.Clients, FlowClient{Kind: kind, N: n})
	}
	slices.SortFunc(f.Clients, func(a, b FlowClient) int {
		return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Key, b.Key), cmp.Compare(a.Kind, b.Kind))
	})

	byName := map[string]map[string]int64{} // path -> name -> n
	add := func(path, name string, n int64) {
		m := byName[path]
		if m == nil {
			m = map[string]int64{}
			byName[path] = m
		}
		m[name] += n
	}
	answered := map[string]int64{}
	if err := collect(ctx, s.db, `SELECT name, result, SUM(n) FROM `+src+` GROUP BY name, result`, args, func(r *sql.Rows) error {
		var name string
		var code int
		var n int64
		if err := r.Scan(&name, &code, &n); err != nil {
			return err
		}
		switch code {
		case codeAnswered:
			answered[name] += n
		case codeCached, codeStale:
			add(PathCache, name, n)
		case codeBlocked:
			add(PathBlocked, name, n)
		case codeLocal:
			add(PathLocal, name, n)
		default:
			add(PathFailed, name, n)
		}
		return nil
	}); err != nil {
		return err
	}

	// Which server answered: from each query for short ranges, otherwise
	// from the hourly upstream totals.
	upQuery, upArgs := `SELECT name, upstream, SUM(n) FROM hourly_up WHERE hour >= ? AND hour < ? GROUP BY name, upstream`,
		[]any{q.From.Unix() / 3600, (q.To.Unix() + 3599) / 3600}
	if raw {
		upQuery, upArgs = `SELECT name, upstream, COUNT(*) FROM queries WHERE t >= ? AND t < ? AND result = ? AND upstream IS NOT NULL GROUP BY name, upstream`,
			[]any{q.From.UnixMicro(), q.To.UnixMicro(), codeAnswered}
	}
	if err := collect(ctx, s.db, upQuery, upArgs, func(r *sql.Rows) error {
		var name, up string
		var n int64
		if err := r.Scan(&name, &up, &n); err != nil {
			return err
		}
		n = min(n, answered[name])
		if n > 0 {
			answered[name] -= n
			add(PathUp+up, name, n)
		}
		return nil
	}); err != nil {
		return err
	}
	for name, n := range answered {
		if n > 0 {
			add(PathUp, name, n)
		}
	}

	paths := map[string]int64{}
	for path, names := range byName {
		for _, r := range topRows(names, flowNames) {
			f.Names = append(f.Names, FlowName{Name: r.Key, Path: path, N: r.N})
			paths[path] += r.N
		}
	}
	f.Paths = topRows(paths, 0)
	res.Flows = []Flow{f}
	return nil
}

// topRows sorts counts, largest first, and sums those after the first
// limit (0: no limit) into one row with an empty key.
func topRows(m map[string]int64, limit int) []FlowRow {
	out := make([]FlowRow, 0, len(m))
	for k, n := range m {
		out = append(out, FlowRow{k, n})
	}
	slices.SortFunc(out, func(a, b FlowRow) int {
		if c := cmp.Compare(b.N, a.N); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	if limit > 0 && len(out) > limit {
		var rest int64
		for _, r := range out[limit:] {
			rest += r.N
		}
		out = append(out[:limit], FlowRow{"", rest})
	}
	return out
}
