package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Query kinds.
const (
	KindSummary = "summary" // totals and a time series
	KindTop     = "top"     // top domains, blocked domains or devices
	KindSearch  = "search"  // individual queries, newest first
	KindDomain  = "domain"  // one domain: totals, series, devices, caught by
	KindPerf    = "perf"    // response times, upstream health
)

// Top list kinds.
const (
	TopDomains = "domains"
	TopBlocked = "blocked"
	TopClients = "clients"
	TopLists   = "lists" // the lists (or custom rules) behind blocks
)

// Query asks one node about its history. It is sent as JSON to peers, so
// every node answers the same question.
type Query struct {
	Kind string    `json:"kind"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Step is the series bucket size in seconds (summary and domain).
	Step int64 `json:"step,omitempty"`
	// Offset is added to unix seconds before bucketing, so daily buckets
	// start at local midnight.
	Offset int64 `json:"offset,omitempty"`
	// By selects the top list: domains, blocked or clients.
	By string `json:"by,omitempty"`
	// Clients limits to these client addresses.
	Clients []string `json:"clients,omitempty"`
	// Name is the domain (domain) or search words (search).
	Name string `json:"name,omitempty"`
	// Result limits search to a result, or "allowed".
	Result string `json:"result,omitempty"`
	// Before pages search: only queries before this unix microsecond.
	Before int64 `json:"before,omitempty"`
	Limit  int   `json:"limit,omitempty"`
	// Flags adds (to top lists) every domain whose answers were flagged
	// in the period.
	Flags bool `json:"flags,omitempty"`
	// Baseline (perf) also returns hourly response times for this many
	// seconds before From, to judge what is usual.
	Baseline int64 `json:"baseline,omitempty"`
	// Devices (perf) adds each device's response times.
	Devices bool `json:"devices,omitempty"`
}

// Counts are query totals.
type Counts struct {
	Total   int64   `json:"total"`
	Blocked int64   `json:"blocked"`
	Cached  int64   `json:"cached"` // including stale
	Local   int64   `json:"local"`
	Failed  int64   `json:"failed"`
	MsSum   float64 `json:"ms_sum"` // for the average response time
}

func (c *Counts) add(result int, n int64, ms float64) {
	c.Total += n
	c.MsSum += ms
	switch result {
	case codeBlocked:
		c.Blocked += n
	case codeCached, codeStale:
		c.Cached += n
	case codeLocal:
		c.Local += n
	case codeFailed:
		c.Failed += n
	}
}

func (c *Counts) merge(o Counts) {
	c.Total += o.Total
	c.Blocked += o.Blocked
	c.Cached += o.Cached
	c.Local += o.Local
	c.Failed += o.Failed
	c.MsSum += o.MsSum
}

// Point is one bucket of a series. T is the bucket start, unix seconds.
type Point struct {
	T int64 `json:"t"`
	Counts
}

// Row is one entry of a top list.
type Row struct {
	Key     string `json:"key"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	// Rule and List say what last blocked a domain ("caught by").
	Rule string `json:"rule,omitempty"`
	List string `json:"list,omitempty"`
}

// Entry is one query from search.
type Entry struct {
	T       int64   `json:"t"` // unix microseconds
	Time    string  `json:"time"`
	Node    string  `json:"node"`
	Client  string  `json:"client"`
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Result  string  `json:"result"`
	Rcode   string  `json:"rcode"`
	Answers int     `json:"answers"`
	Ms      float64 `json:"ms"`
	Allowed bool    `json:"allowed,omitempty"`
	Rule    string  `json:"rule,omitempty"`
	List    string  `json:"list,omitempty"`
	// IPs and CNAMEs are what the answer held.
	IPs    []string `json:"ips,omitempty"`
	CNAMEs []string `json:"cnames,omitempty"`
}

// Answer is one distinct answer a domain got.
type Answer struct {
	IPs    []string `json:"ips,omitempty"`
	CNAMEs []string `json:"cnames,omitempty"`
}

// Result is a node's answer. Which fields are set depends on the kind.
type Result struct {
	// Detail and Stats say whether the node keeps individual queries and
	// hourly totals.
	Detail bool `json:"detail"`
	Stats  bool `json:"stats"`

	Counts  *Counts  `json:"counts,omitempty"`
	Series  []Point  `json:"series,omitempty"`
	Clients []string `json:"clients,omitempty"` // summary: every client seen
	Rows    []Row    `json:"rows,omitempty"`    // top; domain: its devices
	Entries []Entry  `json:"entries,omitempty"`

	// Flags are risky answers (top with Flags; domain).
	Flags []Flag `json:"flags,omitempty"`

	// Domain only.
	Answers []Answer `json:"answers,omitempty"` // recent distinct answers
	Rule    string   `json:"rule,omitempty"`
	List    string   `json:"list,omitempty"`
	First   int64    `json:"first,omitempty"` // unix seconds
	Last    int64    `json:"last,omitempty"`

	// Perf only.
	Perf *Perf `json:"perf,omitempty"`
}

// Validate fills defaults and checks a query.
func (q *Query) Validate() error {
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() || !q.From.Before(q.To) {
		return fmt.Errorf("%w: from must be before to", ErrBadQuery)
	}
	if q.Step <= 0 {
		q.Step = 3600
	}
	if span := int64(q.To.Sub(q.From).Seconds()); span/q.Step > 2000 {
		return fmt.Errorf("%w: too many buckets", ErrBadQuery)
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	q.Limit = min(q.Limit, 20000)
	if len(q.Clients) > 256 {
		return fmt.Errorf("%w: too many clients", ErrBadQuery)
	}
	switch q.Kind {
	case KindSummary, KindSearch:
	case KindPerf:
		if q.Baseline < 0 || q.Baseline > 30*86400 {
			return fmt.Errorf("%w: baseline must be at most 30 days", ErrBadQuery)
		}
	case KindTop:
		if q.By != TopDomains && q.By != TopBlocked && q.By != TopClients && q.By != TopLists {
			return fmt.Errorf("%w: by must be domains, blocked, clients or lists", ErrBadQuery)
		}
	case KindDomain:
		if q.Name == "" {
			return fmt.Errorf("%w: name is required", ErrBadQuery)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrBadQuery, q.Kind)
	}
	return nil
}

// rawSpan is the longest range answered from individual queries rather
// than hourly totals, so short ranges are exact to the minute.
const rawSpan = 3 * time.Hour

// source returns a subquery yielding (sec, client, name, result, n, ms)
// over the query's range, from individual queries for short ranges (when
// kept) or hourly totals.
func (s *Store) source(q *Query) (string, []any, bool) {
	days, statsDays := s.Retention()
	if days > 0 && (q.To.Sub(q.From) <= rawSpan || statsDays == 0) {
		return `(SELECT t / 1000000 AS sec, client, name, result, 1 AS n, ms FROM queries WHERE t >= ? AND t < ?)`,
			[]any{q.From.UnixMicro(), q.To.UnixMicro()}, true
	}
	if statsDays == 0 {
		return "", nil, false
	}
	return `(SELECT hour * 3600 AS sec, client, name, result, n, ms FROM hourly WHERE hour >= ? AND hour < ?)`,
		[]any{q.From.Unix() / 3600, (q.To.Unix() + 3599) / 3600}, true
}

// where adds the client filter (and a name filter for domain queries).
func where(q *Query, args []any) (string, []any) {
	var conds []string
	if len(q.Clients) > 0 {
		conds = append(conds, "client IN ("+placeholders(len(q.Clients))+")")
		for _, c := range q.Clients {
			args = append(args, c)
		}
	}
	if q.Kind == KindDomain {
		conds = append(conds, "name = ?")
		args = append(args, q.Name)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// Run answers a query from this node's history.
func (s *Store) Run(ctx context.Context, q Query) (*Result, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	days, statsDays := s.Retention()
	res := &Result{Detail: days > 0, Stats: statsDays > 0}
	var err error
	switch q.Kind {
	case KindSummary:
		err = s.summary(ctx, &q, res)
	case KindTop:
		err = s.top(ctx, &q, res)
	case KindSearch:
		err = s.search(ctx, &q, res)
	case KindDomain:
		err = s.domain(ctx, &q, res)
	case KindPerf:
		err = s.perf(ctx, &q, res)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Store) series(ctx context.Context, q *Query, res *Result) error {
	src, args, ok := s.source(q)
	res.Counts = &Counts{}
	if !ok {
		return nil
	}
	w, args := where(q, args)
	rows, err := s.db.QueryContext(ctx, `SELECT (sec + ?) / ? AS b, result, SUM(n), SUM(ms) FROM `+src+w+` GROUP BY b, result ORDER BY b`,
		append([]any{q.Offset, q.Step}, args...)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b, n int64
		var code int
		var ms float64
		if err := rows.Scan(&b, &code, &n, &ms); err != nil {
			return err
		}
		t := b*q.Step - q.Offset
		if len(res.Series) == 0 || res.Series[len(res.Series)-1].T != t {
			res.Series = append(res.Series, Point{T: t})
		}
		res.Series[len(res.Series)-1].add(code, n, ms)
		res.Counts.add(code, n, ms)
	}
	return rows.Err()
}

func (s *Store) summary(ctx context.Context, q *Query, res *Result) error {
	if err := s.series(ctx, q, res); err != nil {
		return err
	}
	src, args, ok := s.source(q)
	if !ok {
		return nil
	}
	w, args := where(q, args)
	return collect(ctx, s.db, `SELECT DISTINCT client FROM `+src+w+` LIMIT 10000`, args, func(r *sql.Rows) error {
		var c string
		err := r.Scan(&c)
		res.Clients = append(res.Clients, c)
		return err
	})
}

func (s *Store) top(ctx context.Context, q *Query, res *Result) error {
	if q.By == TopLists {
		return s.topLists(ctx, q, res)
	}
	src, args, ok := s.source(q)
	if !ok {
		return nil
	}
	w, args := where(q, args)
	key := "name"
	if q.By == TopClients {
		key = "client"
	}
	if q.By == TopBlocked {
		if w == "" {
			w = " WHERE result = ?"
		} else {
			w += " AND result = ?"
		}
		args = append(args, codeBlocked)
	}
	err := collect(ctx, s.db, `SELECT `+key+`, SUM(n), SUM(CASE WHEN result = ? THEN n ELSE 0 END) AS blocked FROM `+src+w+
		` GROUP BY `+key+` ORDER BY 2 DESC, 1 LIMIT ?`, append(append([]any{codeBlocked}, args...), q.Limit), func(r *sql.Rows) error {
		var row Row
		err := r.Scan(&row.Key, &row.Total, &row.Blocked)
		res.Rows = append(res.Rows, row)
		return err
	})
	if err != nil {
		return err
	}
	if q.Flags {
		err := collect(ctx, s.db, `SELECT name, reason, score FROM flagged WHERE t >= ? AND t < ?`, []any{q.From.UnixMicro(), q.To.UnixMicro()}, func(r *sql.Rows) error {
			var f Flag
			err := r.Scan(&f.Name, &f.Reason, &f.Score)
			res.Flags = append(res.Flags, f)
			return err
		})
		if err != nil {
			return err
		}
	}
	if q.By == TopClients || len(res.Rows) == 0 {
		return nil
	}
	return s.caughtBy(ctx, res.Rows)
}

// caughtBy fills in what last blocked each domain.
func (s *Store) caughtBy(ctx context.Context, rows []Row) error {
	idx := map[string]int{}
	args := make([]any, 0, len(rows))
	for i, r := range rows {
		if r.Blocked > 0 {
			idx[r.Key] = i
			args = append(args, r.Key)
		}
	}
	if len(args) == 0 {
		return nil
	}
	return collect(ctx, s.db, `SELECT name, rule, list FROM caught WHERE name IN (`+placeholders(len(args))+`)`, args, func(r *sql.Rows) error {
		var name, rule, list string
		if err := r.Scan(&name, &rule, &list); err != nil {
			return err
		}
		rows[idx[name]].Rule, rows[idx[name]].List = rule, list
		return nil
	})
}

// likeEscape escapes LIKE wildcards in a search word.
var likeEscape = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *Store) search(ctx context.Context, q *Query, res *Result) error {
	if days, _ := s.Retention(); days == 0 {
		return nil
	}
	to := q.To.UnixMicro()
	if q.Before > 0 && q.Before < to {
		to = q.Before
	}
	conds := []string{"t >= ?", "t < ?"}
	args := []any{q.From.UnixMicro(), to}
	if len(q.Clients) > 0 {
		conds = append(conds, "client IN ("+placeholders(len(q.Clients))+")")
		for _, c := range q.Clients {
			args = append(args, c)
		}
	}
	// Every word must appear somewhere in the name, in any order, so
	// "google ads" finds googleads.g.doubleclick.net.
	for _, word := range strings.Fields(strings.ToLower(q.Name)) {
		conds = append(conds, `name LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape.Replace(word)+"%")
	}
	switch q.Result {
	case "":
	case "allowed":
		conds = append(conds, "allowed = 1")
	default:
		code, ok := resultCode(q.Result)
		if !ok {
			return fmt.Errorf("%w: unknown result %q", ErrBadQuery, q.Result)
		}
		if code == codeCached {
			conds = append(conds, "result IN (?, ?)")
			args = append(args, codeCached, codeStale)
		} else {
			conds = append(conds, "result = ?")
			args = append(args, code)
		}
	}
	args = append(args, q.Limit)
	return collect(ctx, s.db, `SELECT t, client, name, qtype, result, rcode, answers, ms, allowed, COALESCE(rule, ''), COALESCE(list, ''), COALESCE(ips, ''), COALESCE(cnames, '') FROM queries WHERE `+
		strings.Join(conds, " AND ")+` ORDER BY t DESC LIMIT ?`, args, func(r *sql.Rows) error {
		var e Entry
		var code, allowed int
		var ips, cnames string
		if err := r.Scan(&e.T, &e.Client, &e.Name, &e.Type, &code, &e.Rcode, &e.Answers, &e.Ms, &allowed, &e.Rule, &e.List, &ips, &cnames); err != nil {
			return err
		}
		e.IPs, e.CNAMEs = split(ips), split(cnames)
		e.Result, e.Allowed, e.Node = resultName(code), allowed == 1, s.node()
		e.Time = time.UnixMicro(e.T).UTC().Format(time.RFC3339Nano)
		res.Entries = append(res.Entries, e)
		return nil
	})
}

func (s *Store) domain(ctx context.Context, q *Query, res *Result) error {
	if err := s.series(ctx, q, res); err != nil {
		return err
	}
	src, args, ok := s.source(q)
	if !ok {
		return nil
	}
	w, args := where(q, args)
	err := collect(ctx, s.db, `SELECT client, SUM(n), SUM(CASE WHEN result = ? THEN n ELSE 0 END), MIN(sec), MAX(sec) FROM `+src+w+
		` GROUP BY client ORDER BY 2 DESC, 1 LIMIT ?`, append(append([]any{codeBlocked}, args...), q.Limit), func(r *sql.Rows) error {
		var row Row
		var first, last int64
		if err := r.Scan(&row.Key, &row.Total, &row.Blocked, &first, &last); err != nil {
			return err
		}
		if res.First == 0 || first < res.First {
			res.First = first
		}
		res.Last = max(res.Last, last)
		res.Rows = append(res.Rows, row)
		return nil
	})
	if err != nil {
		return err
	}
	// Exact last-seen time from individual queries, when kept.
	if res.Detail {
		var t sql.NullInt64
		if s.db.QueryRowContext(ctx, `SELECT MAX(t) FROM queries WHERE name = ?`, q.Name).Scan(&t) == nil && t.Valid {
			res.Last = max(res.Last, t.Int64/1_000_000)
		}
	}
	var rule, list string
	if s.db.QueryRowContext(ctx, `SELECT rule, list FROM caught WHERE name = ?`, q.Name).Scan(&rule, &list) == nil {
		res.Rule, res.List = rule, list
	}
	var f Flag
	if s.db.QueryRowContext(ctx, `SELECT name, reason, score FROM flagged WHERE name = ?`, q.Name).Scan(&f.Name, &f.Reason, &f.Score) == nil {
		res.Flags = []Flag{f}
	}
	if !res.Detail {
		return nil
	}
	// The latest distinct answers.
	seen := map[string]bool{}
	return collect(ctx, s.db, `SELECT COALESCE(ips, ''), COALESCE(cnames, '') FROM queries WHERE name = ? AND (ips IS NOT NULL OR cnames IS NOT NULL) ORDER BY t DESC LIMIT 200`,
		[]any{q.Name}, func(r *sql.Rows) error {
			var ips, cn string
			if err := r.Scan(&ips, &cn); err != nil {
				return err
			}
			if k := ips + "|" + cn; !seen[k] && len(res.Answers) < 5 {
				seen[k] = true
				res.Answers = append(res.Answers, Answer{IPs: split(ips), CNAMEs: split(cn)})
			}
			return nil
		})
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func collect(ctx context.Context, db *sql.DB, query string, args []any, fn func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Merge combines the answers of several nodes to the same query.
func Merge(q Query, parts []*Result) *Result {
	q.Validate()
	out := &Result{}
	series := map[int64]*Point{}
	clients := map[string]bool{}
	rows := map[string]*Row{}
	flags := map[string]Flag{}
	var perfs []*Perf
	for _, p := range parts {
		if p == nil {
			continue
		}
		if p.Perf != nil {
			perfs = append(perfs, p.Perf)
		}
		out.Detail = out.Detail || p.Detail
		out.Stats = out.Stats || p.Stats
		if p.Counts != nil {
			if out.Counts == nil {
				out.Counts = &Counts{}
			}
			out.Counts.merge(*p.Counts)
		}
		for _, pt := range p.Series {
			if cur, ok := series[pt.T]; ok {
				cur.merge(pt.Counts)
			} else {
				c := pt
				series[pt.T] = &c
			}
		}
		for _, c := range p.Clients {
			clients[c] = true
		}
		for _, r := range p.Rows {
			if cur, ok := rows[r.Key]; ok {
				cur.Total += r.Total
				cur.Blocked += r.Blocked
				if cur.Rule == "" {
					cur.Rule, cur.List = r.Rule, r.List
				}
			} else {
				c := r
				rows[r.Key] = &c
			}
		}
		out.Entries = append(out.Entries, p.Entries...)
		for _, f := range p.Flags {
			if cur, ok := flags[f.Name]; !ok || f.Score > cur.Score {
				flags[f.Name] = f
			}
		}
		for _, a := range p.Answers {
			if len(out.Answers) < 5 && !slices.ContainsFunc(out.Answers, func(b Answer) bool { return slices.Equal(a.IPs, b.IPs) && slices.Equal(a.CNAMEs, b.CNAMEs) }) {
				out.Answers = append(out.Answers, a)
			}
		}
		if out.Rule == "" {
			out.Rule, out.List = p.Rule, p.List
		}
		if p.First != 0 && (out.First == 0 || p.First < out.First) {
			out.First = p.First
		}
		out.Last = max(out.Last, p.Last)
	}
	if q.Kind == KindPerf {
		out.Perf = mergePerf(q, perfs)
	}
	for _, pt := range series {
		out.Series = append(out.Series, *pt)
	}
	slices.SortFunc(out.Series, func(a, b Point) int { return int(a.T - b.T) })
	for c := range clients {
		out.Clients = append(out.Clients, c)
	}
	for _, f := range flags {
		out.Flags = append(out.Flags, f)
	}
	slices.SortFunc(out.Flags, func(a, b Flag) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(out.Clients)
	for _, r := range rows {
		out.Rows = append(out.Rows, *r)
	}
	slices.SortFunc(out.Rows, func(a, b Row) int {
		if a.Total != b.Total {
			if a.Total > b.Total {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(out.Rows) > q.Limit {
		out.Rows = out.Rows[:q.Limit]
	}
	slices.SortStableFunc(out.Entries, func(a, b Entry) int {
		switch {
		case a.T > b.T:
			return -1
		case a.T < b.T:
			return 1
		}
		return 0
	})
	if len(out.Entries) > q.Limit {
		out.Entries = out.Entries[:q.Limit]
	}
	return out
}

// topLists counts blocks per list. Each block counts for the list whose
// rule matched it. Individual queries say exactly which list that was;
// beyond them, the hourly totals are matched with the list that last
// blocked each domain.
func (s *Store) topLists(ctx context.Context, q *Query, res *Result) error {
	days, statsDays := s.Retention()
	var query string
	var args []any
	clients := func(col string) string {
		if len(q.Clients) == 0 {
			return ""
		}
		for _, c := range q.Clients {
			args = append(args, c)
		}
		return " AND " + col + " IN (" + placeholders(len(q.Clients)) + ")"
	}
	kept := s.now().AddDate(0, 0, -days)
	switch {
	case days > 0 && (!q.From.Before(kept) || statsDays == 0):
		args = []any{q.From.UnixMicro(), q.To.UnixMicro(), codeBlocked}
		query = `SELECT COALESCE(list, ''), COUNT(*) FROM queries WHERE t >= ? AND t < ? AND result = ?` + clients("client")
	case statsDays > 0:
		args = []any{q.From.Unix() / 3600, (q.To.Unix() + 3599) / 3600, codeBlocked}
		query = `SELECT COALESCE(c.list, ''), SUM(h.n) FROM hourly h LEFT JOIN caught c ON c.name = h.name
			WHERE h.hour >= ? AND h.hour < ? AND h.result = ?` + clients("h.client")
	default:
		return nil
	}
	return collect(ctx, s.db, query+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?`, append(args, q.Limit), func(r *sql.Rows) error {
		var row Row
		err := r.Scan(&row.Key, &row.Total)
		row.Blocked = row.Total
		res.Rows = append(res.Rows, row)
		return err
	})
}
