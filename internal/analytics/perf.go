package analytics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"time"
)

// Response-time tracking.
//
// The writer goroutine rolls every recorded query up into 5-minute slots
// per result and record type, with a latency histogram, so percentiles can
// be read back and merged across nodes exactly. Upstream servers report
// each exchange (see ObserveUpstream) into the same kind of slots. Nothing
// here runs on the query path: the server already measures each query's
// time, and upstream samples go through a non-blocking queue.

const slotSecs = 300

// bounds are the histogram bucket upper limits in milliseconds; the last
// bucket holds everything slower.
var bounds = [...]float64{0.1, 0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 2000, 5000}

// HistLen is the number of histogram buckets.
const HistLen = len(bounds) + 1

// Hist counts response times per bucket.
type Hist [HistLen]int64

func bucketOf(ms float64) int {
	i, _ := slices.BinarySearch(bounds[:], ms)
	return i
}

// Add counts one response time.
func (h *Hist) Add(ms float64) { h[bucketOf(ms)]++ }

func (h *Hist) merge(o *Hist) {
	for i := range h {
		h[i] += o[i]
	}
}

// Quantile estimates the q-th quantile (0-1), interpolating inside a
// bucket. max caps the open last bucket.
func (h *Hist) Quantile(q, max float64) float64 {
	var n int64
	for _, c := range h {
		n += c
	}
	if n == 0 {
		return 0
	}
	rank := q * float64(n)
	var cum float64
	for i, c := range h {
		if c == 0 {
			continue
		}
		if cum+float64(c) >= rank {
			lo := 0.0
			if i > 0 {
				lo = bounds[i-1]
			}
			hi := max
			if i < len(bounds) {
				hi = bounds[i]
			}
			if max > 0 {
				hi = math.Min(hi, max)
			}
			if hi < lo {
				hi = lo
			}
			return lo + (hi-lo)*(rank-cum)/float64(c)
		}
		cum += float64(c)
	}
	return max
}

// PerfStat is the response times of a set of queries.
type PerfStat struct {
	N    int64   `json:"n"`
	Ms   float64 `json:"ms"`  // sum
	Max  float64 `json:"max"` // slowest
	Hist Hist    `json:"hist"`
}

func (p *PerfStat) add(ms float64) {
	p.N++
	p.Ms += ms
	p.Max = math.Max(p.Max, ms)
	p.Hist.Add(ms)
}

func (p *PerfStat) merge(o *PerfStat) {
	p.N += o.N
	p.Ms += o.Ms
	p.Max = math.Max(p.Max, o.Max)
	p.Hist.merge(&o.Hist)
}

// Avg is the mean response time.
func (p *PerfStat) Avg() float64 {
	if p.N == 0 {
		return 0
	}
	return p.Ms / float64(p.N)
}

// Q is a quantile of the response time.
func (p *PerfStat) Q(q float64) float64 { return p.Hist.Quantile(q, p.Max) }

// PerfPoint is one bucket of response times.
type PerfPoint struct {
	T int64 `json:"t"`
	// All is every answered query, Upstream those answered by asking an
	// upstream server (cache misses).
	All      PerfStat `json:"all"`
	Upstream PerfStat `json:"upstream"`
	Cached   int64    `json:"cached"` // including stale
	Blocked  int64    `json:"blocked"`
	Local    int64    `json:"local"`
	Failed   int64    `json:"failed"`
	Servfail int64    `json:"servfail"`
	Nxdomain int64    `json:"nxdomain"`
}

func (p *PerfPoint) merge(o *PerfPoint) {
	p.All.merge(&o.All)
	p.Upstream.merge(&o.Upstream)
	p.Cached += o.Cached
	p.Blocked += o.Blocked
	p.Local += o.Local
	p.Failed += o.Failed
	p.Servfail += o.Servfail
	p.Nxdomain += o.Nxdomain
}

// UpPoint is one upstream server's exchanges in a bucket. Stat holds the
// successful ones.
type UpPoint struct {
	T        int64    `json:"t"`
	Tries    int64    `json:"tries"`
	Errors   int64    `json:"errors"`
	Timeouts int64    `json:"timeouts"`
	Servfail int64    `json:"servfail"`
	Stat     PerfStat `json:"stat"`
}

func (p *UpPoint) merge(o *UpPoint) {
	p.Tries += o.Tries
	p.Errors += o.Errors
	p.Timeouts += o.Timeouts
	p.Servfail += o.Servfail
	p.Stat.merge(&o.Stat)
}

// UpSeries is one node's view of one upstream server. Each node has its
// own path to the internet, so they are not added together.
type UpSeries struct {
	Node   string    `json:"node"`
	Server string    `json:"server"`
	Points []UpPoint `json:"points"`
	Total  UpPoint   `json:"total"`
	Usual  UpPoint   `json:"usual"` // the baseline period
}

// SlowRow is a domain or device with its response times (from the hourly
// totals: averages only).
type SlowRow struct {
	Key      string  `json:"key"`
	N        int64   `json:"n"`
	Ms       float64 `json:"ms"`       // sum over upstream answers
	Upstream int64   `json:"upstream"` // answers from upstream
	Cached   int64   `json:"cached"`
	Failed   int64   `json:"failed"`
}

// Perf is a node's response-time history for a period.
type Perf struct {
	Series    []PerfPoint          `json:"series"`
	Baseline  []PerfPoint          `json:"baseline,omitempty"` // hourly, the period before
	Types     map[string]*PerfStat `json:"types,omitempty"`    // per record type, whole period
	Upstreams []UpSeries           `json:"upstreams,omitempty"`
	Domains   []SlowRow            `json:"domains,omitempty"` // slowest to look up
	Devices   []SlowRow            `json:"devices,omitempty"`
}

var histCols = func() string {
	c := make([]string, HistLen)
	for i := range c {
		c[i] = fmt.Sprintf("h%d", i)
	}
	return strings.Join(c, ", ")
}()

func histSums() string {
	c := make([]string, HistLen)
	for i := range c {
		c[i] = fmt.Sprintf("SUM(h%d)", i)
	}
	return strings.Join(c, ", ")
}

func histDefs() string {
	var b strings.Builder
	for i := range HistLen {
		fmt.Fprintf(&b, ",\n\th%d INTEGER NOT NULL DEFAULT 0", i)
	}
	return b.String()
}

func histUpdates() string {
	c := make([]string, HistLen)
	for i := range c {
		c[i] = fmt.Sprintf("h%d = h%d + excluded.h%d", i, i, i)
	}
	return strings.Join(c, ", ")
}

var perfSchema = `
CREATE TABLE IF NOT EXISTS perf (
	slot     INTEGER NOT NULL, -- unix seconds / 300
	result   INTEGER NOT NULL,
	qtype    TEXT    NOT NULL,
	n        INTEGER NOT NULL,
	ms       REAL    NOT NULL,
	max      REAL    NOT NULL,
	servfail INTEGER NOT NULL,
	nxdomain INTEGER NOT NULL` + histDefs() + `,
	PRIMARY KEY (slot, result, qtype)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS upstream_perf (
	slot     INTEGER NOT NULL,
	server   TEXT    NOT NULL,
	tries    INTEGER NOT NULL,
	errors   INTEGER NOT NULL,
	timeouts INTEGER NOT NULL,
	servfail INTEGER NOT NULL,
	n        INTEGER NOT NULL, -- successful
	ms       REAL    NOT NULL,
	max      REAL    NOT NULL` + histDefs() + `,
	PRIMARY KEY (slot, server)
) WITHOUT ROWID;
`

type perfKey struct {
	slot   int64
	result int
	qtype  string
}

type perfAgg struct {
	PerfStat
	servfail, nxdomain int64
}

// Upstream exchange outcomes.
const (
	upOK = iota
	upError
	upTimeout
)

type upSample struct {
	server string
	t      time.Time
	ms     float64
	kind   int
	rcode  int
}

type upKey struct {
	slot   int64
	server string
}

type upAgg struct {
	tries, errors, timeouts, servfail int64
	stat                              PerfStat
}

// ObserveUpstream records one exchange with an upstream server: when it
// started, how long it took, the answer's rcode and any error. It never
// blocks; set it as the upstream group's observer.
func (s *Store) ObserveUpstream(server string, start time.Time, d time.Duration, rcode int, err error) {
	u := upSample{server: server, t: start, ms: float64(d.Microseconds()) / 1000, rcode: rcode}
	if err != nil {
		u.kind = upError
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
			u.kind = upTimeout
		}
	}
	select {
	case s.upIn <- u:
	default:
		s.dropped.Add(1)
	}
}

func (s *Store) perfDays() int {
	days, statsDays := s.Retention()
	if statsDays > 0 {
		return statsDays
	}
	return days
}

// addUp folds an upstream sample into the pending totals (writer goroutine).
func (s *Store) addUp(u upSample) {
	k := upKey{u.t.Unix() / slotSecs, u.server}
	a := s.upPending[k]
	if a == nil {
		a = &upAgg{}
		s.upPending[k] = a
	}
	a.tries++
	switch u.kind {
	case upError:
		a.errors++
	case upTimeout:
		a.timeouts++
	default:
		a.stat.add(u.ms)
		if u.rcode == 2 { // SERVFAIL
			a.servfail++
		}
	}
}

func histArgs(args []any, h *Hist) []any {
	for _, c := range h {
		args = append(args, c)
	}
	return args
}

func (s *Store) writeUpstream() error {
	if len(s.upPending) == 0 {
		return nil
	}
	defer clear(s.upPending)
	if s.perfDays() == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO upstream_perf (slot, server, tries, errors, timeouts, servfail, n, ms, max, ` + histCols + `) VALUES (` +
		placeholders(9+HistLen) + `) ON CONFLICT (slot, server) DO UPDATE SET tries = tries + excluded.tries, errors = errors + excluded.errors,
		timeouts = timeouts + excluded.timeouts, servfail = servfail + excluded.servfail, n = n + excluded.n, ms = ms + excluded.ms,
		max = MAX(max, excluded.max), ` + histUpdates())
	if err != nil {
		return err
	}
	defer st.Close()
	args := make([]any, 0, 9+HistLen)
	for k, a := range s.upPending {
		args = append(args[:0], k.slot, k.server, a.tries, a.errors, a.timeouts, a.servfail, a.stat.N, a.stat.Ms, a.stat.Max)
		if _, err := st.Exec(histArgs(args, &a.stat.Hist)...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// writePerf rolls a batch of queries into the perf slots.
func writePerf(tx *sql.Tx, agg map[perfKey]*perfAgg) error {
	if len(agg) == 0 {
		return nil
	}
	st, err := tx.Prepare(`INSERT INTO perf (slot, result, qtype, n, ms, max, servfail, nxdomain, ` + histCols + `) VALUES (` +
		placeholders(8+HistLen) + `) ON CONFLICT (slot, result, qtype) DO UPDATE SET n = n + excluded.n, ms = ms + excluded.ms,
		max = MAX(max, excluded.max), servfail = servfail + excluded.servfail, nxdomain = nxdomain + excluded.nxdomain, ` + histUpdates())
	if err != nil {
		return err
	}
	defer st.Close()
	args := make([]any, 0, 8+HistLen)
	for k, a := range agg {
		args = append(args[:0], k.slot, k.result, k.qtype, a.N, a.Ms, a.Max, a.servfail, a.nxdomain)
		if _, err := st.Exec(histArgs(args, &a.Hist)...); err != nil {
			return err
		}
	}
	return nil
}

func scanHist(dest []any, h *Hist) []any {
	for i := range h {
		dest = append(dest, &h[i])
	}
	return dest
}

// bucketExpr groups 5-minute slots into the query's buckets.
const bucketExpr = `(slot * 300 + ?) / ?`

func (s *Store) perf(ctx context.Context, q *Query, res *Result) error {
	p := &Perf{Types: map[string]*PerfStat{}}
	res.Perf = p
	if s.perfDays() == 0 {
		return nil
	}
	lo, hi := q.From.Unix()/slotSecs, (q.To.Unix()+slotSecs-1)/slotSecs
	series, err := s.perfSeries(ctx, lo, hi, q.Offset, q.Step)
	if err != nil {
		return err
	}
	p.Series = series
	if q.Baseline > 0 {
		blo := q.From.Add(-time.Duration(q.Baseline) * time.Second).Unix()
		if p.Baseline, err = s.perfSeries(ctx, blo/slotSecs, lo, 0, 3600); err != nil {
			return err
		}
	}
	err = collect(ctx, s.db, `SELECT qtype, SUM(n), SUM(ms), MAX(max), `+histSums()+` FROM perf WHERE slot >= ? AND slot < ? GROUP BY qtype`,
		[]any{lo, hi}, func(r *sql.Rows) error {
			var t string
			st := &PerfStat{}
			if err := r.Scan(scanHist([]any{&t, &st.N, &st.Ms, &st.Max}, &st.Hist)...); err != nil {
				return err
			}
			p.Types[t] = st
			return nil
		})
	if err != nil {
		return err
	}
	if p.Upstreams, err = s.upSeries(ctx, q, lo, hi); err != nil {
		return err
	}
	return s.slow(ctx, q, p)
}

func (s *Store) perfSeries(ctx context.Context, lo, hi, offset, step int64) ([]PerfPoint, error) {
	var out []PerfPoint
	err := collect(ctx, s.db, `SELECT `+bucketExpr+` AS b, result, SUM(n), SUM(ms), MAX(max), SUM(servfail), SUM(nxdomain), `+histSums()+
		` FROM perf WHERE slot >= ? AND slot < ? GROUP BY b, result ORDER BY b`, []any{offset, step, lo, hi}, func(r *sql.Rows) error {
		var b int64
		var code int
		var st PerfStat
		var sf, nx int64
		if err := r.Scan(scanHist([]any{&b, &code, &st.N, &st.Ms, &st.Max, &sf, &nx}, &st.Hist)...); err != nil {
			return err
		}
		t := b*step - offset
		if len(out) == 0 || out[len(out)-1].T != t {
			out = append(out, PerfPoint{T: t})
		}
		pt := &out[len(out)-1]
		pt.Servfail += sf
		pt.Nxdomain += nx
		switch code {
		case codeFailed:
			pt.Failed += st.N
		case codeBlocked:
			pt.Blocked += st.N
		case codeCached, codeStale:
			pt.Cached += st.N
		case codeLocal:
			pt.Local += st.N
		case codeAnswered:
			pt.Upstream.merge(&st)
		}
		// Failed queries end in a SERVFAIL after waiting on upstream; they
		// count towards response times too, as clients waited for them.
		pt.All.merge(&st)
		return nil
	})
	return out, err
}

func (s *Store) upSeries(ctx context.Context, q *Query, lo, hi int64) ([]UpSeries, error) {
	byServer := map[string]*UpSeries{}
	var order []string
	get := func(server string) *UpSeries {
		u := byServer[server]
		if u == nil {
			u = &UpSeries{Node: s.node(), Server: server}
			byServer[server] = u
			order = append(order, server)
		}
		return u
	}
	scan := func(r *sql.Rows) (string, UpPoint, error) {
		var server string
		var p UpPoint
		err := r.Scan(scanHist([]any{&p.T, &server, &p.Tries, &p.Errors, &p.Timeouts, &p.Servfail, &p.Stat.N, &p.Stat.Ms, &p.Stat.Max}, &p.Stat.Hist)...)
		return server, p, err
	}
	cols := `SUM(tries), SUM(errors), SUM(timeouts), SUM(servfail), SUM(n), SUM(ms), MAX(max), ` + histSums()
	err := collect(ctx, s.db, `SELECT `+bucketExpr+` AS b, server, `+cols+` FROM upstream_perf WHERE slot >= ? AND slot < ? GROUP BY b, server ORDER BY b`,
		[]any{q.Offset, q.Step, lo, hi}, func(r *sql.Rows) error {
			server, p, err := scan(r)
			if err != nil {
				return err
			}
			p.T = p.T*q.Step - q.Offset
			u := get(server)
			u.Points = append(u.Points, p)
			u.Total.merge(&p)
			return nil
		})
	if err != nil {
		return nil, err
	}
	if q.Baseline > 0 && len(byServer) > 0 {
		blo := q.From.Add(-time.Duration(q.Baseline)*time.Second).Unix() / slotSecs
		err = collect(ctx, s.db, `SELECT 0, server, `+cols+` FROM upstream_perf WHERE slot >= ? AND slot < ? GROUP BY server`,
			[]any{blo, lo}, func(r *sql.Rows) error {
				server, p, err := scan(r)
				if err != nil {
					return err
				}
				if u := byServer[server]; u != nil {
					u.Usual = p
				}
				return nil
			})
		if err != nil {
			return nil, err
		}
	}
	out := make([]UpSeries, 0, len(order))
	for _, k := range order {
		out = append(out, *byServer[k])
	}
	return out, nil
}

// slow finds the domains slowest to look up and each device's response
// times, from the hourly totals.
func (s *Store) slow(ctx context.Context, q *Query, p *Perf) error {
	_, statsDays := s.Retention()
	if statsDays == 0 {
		return nil
	}
	args := []any{q.From.Unix() / 3600, (q.To.Unix() + 3599) / 3600}
	limit := max(q.Limit, 1) * 3 // extra, so the merged list is right
	err := collect(ctx, s.db, `SELECT name, SUM(n), SUM(ms) FROM hourly WHERE hour >= ? AND hour < ? AND result = ?
		GROUP BY name HAVING SUM(n) >= 3 ORDER BY SUM(ms) / SUM(n) DESC LIMIT ?`, append(args, codeAnswered, limit), func(r *sql.Rows) error {
		var row SlowRow
		err := r.Scan(&row.Key, &row.N, &row.Ms)
		row.Upstream = row.N
		p.Domains = append(p.Domains, row)
		return err
	})
	if err != nil || !q.Devices {
		return err
	}
	return collect(ctx, s.db, `SELECT client, SUM(n),
		SUM(CASE WHEN result = ? THEN ms ELSE 0 END), SUM(CASE WHEN result = ? THEN n ELSE 0 END),
		SUM(CASE WHEN result IN (?, ?) THEN n ELSE 0 END), SUM(CASE WHEN result = ? THEN n ELSE 0 END)
		FROM hourly WHERE hour >= ? AND hour < ? GROUP BY client ORDER BY 2 DESC LIMIT 500`,
		append([]any{codeAnswered, codeAnswered, codeCached, codeStale, codeFailed}, args...), func(r *sql.Rows) error {
			var row SlowRow
			err := r.Scan(&row.Key, &row.N, &row.Ms, &row.Upstream, &row.Cached, &row.Failed)
			p.Devices = append(p.Devices, row)
			return err
		})
}

// mergePerf combines nodes' response-time histories.
func mergePerf(q Query, parts []*Perf) *Perf {
	out := &Perf{Types: map[string]*PerfStat{}}
	series, baseline := map[int64]*PerfPoint{}, map[int64]*PerfPoint{}
	domains, devices := map[string]*SlowRow{}, map[string]*SlowRow{}
	addPts := func(m map[int64]*PerfPoint, pts []PerfPoint) {
		for i := range pts {
			if cur, ok := m[pts[i].T]; ok {
				cur.merge(&pts[i])
			} else {
				c := pts[i]
				m[c.T] = &c
			}
		}
	}
	addRows := func(m map[string]*SlowRow, rows []SlowRow) {
		for _, r := range rows {
			if cur, ok := m[r.Key]; ok {
				cur.N += r.N
				cur.Ms += r.Ms
				cur.Upstream += r.Upstream
				cur.Cached += r.Cached
				cur.Failed += r.Failed
			} else {
				c := r
				m[r.Key] = &c
			}
		}
	}
	for _, p := range parts {
		if p == nil {
			continue
		}
		addPts(series, p.Series)
		addPts(baseline, p.Baseline)
		for t, st := range p.Types {
			if cur, ok := out.Types[t]; ok {
				cur.merge(st)
			} else {
				c := *st
				out.Types[t] = &c
			}
		}
		out.Upstreams = append(out.Upstreams, p.Upstreams...)
		addRows(domains, p.Domains)
		addRows(devices, p.Devices)
	}
	sorted := func(m map[int64]*PerfPoint) []PerfPoint {
		out := make([]PerfPoint, 0, len(m))
		for _, p := range m {
			out = append(out, *p)
		}
		slices.SortFunc(out, func(a, b PerfPoint) int { return int(a.T - b.T) })
		return out
	}
	out.Series, out.Baseline = sorted(series), sorted(baseline)
	slices.SortFunc(out.Upstreams, func(a, b UpSeries) int {
		return strings.Compare(a.Node+"\x00"+a.Server, b.Node+"\x00"+b.Server)
	})
	for _, r := range domains {
		out.Domains = append(out.Domains, *r)
	}
	slices.SortFunc(out.Domains, func(a, b SlowRow) int {
		if x, y := a.Ms/float64(a.N), b.Ms/float64(b.N); x != y {
			if x > y {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(out.Domains) > q.Limit {
		out.Domains = out.Domains[:q.Limit]
	}
	for _, r := range devices {
		out.Devices = append(out.Devices, *r)
	}
	slices.SortFunc(out.Devices, func(a, b SlowRow) int {
		if a.N != b.N {
			if a.N > b.N {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

// Backfill: history written before response-time tracking existed still
// has each query's time, so the perf slots are rebuilt from it once, in
// the background. Queries recorded from now on are rolled up by the
// writer; the backfill only reads queries older than the cutoff it saves
// on first start, and saves its progress with each chunk, so a restart
// carries on where it stopped and never counts a query twice.

const metaSchema = `CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID;`

func (s *Store) meta(k string) (int64, bool) {
	var v int64
	if s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v) != nil {
		return 0, false
	}
	return v, true
}

func setMeta(ex interface {
	Exec(string, ...any) (sql.Result, error)
}, k string, v int64) error {
	_, err := ex.Exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

// backfillCutoff returns the time (unix microseconds) before which old
// queries still need rolling up, or 0 when there is nothing to do.
func (s *Store) backfillCutoff() (int64, error) {
	if _, err := s.db.Exec(metaSchema); err != nil {
		return 0, err
	}
	if _, done := s.meta("perf_backfill_done"); done {
		return 0, nil
	}
	if c, ok := s.meta("perf_backfill_cutoff"); ok {
		return c, nil
	}
	c := s.now().UnixMicro()
	var oldest sql.NullInt64
	if err := s.db.QueryRow(`SELECT MIN(t) FROM queries`).Scan(&oldest); err != nil {
		return 0, err
	}
	if !oldest.Valid {
		return 0, setMeta(s.db, "perf_backfill_done", c) // nothing to rebuild
	}
	if err := setMeta(s.db, "perf_backfill_cutoff", c); err != nil {
		return 0, err
	}
	return c, setMeta(s.db, "perf_backfill_from", oldest.Int64)
}

const backfillChunk = int64(6 * time.Hour / time.Microsecond)

func (s *Store) backfill(cutoff int64) {
	defer s.bg.Done()
	from, _ := s.meta("perf_backfill_from")
	total := 0
	for from < cutoff {
		select {
		case <-s.stop:
			return
		default:
		}
		to := min(from+backfillChunk, cutoff)
		n, err := s.backfillChunk(from, to, to == cutoff)
		if err != nil {
			s.log.Warn("rebuilding response times from history failed; will retry on restart", "err", err)
			return
		}
		total += n
		from = to
		time.Sleep(5 * time.Millisecond) // leave room for the writer
	}
	if total > 0 {
		s.log.Info("response times rebuilt from existing history", "queries", total)
	}
}

func (s *Store) backfillChunk(from, to int64, last bool) (int, error) {
	agg := map[perfKey]*perfAgg{}
	n := 0
	err := collect(context.Background(), s.db, `SELECT t, qtype, result, rcode, ms FROM queries WHERE t >= ? AND t < ?`, []any{from, to}, func(r *sql.Rows) error {
		var t int64
		var qtype, rcode string
		var code int
		var ms float64
		if err := r.Scan(&t, &qtype, &code, &rcode, &ms); err != nil {
			return err
		}
		k := perfKey{t / 1_000_000 / slotSecs, code, qtype}
		a := agg[k]
		if a == nil {
			a = &perfAgg{}
			agg[k] = a
		}
		a.add(ms)
		switch rcode {
		case "SERVFAIL":
			a.servfail++
		case "NXDOMAIN":
			a.nxdomain++
		}
		n++
		return nil
	})
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := writePerf(tx, agg); err != nil {
		return 0, err
	}
	if err := setMeta(tx, "perf_backfill_from", to); err != nil {
		return 0, err
	}
	if last {
		if err := setMeta(tx, "perf_backfill_done", to); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}
