// Package analytics keeps a node's long-term query history in SQLite, for
// analytics and search.
//
// Each node keeps only its own queries. The dashboard asks every node and
// merges the answers (see Merge), so there is no central database and a
// node's history is lost only if that node is.
//
// Two tables hold the data: queries has one row per query (for search,
// kept history.days), and hourly has counts per hour, device, domain and
// result (for charts and top lists, kept history.stats_days). Writes are
// queued and batched by one goroutine, so recording a query never waits on
// the disk.
package analytics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite" // pure Go, so the image stays CGO-free

	"github.com/prezmc/dnserv/internal/querylog"
)

// Result codes stored in the database.
const (
	codeAnswered = iota
	codeCached
	codeStale
	codeBlocked
	codeLocal
	codeFailed
)

var resultNames = [...]string{
	codeAnswered: querylog.Answered, codeCached: querylog.Cached, codeStale: querylog.Stale,
	codeBlocked: querylog.Blocked, codeLocal: querylog.Local, codeFailed: querylog.Failed,
}

func resultCode(s string) (int, bool) {
	for i, n := range resultNames {
		if n == s {
			return i, true
		}
	}
	return 0, false
}

func resultName(c int) string {
	if c >= 0 && c < len(resultNames) {
		return resultNames[c]
	}
	return "unknown"
}

const (
	queueSize   = 1 << 15 // queries waiting to be written
	upQueueSize = 1 << 12 // upstream exchanges waiting to be counted
	batchMax    = 4096
	flushEvery  = time.Second
	pruneEvery  = time.Hour
)

const schema = `
PRAGMA auto_vacuum = INCREMENTAL;
CREATE TABLE IF NOT EXISTS queries (
	t       INTEGER NOT NULL, -- unix microseconds
	client  TEXT    NOT NULL,
	name    TEXT    NOT NULL,
	qtype   TEXT    NOT NULL,
	result  INTEGER NOT NULL,
	rcode   TEXT    NOT NULL,
	answers INTEGER NOT NULL,
	ms      REAL    NOT NULL,
	allowed INTEGER NOT NULL,
	rule    TEXT,
	list    TEXT
);
CREATE INDEX IF NOT EXISTS queries_t ON queries (t);
CREATE INDEX IF NOT EXISTS queries_client ON queries (client, t);
CREATE INDEX IF NOT EXISTS queries_name ON queries (name, t);
CREATE TABLE IF NOT EXISTS hourly (
	hour   INTEGER NOT NULL, -- unix seconds / 3600
	name   TEXT    NOT NULL,
	client TEXT    NOT NULL,
	result INTEGER NOT NULL,
	n      INTEGER NOT NULL,
	ms     REAL    NOT NULL, -- sum of response times
	PRIMARY KEY (hour, name, client, result)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hourly_client ON hourly (client, hour);
CREATE INDEX IF NOT EXISTS hourly_name ON hourly (name, hour);
-- Domains whose answers looked risky (an address on an IP threat list,
-- or a CNAME to a risky domain), with the latest reason.
CREATE TABLE IF NOT EXISTS flagged (
	name   TEXT PRIMARY KEY,
	reason TEXT NOT NULL,
	score  INTEGER NOT NULL,
	t      INTEGER NOT NULL
) WITHOUT ROWID;
-- The rule and list that last blocked each domain ("caught by").
CREATE TABLE IF NOT EXISTS caught (
	name TEXT PRIMARY KEY,
	rule TEXT NOT NULL,
	list TEXT NOT NULL,
	t    INTEGER NOT NULL
) WITHOUT ROWID;
`

// Store is one node's query history.
type Store struct {
	db   *sql.DB
	log  *slog.Logger
	node func() string // this node's name, put on search results

	in   chan querylog.Entry
	upIn chan upSample
	// upPending holds upstream totals not yet written (writer only).
	upPending map[upKey]*upAgg
	dropped   atomic.Uint64
	written   atomic.Uint64

	days, statsDays atomic.Int64

	checker   atomic.Pointer[Checker]
	now       func() time.Time
	pruneCh   chan struct{}
	flushReq  chan chan struct{}
	clearReq  chan clearReq
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	bg        sync.WaitGroup // background jobs (backfill)
}

// Open opens (or creates) the history database at path and starts the
// writer. days and statsDays are the retention (see SetRetention).
func Open(path string, node func() string, days, statsDays int, log *slog.Logger) (*Store, error) {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "synchronous(NORMAL)", "busy_timeout(5000)", "cache_size(-16000)", "temp_store(MEMORY)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("history: %w", err)
	}
	if _, err := db.Exec(perfSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("history: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("history: %w", err)
	}
	s := &Store{
		db: db, log: log, node: node, in: make(chan querylog.Entry, queueSize),
		upIn: make(chan upSample, upQueueSize), upPending: map[upKey]*upAgg{},
		now: time.Now, stop: make(chan struct{}), done: make(chan struct{}),
		pruneCh: make(chan struct{}, 1), flushReq: make(chan chan struct{}), clearReq: make(chan clearReq),
	}
	s.days.Store(int64(days))
	s.statsDays.Store(int64(statsDays))
	cutoff, err := s.backfillCutoff()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("history: %w", err)
	}
	go s.run()
	if cutoff > 0 {
		s.bg.Add(1)
		go s.backfill(cutoff)
	}
	return s, nil
}

// SetRetention changes how many days of individual queries and of hourly
// totals are kept. 0 stops keeping (and removes) that kind of history.
func (s *Store) SetRetention(days, statsDays int) {
	old := s.days.Swap(int64(days)) != int64(days)
	old = s.statsDays.Swap(int64(statsDays)) != int64(statsDays) || old
	if old && s.pruneCh != nil {
		select {
		case s.pruneCh <- struct{}{}:
		default:
		}
	}
}

// Retention returns the current retention in days.
func (s *Store) Retention() (days, statsDays int) {
	return int(s.days.Load()), int(s.statsDays.Load())
}

// Record queues a query to be written. It never blocks: if the writer has
// fallen far behind, the query is counted as dropped instead.
func (s *Store) Record(e querylog.Entry) {
	select {
	case s.in <- e:
	default:
		s.dropped.Add(1)
	}
}

// Stats reports what the writer has done.
type Stats struct {
	Written uint64 `json:"written"`
	Dropped uint64 `json:"dropped"`
	Queued  int    `json:"queued"`
	Days    int    `json:"days"`
	Stats   int    `json:"stats_days"`
	Bytes   int64  `json:"bytes"`
}

// Stats returns writer counters and the database size.
func (s *Store) Stats() Stats {
	st := Stats{Written: s.written.Load(), Dropped: s.dropped.Load(), Queued: len(s.in)}
	st.Days, st.Stats = s.Retention()
	var pages, size int64
	if s.db.QueryRow("PRAGMA page_count").Scan(&pages) == nil && s.db.QueryRow("PRAGMA page_size").Scan(&size) == nil {
		st.Bytes = pages * size
	}
	return st
}

// Close writes what is queued and closes the database.
func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.done
	s.bg.Wait()
	return s.db.Close()
}

// Flush waits until everything recorded so far is written (for tests).
func (s *Store) Flush() {
	ch := make(chan struct{})
	s.flushReq <- ch
	<-ch
}

// What Clear can delete.
const (
	ClearPerformance = "performance" // response times and upstream timings
	ClearAll         = "history"     // every query, total and timing
)

type clearReq struct {
	what string
	done chan error
}

// Clear deletes this node's performance stats (ClearPerformance) or all of
// its query history (ClearAll). It runs on the writer, after everything
// recorded so far is written.
func (s *Store) Clear(ctx context.Context, what string) error {
	if what != ClearPerformance && what != ClearAll {
		return fmt.Errorf("history: can't clear %q", what)
	}
	c := clearReq{what: what, done: make(chan error, 1)}
	select {
	case s.clearReq <- c:
	case <-s.done:
		return errors.New("history is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-c.done:
		return err
	case <-ctx.Done():
		return ctx.Err() // it still finishes on the writer
	}
}

func (s *Store) clear(what string) error {
	tables := []string{"perf", "upstream_perf"}
	if what == ClearAll {
		tables = append(tables, "queries", "hourly", "flagged", "caught")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tables {
		if _, err := tx.Exec("DELETE FROM " + t); err != nil {
			return fmt.Errorf("history: clear %s: %w", t, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if what == ClearAll {
		// Give the space back; the file can be large.
		if _, err := s.db.Exec("VACUUM"); err != nil {
			s.log.Warn("history: vacuum after clearing failed", "err", err)
		}
	}
	return nil
}

func (s *Store) run() {
	defer close(s.done)
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	prune := time.NewTicker(pruneEvery)
	defer prune.Stop()
	batch := make([]querylog.Entry, 0, batchMax)
	flush := func() {
		if err := s.writeUpstream(); err != nil {
			s.log.Warn("upstream timing write failed", "err", err)
		}
		if len(batch) == 0 {
			return
		}
		if err := s.write(batch); err != nil {
			s.log.Warn("query history write failed", "err", err, "queries", len(batch))
			s.dropped.Add(uint64(len(batch)))
		} else {
			s.written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	// First clean-up shortly after start, then hourly.
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	for {
		select {
		case e := <-s.in:
			batch = append(batch, e)
			if len(batch) >= batchMax {
				flush()
			}
		case u := <-s.upIn:
			s.addUp(u)
		case <-tick.C:
			flush()
		case c := <-s.clearReq:
			// Write what is waiting first, so nothing recorded before the
			// clear turns up after it.
			for drained := false; !drained; {
				select {
				case e := <-s.in:
					batch = append(batch, e)
				case u := <-s.upIn:
					s.addUp(u)
				default:
					drained = true
				}
			}
			flush()
			c.done <- s.clear(c.what)
		case ch := <-s.flushReq:
			for drained := false; !drained; {
				select {
				case e := <-s.in:
					batch = append(batch, e)
				case u := <-s.upIn:
					s.addUp(u)
				default:
					drained = true
				}
			}
			flush()
			close(ch)
		case <-first.C:
			s.prune()
		case <-prune.C:
			s.prune()
		case <-s.pruneCh:
			flush()
			s.prune()
		case <-s.stop:
			for drained := false; !drained; {
				select {
				case e := <-s.in:
					batch = append(batch, e)
				case u := <-s.upIn:
					s.addUp(u)
				default:
					drained = true
				}
			}
			flush()
			return
		}
	}
}

type hourKey struct {
	hour   int64
	name   string
	client string
	result int
}

type hourAgg struct {
	n  int64
	ms float64
}

func (s *Store) write(batch []querylog.Entry) error {
	days, statsDays := s.Retention()
	if days == 0 && statsDays == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if days > 0 {
		// Many rows per statement: far fewer round trips into SQLite.
		const per = 64
		full, err := tx.Prepare(insertRows(per))
		if err != nil {
			return err
		}
		defer full.Close()
		args := make([]any, 0, per*13)
		for i := 0; i < len(batch); i += per {
			chunk := batch[i:min(i+per, len(batch))]
			args = args[:0]
			for _, e := range chunk {
				code, _ := resultCode(e.Result)
				var rule, list any
				if e.Rule != "" || e.List != "" {
					rule, list = e.Rule, e.List
				}
				ips, cn := answerOf(e.Answer)
				args = append(args, e.Time.UnixMicro(), e.Client.String(), e.Name, e.Type, code, e.Rcode, e.Answers, e.Duration, b2i(e.Allowed), rule, list,
					joinAddrs(ips), joinNames(cn))
			}
			if len(chunk) == per {
				_, err = full.Exec(args...)
			} else {
				_, err = tx.Exec(insertRows(len(chunk)), args...)
			}
			if err != nil {
				return err
			}
		}
	}
	if days > 0 || statsDays > 0 {
		perf := map[perfKey]*perfAgg{}
		for _, e := range batch {
			code, _ := resultCode(e.Result)
			k := perfKey{e.Time.Unix() / slotSecs, code, e.Type}
			a := perf[k]
			if a == nil {
				a = &perfAgg{}
				perf[k] = a
			}
			a.add(e.Duration)
			switch e.Rcode {
			case "SERVFAIL":
				a.servfail++
			case "NXDOMAIN":
				a.nxdomain++
			}
		}
		if err := writePerf(tx, perf); err != nil {
			return err
		}
	}
	if statsDays > 0 {
		agg := map[hourKey]hourAgg{}
		caught := map[string]querylog.Entry{}
		for _, e := range batch {
			code, _ := resultCode(e.Result)
			k := hourKey{e.Time.Unix() / 3600, e.Name, e.Client.String(), code}
			a := agg[k]
			a.n++
			a.ms += e.Duration
			agg[k] = a
			if code == codeBlocked && (e.Rule != "" || e.List != "") {
				caught[e.Name] = e
			}
		}
		if err := s.flag(tx, batch); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT INTO hourly (hour, name, client, result, n, ms) VALUES (?,?,?,?,?,?)
			ON CONFLICT (hour, name, client, result) DO UPDATE SET n = n + excluded.n, ms = ms + excluded.ms`)
		if err != nil {
			return err
		}
		for k, a := range agg {
			if _, err := st.Exec(k.hour, k.name, k.client, k.result, a.n, a.ms); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
		if len(caught) > 0 {
			st, err := tx.Prepare(`INSERT INTO caught (name, rule, list, t) VALUES (?,?,?,?)
				ON CONFLICT (name) DO UPDATE SET rule = excluded.rule, list = excluded.list, t = excluded.t`)
			if err != nil {
				return err
			}
			for n, e := range caught {
				if _, err := st.Exec(n, e.Rule, e.List, e.Time.UnixMicro()); err != nil {
					st.Close()
					return err
				}
			}
			st.Close()
		}
	}
	return tx.Commit()
}

func insertRows(n int) string {
	return `INSERT INTO queries (t, client, name, qtype, result, rcode, answers, ms, allowed, rule, list, ips, cnames) VALUES ` +
		strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?,?,?,?,?,?,?,?),", n), ",")
}

// migrate adds columns that later versions keep.
func migrate(db *sql.DB) error {
	have := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(queries)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			def              any
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	for _, col := range []string{"ips", "cnames"} {
		if !have[col] {
			if _, err := db.Exec(`ALTER TABLE queries ADD COLUMN ` + col + ` TEXT`); err != nil {
				return err
			}
		}
	}
	return nil
}

// answerOf reads the addresses and CNAME targets of an answer.
func answerOf(rrs []dns.RR) (ips []netip.Addr, cnames []string) {
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A); ok {
				ips = append(ips, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				ips = append(ips, a)
			}
		case *dns.CNAME:
			cnames = append(cnames, strings.TrimSuffix(strings.ToLower(v.Target), "."))
		}
	}
	return ips, cnames
}

func joinAddrs(ips []netip.Addr) any {
	if len(ips) == 0 {
		return nil
	}
	parts := make([]string, len(ips))
	for i, a := range ips {
		parts[i] = a.String()
	}
	return strings.Join(parts, ",")
}

func joinNames(n []string) any {
	if len(n) == 0 {
		return nil
	}
	return strings.Join(n, ",")
}

// Flag is a risk found in a domain's answers.
type Flag struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

// Checker rates a domain's answer: addresses and CNAME targets. It runs on
// the writer goroutine, never on the query path.
type Checker func(name string, ips []netip.Addr, cnames []string) (score int, reason string)

// SetChecker sets how answers are checked (nil: not checked).
func (s *Store) SetChecker(c Checker) { s.checker.Store(&c) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// flag checks each distinct answer in the batch and records risky ones.
func (s *Store) flag(tx *sql.Tx, batch []querylog.Entry) error {
	cp := s.checker.Load()
	if cp == nil || *cp == nil {
		return nil
	}
	check := *cp
	type hit struct {
		Flag
		t int64
	}
	seen := map[string]bool{}
	var hits []hit
	for _, e := range batch {
		if len(e.Answer) == 0 {
			continue
		}
		ips, cn := answerOf(e.Answer)
		key := e.Name + "|" + fmt.Sprint(joinAddrs(ips), joinNames(cn))
		if seen[key] {
			continue
		}
		seen[key] = true
		if score, reason := check(e.Name, ips, cn); score > 0 {
			hits = append(hits, hit{Flag{e.Name, reason, score}, e.Time.UnixMicro()})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	st, err := tx.Prepare(`INSERT INTO flagged (name, reason, score, t) VALUES (?,?,?,?)
		ON CONFLICT (name) DO UPDATE SET reason = excluded.reason, score = excluded.score, t = excluded.t`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, h := range hits {
		if _, err := st.Exec(h.Name, h.Reason, h.Score, h.t); err != nil {
			return err
		}
	}
	return nil
}

// prune removes history older than the retention, in chunks so queries
// keep being written meanwhile.
func (s *Store) prune() {
	days, statsDays := s.Retention()
	now := s.now()
	cut := now.AddDate(0, 0, -days).UnixMicro()
	if days == 0 {
		cut = now.Add(time.Hour).UnixMicro() // everything
	}
	removed := int64(0)
	for {
		res, err := s.db.Exec(`DELETE FROM queries WHERE rowid IN (SELECT rowid FROM queries WHERE t < ? LIMIT 20000)`, cut)
		if err != nil {
			s.log.Warn("query history clean-up failed", "err", err)
			return
		}
		n, _ := res.RowsAffected()
		removed += n
		if n < 20000 {
			break
		}
	}
	hcut := now.AddDate(0, 0, -statsDays).Unix() / 3600
	if statsDays == 0 {
		hcut = now.Unix()/3600 + 1
	}
	if res, err := s.db.Exec(`DELETE FROM hourly WHERE hour < ?`, hcut); err == nil {
		n, _ := res.RowsAffected()
		removed += n
	}
	pcut := now.AddDate(0, 0, -s.perfDays()).Unix() / slotSecs
	if s.perfDays() == 0 {
		pcut = now.Unix()/slotSecs + 1
	}
	for _, t := range []string{"perf", "upstream_perf"} {
		if res, err := s.db.Exec(`DELETE FROM `+t+` WHERE slot < ?`, pcut); err == nil {
			n, _ := res.RowsAffected()
			removed += n
		}
	}
	s.db.Exec(`DELETE FROM caught WHERE t < ?`, hcut*3600*1_000_000)
	s.db.Exec(`DELETE FROM flagged WHERE t < ?`, hcut*3600*1_000_000)
	if removed > 0 {
		s.db.Exec(`PRAGMA incremental_vacuum`)
		s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		s.log.Debug("query history cleaned up", "rows", removed)
	}
}

// ErrBadQuery is returned for a query the store can't run.
var ErrBadQuery = errors.New("bad analytics query")
