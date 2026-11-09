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
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure Go, so the image stays CGO-free

	"github.com/prezmc/dnserve/internal/querylog"
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
	queueSize  = 1 << 15 // queries waiting to be written
	batchMax   = 4096
	flushEvery = time.Second
	pruneEvery = time.Hour
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

	in      chan querylog.Entry
	dropped atomic.Uint64
	written atomic.Uint64

	days, statsDays atomic.Int64

	now       func() time.Time
	pruneCh   chan struct{}
	flushReq  chan chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
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
	s := &Store{
		db: db, log: log, node: node, in: make(chan querylog.Entry, queueSize),
		now: time.Now, stop: make(chan struct{}), done: make(chan struct{}),
		pruneCh: make(chan struct{}, 1), flushReq: make(chan chan struct{}),
	}
	s.days.Store(int64(days))
	s.statsDays.Store(int64(statsDays))
	go s.run()
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
	return s.db.Close()
}

// Flush waits until everything recorded so far is written (for tests).
func (s *Store) Flush() {
	ch := make(chan struct{})
	s.flushReq <- ch
	<-ch
}

func (s *Store) run() {
	defer close(s.done)
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	prune := time.NewTicker(pruneEvery)
	defer prune.Stop()
	batch := make([]querylog.Entry, 0, batchMax)
	flush := func() {
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
		case <-tick.C:
			flush()
		case ch := <-s.flushReq:
			for drained := false; !drained; {
				select {
				case e := <-s.in:
					batch = append(batch, e)
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
		args := make([]any, 0, per*11)
		for i := 0; i < len(batch); i += per {
			chunk := batch[i:min(i+per, len(batch))]
			args = args[:0]
			for _, e := range chunk {
				code, _ := resultCode(e.Result)
				var rule, list any
				if e.Rule != "" || e.List != "" {
					rule, list = e.Rule, e.List
				}
				args = append(args, e.Time.UnixMicro(), e.Client.String(), e.Name, e.Type, code, e.Rcode, e.Answers, e.Duration, b2i(e.Allowed), rule, list)
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
	return `INSERT INTO queries (t, client, name, qtype, result, rcode, answers, ms, allowed, rule, list) VALUES ` +
		strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?,?,?,?,?,?),", n), ",")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
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
	s.db.Exec(`DELETE FROM caught WHERE t < ?`, hcut*3600*1_000_000)
	if removed > 0 {
		s.db.Exec(`PRAGMA incremental_vacuum`)
		s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		s.log.Debug("query history cleaned up", "rows", removed)
	}
}

// ErrBadQuery is returned for a query the store can't run.
var ErrBadQuery = errors.New("bad analytics query")
