package analytics

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/prezmc/dnserve/internal/querylog"
)

func open(t *testing.T, days, stats int) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "history.db"), func() string { return "node-a" }, days, stats, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var base = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func entry(min int, client, name, result string) querylog.Entry {
	e := querylog.Entry{Time: base.Add(time.Duration(min) * time.Minute), Client: netip.MustParseAddr(client), Name: name, Type: "A", Result: result, Rcode: "NOERROR", Duration: 2}
	if result == querylog.Blocked {
		e.Rule, e.List = "||"+name+"^", "HaGeZi Pro"
	}
	return e
}

func fill(s *Store) {
	for i := range 30 {
		s.Record(entry(i, "192.168.1.10", "example.com", querylog.Answered))
		s.Record(entry(i, "192.168.1.11", "example.com", querylog.Cached))
	}
	for i := range 10 {
		s.Record(entry(i+70, "192.168.1.10", "ads.tracker.net", querylog.Blocked))
	}
	s.Record(entry(5, "192.168.1.12", "googleads.g.doubleclick.net", querylog.Blocked))
	s.Flush()
}

func run(t *testing.T, s *Store, q Query) *Result {
	t.Helper()
	r, err := s.Run(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSummaryAndTop(t *testing.T) {
	s := open(t, 30, 90)
	fill(s)
	day := Query{From: base.Add(-time.Hour), To: base.Add(23 * time.Hour)}

	q := day
	q.Kind, q.Step = KindSummary, 3600
	r := run(t, s, q)
	if r.Counts.Total != 71 || r.Counts.Blocked != 11 || r.Counts.Cached != 30 {
		t.Fatalf("counts = %+v", r.Counts)
	}
	if len(r.Series) != 2 || r.Series[0].T != base.Unix() || r.Series[1].Blocked != 10 {
		t.Fatalf("series = %+v", r.Series)
	}
	if len(r.Clients) != 3 {
		t.Fatalf("clients = %v", r.Clients)
	}

	q = day
	q.Kind, q.By = KindTop, TopBlocked
	r = run(t, s, q)
	if len(r.Rows) != 2 || r.Rows[0].Key != "ads.tracker.net" || r.Rows[0].Total != 10 || r.Rows[0].List != "HaGeZi Pro" || r.Rows[0].Rule != "||ads.tracker.net^" {
		t.Fatalf("top blocked = %+v", r.Rows)
	}

	q = day
	q.Kind, q.By, q.Clients = KindTop, TopDomains, []string{"192.168.1.11"}
	r = run(t, s, q)
	if len(r.Rows) != 1 || r.Rows[0].Key != "example.com" || r.Rows[0].Total != 30 {
		t.Fatalf("top for one client = %+v", r.Rows)
	}

	q = day
	q.Kind, q.By = KindTop, TopClients
	r = run(t, s, q)
	if len(r.Rows) != 3 || r.Rows[0].Key != "192.168.1.10" || r.Rows[0].Blocked != 10 {
		t.Fatalf("top clients = %+v", r.Rows)
	}
}

func TestShortRangeUsesIndividualQueries(t *testing.T) {
	s := open(t, 30, 90)
	fill(s)
	r := run(t, s, Query{Kind: KindSummary, From: base, To: base.Add(10 * time.Minute), Step: 300})
	// Minutes 0-9: 20 example.com plus the one doubleclick query.
	if r.Counts.Total != 21 || len(r.Series) != 2 {
		t.Fatalf("counts = %+v series = %+v", r.Counts, r.Series)
	}
}

func TestSearch(t *testing.T) {
	s := open(t, 30, 90)
	fill(s)
	day := Query{Kind: KindSearch, From: base.Add(-time.Hour), To: base.Add(23 * time.Hour), Limit: 5}

	q := day
	q.Name = "google ads"
	r := run(t, s, q)
	if len(r.Entries) != 1 || r.Entries[0].Name != "googleads.g.doubleclick.net" || r.Entries[0].Node != "node-a" {
		t.Fatalf("search = %+v", r.Entries)
	}

	q = day
	r = run(t, s, q)
	if len(r.Entries) != 5 || r.Entries[0].Name != "ads.tracker.net" || r.Entries[0].T < r.Entries[4].T {
		t.Fatalf("newest first = %+v", r.Entries)
	}
	q.Before = r.Entries[4].T
	r2 := run(t, s, q)
	if len(r2.Entries) != 5 || r2.Entries[0].T >= q.Before {
		t.Fatalf("paging = %+v", r2.Entries)
	}

	q = day
	q.Result, q.Clients = "cached", []string{"192.168.1.11"}
	q.Limit = 100
	if r := run(t, s, q); len(r.Entries) != 30 {
		t.Fatalf("cached for one client = %d", len(r.Entries))
	}
	q.Name = "100%_"
	if r := run(t, s, q); len(r.Entries) != 0 {
		t.Fatalf("wildcards must be literal, got %d", len(r.Entries))
	}
}

func TestDomain(t *testing.T) {
	s := open(t, 30, 90)
	fill(s)
	r := run(t, s, Query{Kind: KindDomain, Name: "ads.tracker.net", From: base.Add(-time.Hour), To: base.Add(23 * time.Hour)})
	if r.Counts.Blocked != 10 || len(r.Rows) != 1 || r.Rows[0].Key != "192.168.1.10" || r.List != "HaGeZi Pro" {
		t.Fatalf("domain = %+v", r)
	}
	if r.Last != base.Add(79*time.Minute).Unix() {
		t.Fatalf("last = %v", time.Unix(r.Last, 0))
	}
}

func TestRetention(t *testing.T) {
	s := open(t, 30, 90)
	s.now = func() time.Time { return base.AddDate(0, 0, 31) }
	fill(s)
	s.prune()
	q := Query{Kind: KindSearch, From: base.Add(-time.Hour), To: base.Add(23 * time.Hour)}
	if r := run(t, s, q); len(r.Entries) != 0 {
		t.Fatalf("old queries kept: %d", len(r.Entries))
	}
	q.Kind = KindSummary
	if r := run(t, s, q); r.Counts.Total != 71 {
		t.Fatalf("hourly totals should outlive individual queries: %+v", r.Counts)
	}
	// Turning history off removes it and stops recording.
	s.SetRetention(0, 0)
	s.Record(entry(1, "192.168.1.10", "x.com", querylog.Answered))
	s.Flush()
	if r := run(t, s, q); r.Counts.Total != 0 || r.Detail || r.Stats {
		t.Fatalf("after turning off: %+v", r)
	}
}

func TestMerge(t *testing.T) {
	a, b := open(t, 30, 90), open(t, 30, 90)
	fill(a)
	b.node = func() string { return "node-b" }
	for i := range 5 {
		b.Record(entry(i, "192.168.1.20", "ads.tracker.net", querylog.Blocked))
	}
	b.Flush()
	q := Query{Kind: KindTop, By: TopBlocked, From: base.Add(-time.Hour), To: base.Add(23 * time.Hour)}
	m := Merge(q, []*Result{run(t, a, q), run(t, b, q), nil})
	if m.Rows[0].Key != "ads.tracker.net" || m.Rows[0].Total != 15 {
		t.Fatalf("merged top = %+v", m.Rows)
	}
	q.Kind = KindSummary
	m = Merge(q, []*Result{run(t, a, q), run(t, b, q)})
	if m.Counts.Total != 76 || len(m.Clients) != 4 {
		t.Fatalf("merged summary = %+v %v", m.Counts, m.Clients)
	}
	q.Kind, q.Limit = KindSearch, 8
	m = Merge(q, []*Result{run(t, a, q), run(t, b, q)})
	if len(m.Entries) != 8 {
		t.Fatalf("merged search = %d", len(m.Entries))
	}
	for i := 1; i < len(m.Entries); i++ {
		if m.Entries[i].T > m.Entries[i-1].T {
			t.Fatal("merged search not newest first")
		}
	}
}

func TestRecordNeverBlocks(t *testing.T) {
	s := open(t, 30, 90)
	e := entry(0, "192.168.1.10", "example.com", querylog.Answered)
	start := time.Now()
	for range queueSize * 3 {
		s.Record(e)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Record took %v", d)
	}
	s.Flush()
	st := s.Stats()
	if st.Written+st.Dropped != queueSize*3 {
		t.Fatalf("stats = %+v", st)
	}
}

func BenchmarkRecord(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "h.db"), func() string { return "n" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	e := entry(0, "192.168.1.10", "example.com", querylog.Answered)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Record(e)
		}
	})
}

// BenchmarkWrite measures how fast the writer stores queries.
func BenchmarkWrite(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "h.db"), func() string { return "n" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	batch := make([]querylog.Entry, 1000)
	for i := range batch {
		batch[i] = entry(i%60, "192.168.1."+string(rune('0'+i%10)), "d"+string(rune('a'+i%26))+".example.com", querylog.Answered)
	}
	b.ResetTimer()
	for range b.N {
		if err := s.write(batch); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N*len(batch))/b.Elapsed().Seconds(), "queries/s")
}
