package analytics

import (
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/querylog"
)

func TestReach(t *testing.T) {
	for _, tc := range []struct {
		name string
		span time.Duration
	}{{"hourly", 24 * time.Hour}, {"raw", 2 * time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			s := open(t, 30, 90)
			s.Record(entry(1, "192.168.1.10", "bad.example", querylog.Answered))
			s.Record(entry(2, "192.168.1.10", "bad.example", querylog.Cached))
			s.Record(entry(3, "192.168.1.11", "bad.example", querylog.Blocked))
			s.Record(entry(70, "192.168.1.11", "worse.example", querylog.Answered))
			s.Record(entry(5, "192.168.1.12", "fine.example", querylog.Answered))
			s.Flush()
			q := Query{Kind: KindReach, From: base.Add(-time.Minute), To: base.Add(-time.Minute + tc.span),
				Names: []string{"bad.example", "worse.example"}, Limit: 100}
			r := Merge(q, []*Result{run(t, s, q)})
			got := map[string]Row{}
			for _, row := range r.Rows {
				got[row.Key+" "+row.Client] = row
			}
			if len(got) != 3 {
				t.Fatalf("rows = %+v", r.Rows)
			}
			b := got["bad.example 192.168.1.10"]
			if b.Total != 2 || b.Blocked != 0 || b.Last == 0 {
				t.Errorf("bad.example from .10 = %+v", b)
			}
			if c := got["bad.example 192.168.1.11"]; c.Total != 1 || c.Blocked != 1 || c.Last != 0 {
				t.Errorf("blocked only = %+v, want no last answer", c)
			}
			if w := got["worse.example 192.168.1.11"]; w.Last < b.Last {
				t.Errorf("last times out of order: %d < %d", w.Last, b.Last)
			}
			var through int64
			for _, p := range r.Series {
				through += p.Total
			}
			if through != 3 {
				t.Errorf("answered in series = %d, want 3 (%+v)", through, r.Series)
			}
		})
	}
	if err := (&Query{Kind: KindReach, From: base, To: base.Add(time.Hour)}).Validate(); err == nil {
		t.Error("reach without names accepted")
	}
}
