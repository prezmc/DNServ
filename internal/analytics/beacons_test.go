package analytics

import (
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/querylog"
)

func TestBeacons(t *testing.T) {
	s := open(t, 30, 90)
	at := func(sec int, client, name, result string) {
		e := entry(0, client, name, result)
		e.Time = base.Add(time.Duration(sec) * time.Second)
		s.Record(e)
	}
	// Every 30 s (with a little jitter), 40 times: a beacon.
	for i := 0; i < 40; i++ {
		at(i*30+i%3, "192.168.1.10", "telemetry.example", querylog.Answered)
	}
	// Every 5 minutes, blocked: a beacon too.
	for i := 0; i < 15; i++ {
		at(i*300, "192.168.1.11", "ads.example", querylog.Blocked)
	}
	// Plenty of lookups at random times: not a beacon.
	gaps := []int{3, 400, 17, 90, 1200, 8, 60, 33, 700, 5, 250, 41, 2000, 12, 75}
	t0 := 0
	for _, g := range gaps {
		t0 += g
		at(t0, "192.168.1.12", "news.example", querylog.Answered)
	}
	// Too few lookups.
	for i := 0; i < 5; i++ {
		at(i*60, "192.168.1.12", "rare.example", querylog.Answered)
	}
	s.Flush()

	q := Query{Kind: KindBeacons, From: base.Add(-time.Minute), To: base.Add(24 * time.Hour)}
	r := Merge(q, []*Result{run(t, s, q)})
	got := map[string]Beacon{}
	for _, b := range r.Beacons {
		got[b.Name] = b
	}
	if b := got["telemetry.example"]; b.N != 40 || b.Period < 29 || b.Period > 32 || b.Client != "192.168.1.10" {
		t.Errorf("telemetry = %+v", b)
	}
	if b := got["ads.example"]; b.Period != 300 || b.Blocked != 15 {
		t.Errorf("ads = %+v", b)
	}
	if _, ok := got["news.example"]; ok {
		t.Error("irregular lookups reported as a beacon")
	}
	if _, ok := got["rare.example"]; ok {
		t.Error("too few lookups reported as a beacon")
	}
}
