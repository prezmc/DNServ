package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/prezmc/dnserve/internal/analytics"
	"github.com/prezmc/dnserve/internal/store"
)

// slowRow is a domain or device with its response times, for the UI.
type slowRow struct {
	Key       string   `json:"key"`
	Label     string   `json:"label,omitempty"`
	DeviceID  string   `json:"device,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`
	Queries   int64    `json:"queries"`
	Lookups   int64    `json:"lookups"`
	LookupAvg float64  `json:"lookup_avg_ms"`
	CacheHit  float64  `json:"cache_hit"`
	Failed    int64    `json:"failed"`
}

func toSlow(r analytics.SlowRow) slowRow {
	s := slowRow{Key: r.Key, Queries: r.N, Lookups: r.Upstream, Failed: r.Failed}
	if r.Upstream > 0 {
		s.LookupAvg = r.Ms / float64(r.Upstream)
	}
	if n := r.Cached + r.Upstream + r.Failed; n > 0 {
		s.CacheHit = float64(r.Cached) / float64(n)
	}
	return s
}

// analyticsPerformance reports how quickly queries were answered, how the
// upstream servers did, and anything unusual, across every node.
func (a *API) analyticsPerformance(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindPerf)
	if !ok {
		return
	}
	q.Clients = nil // response times aren't kept per device
	if q.Limit == 0 {
		q.Limit = 15
	}
	// Compare short periods with the week before; longer ones with
	// themselves.
	span := q.To.Sub(q.From)
	if span <= 25*time.Hour { // 24h starts on a whole hour, so a little over
		q.Baseline = int64((7 * 24 * time.Hour).Seconds())
	}
	devices := p.Can(store.PermQueryLog)
	q.Devices = devices
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	perf := res.Perf
	if perf == nil {
		perf = &analytics.Perf{}
	}
	view := analytics.Report(perf, q.Step, span.Hours())
	domains := []slowRow{}
	for _, d := range perf.Domains {
		domains = append(domains, toSlow(d))
	}
	out := map[string]any{
		"from": q.From.UTC(), "to": q.To.UTC(), "step": q.Step,
		"view": view, "domains": domains,
		"detail": res.Detail, "stats": res.Stats, "nodes": nodes,
	}
	if devices {
		keys := make([]string, 0, len(perf.Devices))
		for _, d := range perf.Devices {
			keys = append(keys, d.Key)
		}
		l := a.newLabeler(r.Context(), keys)
		// Add up a named device's addresses.
		merged := map[string]*analytics.SlowRow{}
		rows := []*slowRow{}
		byKey := map[string]*slowRow{}
		for _, d := range perf.Devices {
			key, label, id := d.Key, l.names[d.Key], l.device[d.Key]
			if id != "" {
				key = id
			}
			if m, ok := merged[key]; ok {
				m.N += d.N
				m.Ms += d.Ms
				m.Upstream += d.Upstream
				m.Cached += d.Cached
				m.Failed += d.Failed
				byKey[key].Addrs = append(byKey[key].Addrs, d.Key)
				continue
			}
			c := d
			c.Key = key
			merged[key] = &c
			s := &slowRow{Label: label, DeviceID: id, Addrs: []string{d.Key}}
			byKey[key] = s
			rows = append(rows, s)
		}
		devs := make([]slowRow, 0, len(rows))
		for _, s := range rows {
			m := merged[s.DeviceID]
			if m == nil {
				m = merged[s.Addrs[0]]
			}
			t := toSlow(*m)
			t.Label, t.DeviceID, t.Addrs = s.Label, s.DeviceID, s.Addrs
			devs = append(devs, t)
		}
		slices.SortStableFunc(devs, func(x, y slowRow) int { return int(y.Queries - x.Queries) })
		if len(devs) > 50 {
			devs = devs[:50]
		}
		out["devices"] = devs
	}
	writeJSON(w, http.StatusOK, out)
}
