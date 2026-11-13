package api

import (
	"net/http"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/cache"
)

// The cache report answers "why aren't more answers coming from the
// cache?": every lookup that had to go upstream, put down to a reason, the
// domains behind each reason, and what the cache settings are.

type missReason struct {
	Reason  string           `json:"reason"`
	N       int64            `json:"n"`
	Domains []analytics.Miss `json:"domains"`
}

func (a *API) analyticsCache(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindCache)
	if !ok {
		return
	}
	if q.To.Sub(q.From) > 7*24*time.Hour {
		writeErr(w, http.StatusBadRequest, "the cache report covers up to 7 days")
		return
	}
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	var hits, misses int64
	if res.Counts != nil {
		hits = res.Counts.Cached
	}
	reasons := []*missReason{}
	byReason := map[string]*missReason{}
	for _, m := range res.Misses {
		if m.Name == "" {
			mr := &missReason{Reason: m.Reason, N: m.N, Domains: []analytics.Miss{}}
			byReason[m.Reason] = mr
			reasons = append(reasons, mr)
			misses += m.N
		}
	}
	for _, m := range res.Misses {
		if mr := byReason[m.Reason]; m.Name != "" && mr != nil && len(mr.Domains) < 10 {
			mr.Domains = append(mr.Domains, m)
		}
	}
	c := a.Effective().Cache
	var fill []CacheFill
	if a.CacheFill != nil {
		fill = a.CacheFill(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hits": hits, "misses": misses, "reasons": reasons, "nodes": nodes, "detail": res.Detail, "fill": orEmpty(fill),
		"cache": map[string]any{
			"enabled": c.Enabled, "max_entries": c.MaxEntries, "prefetch": c.Prefetch, "persist": c.Persist,
			"min_ttl": int64(c.MinTTL / time.Second), "max_ttl": int64(c.MaxTTL / time.Second),
			"serve_stale": int64(c.ServeStale / time.Second), "negative_ttl": int64(c.NegativeTTL / time.Second),
		},
	})
}

// CacheFill is how full one server's answer cache is right now.
type CacheFill struct {
	Server string      `json:"server"`
	Fill   *cache.Fill `json:"fill,omitempty"`
	Error  string      `json:"error,omitempty"`
}
