package api

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/threat"
)

// The scoring guide and tuning: what the scoring is now, the defaults and
// presets, each source's points, and a preview of what a change would do
// to the domains seen lately. Saving goes through the settings, like any
// change, so it is replicated, audited and in settings history.

type scoringSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // domains or addresses
	Entries int    `json:"entries"`
	Ok      bool   `json:"ok"`
}

func (a *API) scoringInfo(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Intel == nil {
		writeErr(w, http.StatusNotFound, "risk scoring isn't available")
		return
	}
	status := map[string]threat.SourceStatus{}
	for _, s := range a.Intel.Status() {
		status[s.ID] = s
	}
	var sources []scoringSource
	for _, f := range threat.Feeds {
		s := status[f.ID]
		sources = append(sources, scoringSource{ID: f.ID, Name: f.Name, Kind: "domains", Entries: s.Entries, Ok: s.Entries > 0})
	}
	for _, f := range threat.IPFeeds {
		s := status[f.ID]
		sources = append(sources, scoringSource{ID: f.ID, Name: f.Name, Kind: "addresses", Entries: s.Entries, Ok: s.Entries > 0})
	}
	st := a.Store.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  a.Intel.Enabled(),
		"scoring":  a.Intel.Scoring(),
		"defaults": config.DefaultRiskScoring(),
		"tuned":    st.Settings.RiskScoring != nil,
		"presets":  threat.Presets(),
		"sources":  sources,
		"names":    threat.NameChecks,
		"trusted":  len(a.Effective().Analytics.TrustedDomains),
	})
}

type scoreChange struct {
	Name    string `json:"name"`
	From    int    `json:"from"`
	To      int    `json:"to"`
	FromLvl string `json:"from_level"`
	ToLvl   string `json:"to_level"`
	Queries int64  `json:"queries"`
}

var levelRank = map[string]int{"": 0, "low": 1, "medium": 2, "high": 3}

// scoringPreview scores the last 7 days' domains under a proposed scoring
// and says what would change.
func (a *API) scoringPreview(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Intel == nil || !a.Intel.Enabled() {
		writeErr(w, http.StatusConflict, "risk scoring is off")
		return
	}
	var in config.RiskScoring
	if !readJSON(w, r, &in) {
		return
	}
	next := in.Normalized()
	cur := a.Intel.Scoring()
	now := a.now()
	q := analytics.Query{Kind: analytics.KindTop, By: analytics.TopDomains, From: now.Add(-7 * 24 * time.Hour), To: now, Limit: 20000, Flags: true}
	res, _, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	flags := map[string]int{}
	for _, f := range res.Flags {
		flags[f.Name] = max(flags[f.Name], f.Score)
	}
	before, after := map[string]int{}, map[string]int{}
	var up, down []scoreChange
	for _, row := range res.Rows {
		s1 := max(a.Intel.Score(row.Key).Score, flags[row.Key])
		s2 := max(a.Intel.ScoreWith(row.Key, &next).Score, flags[row.Key])
		l1, l2 := threat.LevelWith(s1, cur), threat.LevelWith(s2, next)
		before[l1]++
		after[l2]++
		if l1 == l2 {
			continue
		}
		c := scoreChange{Name: row.Key, From: s1, To: s2, FromLvl: l1, ToLvl: l2, Queries: row.Total}
		if levelRank[l2] > levelRank[l1] {
			up = append(up, c)
		} else {
			down = append(down, c)
		}
	}
	order := func(x, y scoreChange) int {
		return cmp.Or(cmp.Compare(max(levelRank[y.ToLvl], levelRank[y.FromLvl]), max(levelRank[x.ToLvl], levelRank[x.FromLvl])), cmp.Compare(y.Queries, x.Queries), cmp.Compare(x.Name, y.Name))
	}
	slices.SortFunc(up, order)
	slices.SortFunc(down, order)
	nUp, nDown := len(up), len(down)
	up, down = up[:min(len(up), 15)], down[:min(len(down), 15)]
	delete(before, "")
	delete(after, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"domains": len(res.Rows), "before": before, "after": after,
		"up": orEmpty(up), "down": orEmpty(down), "up_total": nUp, "down_total": nDown,
	})
}
