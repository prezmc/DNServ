package api

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
)

// The security overview answers "did anything risky get through?" the way
// a security product's front page does: a verdict, the high-risk domains
// devices reached (to block, trust or dismiss), how many were blocked
// anyway, and when they were reached.

// reached is a high-risk domain that devices got answers for.
type reached struct {
	Name      string        `json:"name"`
	Risk      threat.Risk   `json:"risk"`
	Type      *threat.Type  `json:"type,omitempty"`
	Now       *domainStatus `json:"now,omitempty"`
	Passed    int64         `json:"passed"`  // lookups answered
	Blocked   int64         `json:"blocked"` // lookups blocked
	Last      int64         `json:"last"`    // unix seconds of the last answer
	Devices   int           `json:"devices"` // how many devices got answers
	Who       []reacher     `json:"who,omitempty"`
	Dismissed bool          `json:"dismissed,omitempty"`
}

// reacher is a device that reached a risky domain.
type reacher struct {
	Key    string `json:"key"` // device id or address, for the Query log
	Label  string `json:"label"`
	Passed int64  `json:"passed"`
}

type tally struct {
	Domains int   `json:"domains"`
	Queries int64 `json:"queries"`
}

type riskPoint struct {
	T int64 `json:"t"`
	N int64 `json:"n"`
}

// maxReached is how many reached domains the overview lists.
const maxReached = 50

func (a *API) analyticsSecurity(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindTop)
	if !ok {
		return
	}
	out := map[string]any{"feeds": false, "through": []reached{}, "blocked": tally{}, "watch": tally{}, "series": []riskPoint{}}
	if a.Intel == nil || !a.Intel.Enabled() {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["feeds"] = true
	var failed []string
	needsKey := false
	for _, s := range a.Intel.Status() {
		switch {
		case s.NeedsKey:
			needsKey = true
		case s.Error != "" && s.Entries == 0:
			failed = append(failed, s.Name)
		}
	}
	out["needs_key"], out["failed"] = needsKey, failed

	// Every domain seen, scored here, as on the risky list.
	q.By, q.Limit, q.Flags = analytics.TopDomains, 20000, true
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	out["nodes"] = nodes
	flags := map[string]*analytics.Flag{}
	for i := range res.Flags {
		flags[res.Flags[i].Name] = &res.Flags[i]
	}
	risks := map[string]threat.Risk{}
	var high []string
	var blocked, watch tally
	for _, row := range res.Rows {
		risk := withFlag(a.Intel.Score(row.Key), flags[row.Key])
		switch {
		case risk.Score >= threat.High:
			risks[row.Key] = risk
			high = append(high, row.Key)
			if row.Blocked > 0 {
				blocked.Domains++
				blocked.Queries += row.Blocked
			}
		case risk.Score >= threat.Medium && row.Total > row.Blocked:
			watch.Domains++
			watch.Queries += row.Total - row.Blocked
		}
	}
	out["blocked"], out["watch"] = blocked, watch
	if len(high) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	slices.SortStableFunc(high, func(x, y string) int { return risks[y].Score - risks[x].Score })
	if len(high) > analytics.MaxNames {
		high = high[:analytics.MaxNames]
	}

	// Who reached them, and when.
	rq := q
	rq.Kind, rq.By, rq.Flags, rq.Names, rq.Limit = analytics.KindReach, "", false, high, 20000
	rres, _, ok := a.askOrFail(w, r, rq)
	if !ok {
		return
	}
	byName := map[string]*reached{}
	clients := map[string]map[string]int64{}
	var addrs []string
	for _, row := range rres.Rows {
		e := byName[row.Key]
		if e == nil {
			e = &reached{Name: row.Key, Risk: risks[row.Key]}
			byName[row.Key] = e
			clients[row.Key] = map[string]int64{}
		}
		passed := row.Total - row.Blocked
		e.Passed += passed
		e.Blocked += row.Blocked
		e.Last = max(e.Last, row.Last)
		if passed > 0 {
			if _, seen := clients[row.Key][row.Client]; !seen {
				addrs = append(addrs, row.Client)
			}
			clients[row.Key][row.Client] += passed
		}
	}
	var through []*reached
	for _, e := range byName {
		if e.Passed > 0 {
			through = append(through, e)
		}
	}
	dismissed := a.Store.State().Dismissed
	for _, e := range through {
		if at, ok := dismissed[e.Name]; ok && !at.Before(time.Unix(e.Last, 0)) {
			e.Dismissed = true
		}
	}
	slices.SortFunc(through, func(x, y *reached) int {
		if x.Dismissed != y.Dismissed {
			if x.Dismissed {
				return 1
			}
			return -1
		}
		return cmp.Or(y.Risk.Score-x.Risk.Score, cmp.Compare(y.Passed, x.Passed), cmp.Compare(x.Name, y.Name))
	})
	if len(through) > maxReached {
		through = through[:maxReached]
	}
	perDevice := p.Can(store.PermQueryLog)
	var l *labeler
	if perDevice {
		l = a.newLabeler(r.Context(), dedupe(addrs))
	}
	list := make([]reached, 0, len(through))
	for _, e := range through {
		// Count devices, not addresses: a named device may have several.
		who := map[string]*reacher{}
		for addr, n := range clients[e.Name] {
			key, label := addr, addr
			if l != nil {
				if id := l.device[addr]; id != "" {
					key = id
				}
				if n := l.names[addr]; n != "" {
					label = n
				}
			}
			if cur := who[key]; cur != nil {
				cur.Passed += n
			} else {
				who[key] = &reacher{Key: key, Label: label, Passed: n}
			}
		}
		e.Devices = len(who)
		if perDevice {
			for _, w := range who {
				e.Who = append(e.Who, *w)
			}
			slices.SortFunc(e.Who, func(x, y reacher) int { return cmp.Or(cmp.Compare(y.Passed, x.Passed), cmp.Compare(x.Label, y.Label)) })
			if len(e.Who) > 3 {
				e.Who = e.Who[:3]
			}
		}
		s := a.statusOf(e.Name)
		e.Now = &s
		e.Type = a.Intel.TypeOf(e.Name)
		list = append(list, *e)
	}
	out["through"] = list
	series := []riskPoint{}
	for _, pt := range rres.Series {
		if pt.Total > 0 {
			series = append(series, riskPoint{T: pt.T, N: pt.Total})
		}
	}
	out["series"] = series
	writeJSON(w, http.StatusOK, out)
}

func dedupe(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// riskDismiss sets a risky domain aside on the security overview until a
// device reaches it again, or brings it back.
func (a *API) riskDismiss(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in store.RiskDismiss
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = filter.Normalize(in.Name)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpRiskDismiss, p.Actor(), in)); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
