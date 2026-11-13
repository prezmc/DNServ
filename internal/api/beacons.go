package api

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
)

// Repeating lookups, by domain: which names devices ask for on a steady
// beat, how often, and which devices. Informational: a beat is typical of
// analytics, telemetry and trackers, but also of mail checks and clocks.

type beaconDevice struct {
	Key    string `json:"key"` // device id or address, for the Query log
	Label  string `json:"label"`
	Addr   string `json:"addr"`
	N      int64  `json:"n"`
	Period int64  `json:"period"`
}

type beaconDomain struct {
	Name    string         `json:"name"`
	N       int64          `json:"n"`
	Blocked int64          `json:"blocked"`
	Period  int64          `json:"period"` // the busiest device's beat, seconds
	Devices int            `json:"devices"`
	Who     []beaconDevice `json:"who,omitempty"`
	Type    *threat.Type   `json:"type,omitempty"`
	Risk    *threat.Risk   `json:"risk,omitempty"`
	Now     *domainStatus  `json:"now,omitempty"`
}

func (a *API) analyticsBeacons(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindBeacons)
	if !ok {
		return
	}
	if q.To.Sub(q.From) > 24*time.Hour {
		q.From = q.To.Add(-24 * time.Hour) // a beat shows within a day
	}
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	perDevice := p.Can(store.PermQueryLog)
	var addrs []string
	for _, b := range res.Beacons {
		addrs = append(addrs, b.Client)
	}
	var l *labeler
	if perDevice {
		l = a.newLabeler(r.Context(), dedupe(addrs))
	}
	byName := map[string]*beaconDomain{}
	whoBy := map[string]map[string]*beaconDevice{}
	var list []*beaconDomain
	for _, b := range res.Beacons {
		d := byName[b.Name]
		if d == nil {
			d = &beaconDomain{Name: b.Name}
			byName[b.Name] = d
			whoBy[b.Name] = map[string]*beaconDevice{}
			list = append(list, d)
		}
		d.N += b.N
		d.Blocked += b.Blocked
		key, label := b.Client, b.Client
		if l != nil {
			if id := l.device[b.Client]; id != "" {
				key = id
			}
			if n := l.names[b.Client]; n != "" {
				label = n
			}
		}
		if cur := whoBy[b.Name][key]; cur != nil {
			if b.N > cur.N {
				cur.Period = b.Period
			}
			cur.N += b.N
		} else {
			whoBy[b.Name][key] = &beaconDevice{Key: key, Label: label, Addr: b.Client, N: b.N, Period: b.Period}
		}
	}
	slices.SortFunc(list, func(x, y *beaconDomain) int { return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.Name, y.Name)) })
	if limit := q.Limit; limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]beaconDomain, 0, len(list))
	for _, d := range list {
		var who []beaconDevice
		for _, w := range whoBy[d.Name] {
			who = append(who, *w)
		}
		slices.SortFunc(who, func(x, y beaconDevice) int { return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.Label, y.Label)) })
		d.Devices = len(who)
		d.Period = who[0].Period
		if perDevice {
			d.Who = who[:min(len(who), 8)]
		}
		if a.Intel != nil {
			d.Type = a.Intel.TypeOf(d.Name)
			if risk := a.Intel.Score(d.Name); risk.Score > 0 {
				d.Risk = &risk
			}
		}
		s := a.statusOf(d.Name)
		d.Now = &s
		out = append(out, *d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out, "nodes": nodes, "detail": res.Detail})
}
