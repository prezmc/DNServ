package api

import (
	"cmp"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/threat"
)

// Analyze: what app or site probably made a device look up a (risky)
// domain. Apps and pages look up their own names first, then the names
// of everything they load, so the lookups the same device made in the
// seconds around it, and especially just before it, point to the source.
// Everything here is a guess from timing, and the page says so. It runs
// on demand from saved history, never on the answer path.

const (
	analyzeWindow   = 60 * time.Second // the default "around it"
	analyzeSpan     = 5 * time.Minute  // read this much either side, to tell background from burst
	analyzeEpisodes = 5                // other lookups of the name to compare
	analyzeTimeline = 60               // rows of the timeline
)

// sourceGuess is one app or site that may be behind the lookup.
type sourceGuess struct {
	Label      string   `json:"label"`              // "Netflix", "example.com"
	Category   string   `json:"category,omitempty"` // "Streaming"
	Confidence string   `json:"confidence"`         // likely or possible
	Share      int      `json:"share"`              // percent of the evidence
	Seen       int      `json:"seen"`               // lookups of the risky name it was near
	Reasons    []string `json:"reasons"`
	Domains    []nameN  `json:"domains"`
	score      float64
}

type nameN struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

// companion is a third-party service seen nearby (ads, analytics, CDN):
// not the source itself, but a hint of what kind of app it is.
type companion struct {
	Label    string `json:"label"`
	Category string `json:"category"`
	N        int    `json:"n"`
}

type timelineRow struct {
	T      int64        `json:"t"`  // unix microseconds
	DT     float64      `json:"dt"` // seconds from the analyzed lookup
	Name   string       `json:"name"`
	Types  []string     `json:"types"`
	Result string       `json:"result"`
	Group  string       `json:"group,omitempty"`
	Target bool         `json:"target,omitempty"`
	Risk   *threat.Risk `json:"risk,omitempty"`
}

// group is where a domain belongs for this analysis.
type group struct {
	key, label, category string
	third                bool // ads, CDN, network: helpers, not sources
	weak                 bool // OS and cloud services: often background
	skip                 bool // local names and reverse lookups
}

func (a *API) groupOf(name string) group {
	n := filter.Normalize(name)
	if !strings.Contains(n, ".") || strings.HasSuffix(n, ".arpa") || strings.HasSuffix(n, ".local") || strings.HasSuffix(n, ".lan") || strings.HasSuffix(n, ".home") || strings.HasSuffix(n, ".internal") {
		return group{skip: true}
	}
	var c threat.Category
	if a.Intel != nil {
		c = a.Intel.Category(n)
	} else {
		c = threat.CategoryOf(n, nil)
	}
	site := siteOf(n)
	g := group{key: "site:" + site, label: site}
	if c.Service != "" {
		g.key, g.label = "svc:"+c.Service, c.Service
	}
	if c.Name != threat.CatOther {
		g.category = c.Name
	}
	switch c.Name {
	case threat.CatNetwork:
		g.skip = true
	case threat.CatAds, threat.CatCDN:
		g.third = true
	case threat.CatOS:
		g.weak = true
	}
	return g
}

// siteOf is a name's registrable domain ("www.bbc.co.uk" → "bbc.co.uk").
func siteOf(name string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	return name
}

// groupScore collects one group's evidence over every analyzed lookup.
type groupScore struct {
	g       group
	score   float64
	seen    int
	near    int
	blocked int     // nearby lookups that were blocked
	closest float64 // seconds, before (negative) or after
	busy    float64 // the worst share of minutes it showed up in
	same    bool    // same site as the risky name
	cname   bool    // its answer pointed to the risky name
	names   map[string]int
}

// inferSource weighs the lookups around each time a device looked name
// up. episodes[i] holds the device's lookups within analyzeSpan of
// times[i] (unix microseconds).
func (a *API) inferSource(name string, times []int64, episodes [][]analytics.Entry, window time.Duration) ([]sourceGuess, []companion) {
	target := filter.Normalize(name)
	tsite := siteOf(target)
	tau := window.Seconds() / 3
	groups := map[string]*groupScore{}
	cache := map[string]group{}
	groupFor := func(n string) group {
		g, ok := cache[n]
		if !ok {
			g = a.groupOf(n)
			cache[n] = g
		}
		return g
	}
	for i, es := range episodes {
		at := times[i]
		weight := map[string]float64{}
		minutes := map[string]map[int64]bool{}
		seen := map[string]map[string]bool{} // key -> name@second, so A+AAAA count once
		for _, e := range es {
			n := filter.Normalize(e.Name)
			if n == target || e.Type == "PTR" {
				continue
			}
			g := groupFor(n)
			if g.skip {
				continue
			}
			dt := float64(e.T-at) / 1e6
			gs := groups[g.key]
			if gs == nil {
				gs = &groupScore{g: g, names: map[string]int{}, closest: math.Inf(1)}
				groups[g.key] = gs
			}
			if minutes[g.key] == nil {
				minutes[g.key], seen[g.key] = map[int64]bool{}, map[string]bool{}
			}
			minutes[g.key][int64(math.Floor(dt/60))] = true
			if math.Abs(dt) > window.Seconds() {
				continue
			}
			k := n + "@" + strconv.FormatInt(e.T/1e6, 10)
			if seen[g.key][k] {
				continue
			}
			seen[g.key][k] = true
			w := math.Exp(-math.Abs(dt) / tau)
			if dt > 0 {
				w *= 0.5 // what an app loads comes after the app itself
			}
			weight[g.key] += w
			gs.near++
			if e.Result == "blocked" {
				gs.blocked++
			}
			gs.names[n]++
			if math.Abs(dt) < math.Abs(gs.closest) {
				gs.closest = dt
			}
			if siteOf(n) == tsite {
				gs.same = true
			}
			for _, c := range e.CNAMEs {
				if filter.Normalize(c) == target {
					gs.cname = true
				}
			}
		}
		span := 2 * analyzeSpan.Minutes()
		for key, w := range weight {
			gs := groups[key]
			// Something looked up all through the ten minutes is more
			// likely background than what caused this lookup.
			share := float64(len(minutes[key])) / span
			gs.busy = max(gs.busy, share)
			f := 1.0
			if share > 0.3 {
				f = 1 - 0.6*(share-0.3)/0.7
			}
			gs.score += w * f
			gs.seen++
		}
	}
	n := float64(len(episodes))
	var cands []*groupScore
	var comps []companion
	for _, gs := range groups {
		if gs.seen == 0 {
			continue
		}
		gs.score /= n
		if n > 1 {
			gs.score *= 0.5 + 0.5*float64(gs.seen)/n
		}
		if gs.same {
			gs.score *= 3
		}
		if gs.cname {
			gs.score *= 4
		}
		// Ads, CDNs, and anything your blocklists stopped every time, are
		// what an app loads, not the app.
		allBlocked := gs.blocked == gs.near
		if (gs.g.third || allBlocked) && !gs.same && !gs.cname {
			cat := gs.g.category
			if allBlocked && !gs.g.third {
				cat = "blocked"
			}
			comps = append(comps, companion{Label: gs.g.label, Category: cat, N: gs.near})
			continue
		}
		if gs.g.weak && !gs.same && !gs.cname {
			gs.score *= 0.6
		}
		cands = append(cands, gs)
	}
	slices.SortFunc(cands, func(x, y *groupScore) int {
		return cmp.Or(cmp.Compare(y.score, x.score), cmp.Compare(x.g.label, y.g.label))
	})
	slices.SortFunc(comps, func(x, y companion) int { return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.Label, y.Label)) })
	comps = comps[:min(len(comps), 6)]
	var total float64
	for _, c := range cands {
		total += c.score
	}
	var out []sourceGuess
	for i, c := range cands[:min(len(cands), 3)] {
		g := sourceGuess{Label: c.g.label, Category: c.g.category, Seen: c.seen, score: c.score, Confidence: "possible"}
		if total > 0 {
			g.Share = int(math.Round(100 * c.score / total))
		}
		// Likely: clearly ahead of the rest, and close in time.
		if i == 0 && c.score >= 0.5 && (len(cands) == 1 || c.score >= 2*cands[1].score) {
			g.Confidence = "likely"
		}
		if c.cname {
			g.Reasons = append(g.Reasons, "its answer pointed to "+name)
		}
		if c.same {
			g.Reasons = append(g.Reasons, "same site as "+name)
		}
		g.Reasons = append(g.Reasons, plural(c.near, "lookup", "lookups")+" nearby, closest "+offset(c.closest))
		if n > 1 {
			if c.seen == int(n) {
				g.Reasons = append(g.Reasons, "near all "+strconv.Itoa(c.seen)+" times it was looked up")
			} else {
				g.Reasons = append(g.Reasons, "near "+strconv.Itoa(c.seen)+" of "+strconv.Itoa(int(n))+" times it was looked up")
			}
		}
		if c.busy > 0.6 {
			g.Reasons = append(g.Reasons, "busy all through these minutes, so it may be unrelated")
		}
		for nm, k := range c.names {
			g.Domains = append(g.Domains, nameN{nm, k})
		}
		slices.SortFunc(g.Domains, func(x, y nameN) int { return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.Name, y.Name)) })
		g.Domains = g.Domains[:min(len(g.Domains), 4)]
		out = append(out, g)
	}
	return out, comps
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// offset says how far from the lookup something was: "3 s before".
func offset(dt float64) string {
	s := int(math.Round(math.Abs(dt)))
	switch {
	case s == 0:
		return "the same second"
	case dt < 0:
		return strconv.Itoa(s) + " s before"
	}
	return strconv.Itoa(s) + " s after"
}

func (a *API) analyticsAnalyze(w http.ResponseWriter, r *http.Request, p *Principal) {
	v := r.URL.Query()
	name := filter.Normalize(v.Get("name"))
	if name == "" || v.Get("client") == "" {
		writeErr(w, http.StatusBadRequest, "name and client are required")
		return
	}
	addrs, err := a.clientAddrs(v.Get("client"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	window := analyzeWindow
	if s, err := strconv.Atoi(v.Get("window")); err == nil && s >= 10 && s <= 300 {
		window = time.Duration(s) * time.Second
	}
	at, _ := strconv.ParseInt(v.Get("t"), 10, 64)
	now := a.now()
	from := now.Add(-24 * time.Hour)
	if at > 0 {
		if tt := time.UnixMicro(at); tt.Before(from.Add(time.Hour)) {
			from = tt.Add(-time.Hour)
		}
	}

	// Every time this device looked the name up in the last day.
	occ, nodes, ok := a.askOrFail(w, r, analytics.Query{Kind: analytics.KindSearch, From: from, To: now.Add(time.Second), Clients: addrs, Names: []string{name}, Limit: 2000})
	if !ok {
		return
	}
	out := map[string]any{"name": name, "detail": occ.Detail, "nodes": nodes, "window": int(window.Seconds()),
		"guesses": []sourceGuess{}, "companions": []companion{}, "timeline": []timelineRow{}}
	l := a.newLabeler(r.Context(), addrs)
	out["device"] = l.names[addrs[0]]
	if out["device"] == "" {
		out["device"] = addrs[0]
	}
	var secs []int64
	for _, e := range slices.Backward(occ.Entries) { // oldest first
		if s := e.T / 1e6; len(secs) == 0 || s > secs[len(secs)-1] {
			secs = append(secs, s)
		}
	}
	out["lookups"] = len(secs)
	if period, ok := analytics.Beat(secs); ok {
		out["period"] = period
	}
	if at == 0 {
		if len(occ.Entries) == 0 {
			writeJSON(w, http.StatusOK, out)
			return
		}
		at = occ.Entries[0].T
	}
	out["t"] = at
	// The lookup asked about, then other times it was looked up (newest
	// first), each far enough apart to be a separate moment.
	times := []int64{at}
	for _, e := range occ.Entries {
		if len(times) == analyzeEpisodes {
			break
		}
		apart := true
		for _, t := range times {
			if d := e.T - t; d > -2*window.Microseconds() && d < 2*window.Microseconds() {
				apart = false
				break
			}
		}
		if apart {
			times = append(times, e.T)
		}
	}
	episodes := make([][]analytics.Entry, len(times))
	errs := make([]error, len(times))
	var wg sync.WaitGroup
	for i, t := range times {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := time.UnixMicro(t)
			res, _, err := a.ask(r.Context(), analytics.Query{Kind: analytics.KindSearch, From: c.Add(-analyzeSpan), To: c.Add(analyzeSpan), Clients: addrs, Limit: 5000}, 4*time.Second)
			if err == nil {
				episodes[i] = res.Entries
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	if errs[0] != nil {
		writeErr(w, http.StatusInternalServerError, errs[0].Error())
		return
	}
	// Drop other moments that failed; the first one is enough to go on.
	for i := len(times) - 1; i > 0; i-- {
		if errs[i] != nil {
			times, episodes = slices.Delete(times, i, i+1), slices.Delete(episodes, i, i+1)
		}
	}
	out["moments"] = len(times)
	guesses, comps := a.inferSource(name, times, episodes, window)
	if guesses != nil {
		out["guesses"] = guesses
	}
	if comps != nil {
		out["companions"] = comps
	}
	if a.Intel != nil {
		out["owner"] = a.Intel.TypeOf(name)
		if c := a.Intel.Category(name); c.Service != "" {
			out["service"] = c
		}
	}
	out["timeline"] = a.timeline(name, at, episodes[0], window)
	writeJSON(w, http.StatusOK, out)
}

// timeline lists the device's lookups around the one analyzed, A and
// AAAA of a name in the same second as one row.
func (a *API) timeline(name string, at int64, es []analytics.Entry, window time.Duration) []timelineRow {
	rows := []timelineRow{}
	idx := map[string]int{}
	risk := map[string]*threat.Risk{}
	for _, e := range slices.Backward(es) { // oldest first
		dt := float64(e.T-at) / 1e6
		if math.Abs(dt) > window.Seconds() {
			continue
		}
		n := filter.Normalize(e.Name)
		k := n + "@" + strconv.FormatInt(e.T/1e6, 10) + e.Result
		if i, ok := idx[k]; ok {
			if !slices.Contains(rows[i].Types, e.Type) {
				rows[i].Types = append(rows[i].Types, e.Type)
			}
			continue
		}
		idx[k] = len(rows)
		row := timelineRow{T: e.T, DT: math.Round(dt*10) / 10, Name: n, Types: []string{e.Type}, Result: e.Result, Target: n == name}
		if g := a.groupOf(n); !g.skip {
			row.Group = g.label
		}
		if a.Intel != nil {
			rk, ok := risk[n]
			if !ok {
				if s := a.Intel.Score(n); s.Score > 0 {
					s.Parts = nil
					rk = &s
				}
				risk[n] = rk
			}
			row.Risk = rk
		}
		rows = append(rows, row)
	}
	// Keep the rows nearest the lookup.
	for len(rows) > analyzeTimeline {
		if math.Abs(rows[0].DT) > math.Abs(rows[len(rows)-1].DT) {
			rows = rows[1:]
		} else {
			rows = rows[:len(rows)-1]
		}
	}
	return rows
}
