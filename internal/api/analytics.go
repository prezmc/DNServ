package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
	"github.com/prezmc/dnserv/internal/virustotal"
)

// PeerAnalytics is the cluster RPC name for analytics queries.
const PeerAnalytics = "analytics"

func (a *API) analyticsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/analytics/summary", a.authed(store.PermDashboard, a.analyticsSummary))
	m.HandleFunc("GET /api/v1/analytics/top", a.authed(store.PermDashboard, a.analyticsTop))
	m.HandleFunc("GET /api/v1/analytics/performance", a.authed(store.PermDashboard, a.analyticsPerformance))
	m.HandleFunc("GET /api/v1/analytics/domain", a.authed(store.PermDashboard, a.analyticsDomain))
	m.HandleFunc("GET /api/v1/analytics/queries", a.authed(store.PermQueryLog, a.analyticsQueries))
	m.HandleFunc("GET /api/v1/analytics/export", a.authed(store.PermExport, a.analyticsExport))
	m.HandleFunc("GET /api/v1/analytics/alsoon", a.authed(store.PermDashboard, a.analyticsAlsoOn))
	m.HandleFunc("POST /api/v1/analytics/virustotal", a.authed(store.PermDashboard, a.virusTotalLookup))
	m.HandleFunc("GET /api/v1/virustotal", a.authed(store.PermDashboard, a.virusTotalStatus))
	m.HandleFunc("PUT /api/v1/virustotal", a.authed(store.PermLists, a.virusTotalSetKey))
	m.HandleFunc("PUT /api/v1/abusech", a.authed(store.PermLists, a.abuseCHSetKey))
	m.HandleFunc("GET /api/v1/analytics/risky", a.authed(store.PermDashboard, a.analyticsRisky))
	m.HandleFunc("GET /api/v1/analytics/intel", a.authed(store.PermDashboard, a.intelStatus))
}

// PeerHandler answers another node's analytics query from this node's
// history. Register it with the cluster under PeerAnalytics.
func (a *API) PeerHandler(ctx context.Context, body json.RawMessage) (any, error) {
	var q analytics.Query
	if err := json.Unmarshal(body, &q); err != nil {
		return nil, err
	}
	if a.Analytics == nil {
		return &analytics.Result{}, nil
	}
	return a.Analytics.Run(ctx, q)
}

// nodeAnswer says whether a node's history is in the result.
type nodeAnswer struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Counts are this server's own totals for the query, so the dashboard
	// can show which server answered what. Set for kinds that count.
	Counts *analytics.Counts `json:"counts,omitempty"`
}

// ranges are the presets the dashboard offers: span and bucket size.
var ranges = map[string]struct {
	span time.Duration
	step int64
}{
	"1h":  {time.Hour, 300},
	"24h": {24 * time.Hour, 3600},
	"7d":  {7 * 24 * time.Hour, 6 * 3600},
	"30d": {30 * 24 * time.Hour, 86400},
	"90d": {90 * 24 * time.Hour, 86400},
}

// parseQuery reads the range, device and limit shared by every view.
func (a *API) parseQuery(w http.ResponseWriter, r *http.Request, p *Principal, kind string) (analytics.Query, bool) {
	v := r.URL.Query()
	q := analytics.Query{Kind: kind}
	rg, ok := ranges[v.Get("range")]
	if v.Get("range") == "" {
		rg, ok = ranges["24h"], true
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "range must be 1h, 24h, 7d, 30d or 90d")
		return q, false
	}
	loc, _ := a.zone()
	now := a.now()
	q.To, q.From, q.Step = now, now.Add(-rg.span), rg.step
	if rg.step >= 3600 {
		// Whole hours, so the hourly totals line up; whole local days for
		// daily buckets.
		_, off := now.In(loc).Zone()
		q.Offset = int64(off)
		q.From = time.Unix((q.From.Unix()+q.Offset)/rg.step*rg.step-q.Offset, 0)
	}
	if c := v.Get("client"); c != "" {
		if !p.Can(store.PermQueryLog) {
			writeErr(w, http.StatusForbidden, "you don't have permission to see individual devices")
			return q, false
		}
		addrs, err := a.clientAddrs(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return q, false
		}
		q.Clients = addrs
	}
	if n, err := strconv.Atoi(v.Get("limit")); err == nil && n > 0 {
		q.Limit = n
	}
	return q, true
}

// clientAddrs turns a device id or IP into the addresses to look for.
func (a *API) clientAddrs(c string) ([]string, error) {
	if d, ok := a.Store.State().Devices[c]; ok {
		return slices.Clone(d.Addrs), nil
	}
	ip, err := netip.ParseAddr(c)
	if err != nil {
		return nil, errors.New("client must be an IP address or device id")
	}
	return []string{ip.Unmap().String()}, nil
}

// ask runs a query on this node and every peer, and merges the answers.
func (a *API) ask(ctx context.Context, q analytics.Query, timeout time.Duration) (*analytics.Result, []nodeAnswer, error) {
	if err := q.Validate(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var (
		parts []*analytics.Result
		nodes []nodeAnswer
		mu    sync.Mutex
		wg    sync.WaitGroup
	)
	self := "this server"
	if a.Cluster != nil {
		self = a.Cluster.Name()
	}
	if a.Analytics != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.Analytics.Run(ctx, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				nodes = append(nodes, nodeAnswer{Name: self, Error: err.Error()})
				return
			}
			parts = append(parts, res)
			nodes = append(nodes, nodeAnswer{Name: self, OK: true, Counts: res.Counts})
		}()
	}
	if a.Cluster != nil {
		// Ask peers for more than we show, so merged top lists are right
		// when a domain is near the cut-off on one node.
		pq := q
		if q.Kind == analytics.KindTop && q.Limit < 500 {
			pq.Limit = min(q.Limit*3, 500)
		}
		for _, rep := range a.Cluster.AskPeers(ctx, PeerAnalytics, pq) {
			n := nodeAnswer{Name: rep.Name}
			var res analytics.Result
			switch {
			case rep.Err != nil:
				n.Error = rep.Err.Error()
			case json.Unmarshal(rep.Body, &res) != nil:
				n.Error = "sent an answer this server doesn't understand"
			default:
				n.OK = true
				n.Counts = res.Counts
				mu.Lock()
				parts = append(parts, &res)
				mu.Unlock()
			}
			mu.Lock()
			nodes = append(nodes, n)
			mu.Unlock()
		}
	}
	wg.Wait()
	slices.SortFunc(nodes, func(x, y nodeAnswer) int {
		if x.Name == self {
			return -1
		}
		if y.Name == self {
			return 1
		}
		return strings.Compare(x.Name, y.Name)
	})
	return analytics.Merge(q, parts), nodes, nil
}

func (a *API) askOrFail(w http.ResponseWriter, r *http.Request, q analytics.Query) (*analytics.Result, []nodeAnswer, bool) {
	res, nodes, err := a.ask(r.Context(), q, 4*time.Second)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, analytics.ErrBadQuery) {
			status = http.StatusBadRequest
		}
		writeErr(w, status, err.Error())
		return nil, nil, false
	}
	return res, nodes, true
}

// labeler names clients: the device name, else the router's name for it.
type labeler struct {
	a      *API
	st     *store.State
	names  map[string]string
	device map[string]string // address -> device id
}

func (a *API) newLabeler(ctx context.Context, addrs []string) *labeler {
	l := &labeler{a: a, st: a.Store.State(), names: map[string]string{}, device: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var ask []netip.Addr
	for _, ad := range addrs {
		if _, done := l.names[ad]; done {
			continue
		}
		l.names[ad] = ""
		if d := l.st.DeviceByAddr(ad); d != nil {
			l.names[ad], l.device[ad] = d.Name, d.ID
		} else if ip, err := netip.ParseAddr(ad); err == nil {
			ask = append(ask, ip)
		}
	}
	// Router names, in parallel with a short deadline.
	for _, ip := range ask {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := a.hostname(ctx, ip)
			mu.Lock()
			l.names[ip.String()] = n
			mu.Unlock()
		}()
	}
	wg.Wait()
	return l
}

// domainStatus says how the filter treats a domain right now, so the UI
// can offer Block, Allow or Undo.
type domainStatus struct {
	Blocked bool   `json:"blocked"`
	Allowed bool   `json:"allowed"`
	Custom  bool   `json:"custom,omitempty"` // by the owner's own rule
	Rule    string `json:"rule,omitempty"`
	List    string `json:"list,omitempty"`
}

func (a *API) statusOf(name string) domainStatus {
	if a.CheckDomain == nil {
		return domainStatus{}
	}
	m := a.CheckDomain(name)
	s := domainStatus{Blocked: m.Blocked, Allowed: m.Allowed}
	if m.Blocked || m.Allowed {
		s.Rule, s.List, s.Custom = m.Rule.Text(), m.Source, m.Source == "Custom rules"
	}
	return s
}

func (a *API) analyticsSummary(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindSummary)
	if !ok {
		return
	}
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	// Count devices, not addresses: a named device may have several.
	st := a.Store.State()
	seen := map[string]bool{}
	for _, c := range res.Clients {
		if d := st.DeviceByAddr(c); d != nil {
			seen["d:"+d.ID] = true
		} else {
			seen[c] = true
		}
	}
	counts := res.Counts
	if counts == nil {
		counts = &analytics.Counts{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": q.From.UTC(), "to": q.To.UTC(), "step": q.Step,
		"counts": counts, "series": orEmpty(res.Series), "devices": len(seen),
		"detail": res.Detail, "stats": res.Stats, "nodes": nodes,
	})
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// topRow is a top-list entry for the UI.
type topRow struct {
	analytics.Row
	Label    string        `json:"label,omitempty"`  // clients: device or router name
	DeviceID string        `json:"device,omitempty"` // clients: named device
	Addrs    []string      `json:"addrs,omitempty"`  // clients
	Now      *domainStatus `json:"now,omitempty"`    // domains: how it's treated now
	Risk     *threat.Risk  `json:"risk,omitempty"`   // domains: when there is any
	Type     *threat.Type  `json:"type,omitempty"`   // domains: when known
}

// withFlag raises a name's risk to what its answers showed.
func withFlag(r threat.Risk, f *analytics.Flag) threat.Risk {
	if f == nil {
		return r
	}
	r.Reasons = append(r.Reasons, f.Reason)
	if f.Score > r.Score {
		r.Score = f.Score
		r.Level = threat.Level(r.Score)
	}
	return r
}

// describe adds risk and type to a domain row.
func (a *API) describe(t *topRow) {
	if a.Intel == nil {
		return
	}
	if r := a.Intel.Score(t.Key); r.Score > 0 {
		t.Risk = &r
	}
	t.Type = a.Intel.TypeOf(t.Key)
}

func (a *API) analyticsTop(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindTop)
	if !ok {
		return
	}
	q.By = r.URL.Query().Get("by")
	if q.By == analytics.TopClients && !p.Can(store.PermQueryLog) {
		writeErr(w, http.StatusForbidden, "you don't have permission to see individual devices")
		return
	}
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	out := []*topRow{}
	if q.By == analytics.TopClients {
		keys := make([]string, len(res.Rows))
		for i, row := range res.Rows {
			keys[i] = row.Key
		}
		l := a.newLabeler(r.Context(), keys)
		byDevice := map[string]*topRow{}
		for _, row := range res.Rows {
			if id := l.device[row.Key]; id != "" {
				if cur, ok := byDevice[id]; ok {
					cur.Total += row.Total
					cur.Blocked += row.Blocked
					cur.Addrs = append(cur.Addrs, row.Key)
					continue
				}
				t := &topRow{Row: row, Label: l.names[row.Key], DeviceID: id, Addrs: []string{row.Key}}
				t.Key = id
				byDevice[id] = t
				out = append(out, t)
				continue
			}
			out = append(out, &topRow{Row: row, Label: l.names[row.Key], Addrs: []string{row.Key}})
		}
		slices.SortStableFunc(out, func(x, y *topRow) int { return int(y.Total - x.Total) })
	} else if q.By == analytics.TopLists {
		for _, row := range res.Rows {
			out = append(out, &topRow{Row: row})
		}
	} else {
		for _, row := range res.Rows {
			s := a.statusOf(row.Key)
			t := &topRow{Row: row, Now: &s}
			a.describe(t)
			out = append(out, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": out, "detail": res.Detail, "stats": res.Stats, "nodes": nodes})
}

func (a *API) analyticsDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindDomain)
	if !ok {
		return
	}
	q.Name = filter.Normalize(strings.TrimSpace(r.URL.Query().Get("name")))
	if q.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	q.Limit = 50
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	out := map[string]any{
		"name": q.Name, "from": q.From.UTC(), "to": q.To.UTC(), "step": q.Step,
		"counts": res.Counts, "series": orEmpty(res.Series), "now": a.statusOf(q.Name),
		"detail": res.Detail, "stats": res.Stats, "nodes": nodes,
	}
	if a.Intel != nil {
		var f *analytics.Flag
		if len(res.Flags) > 0 {
			f = &res.Flags[0]
		}
		out["risk"], out["type"] = withFlag(a.Intel.Score(q.Name), f), a.Intel.TypeOf(q.Name)
	}
	out["answers"] = orEmpty(res.Answers)
	if res.Rule != "" || res.List != "" {
		out["caught_by"] = map[string]string{"rule": res.Rule, "list": res.List}
	}
	if res.First != 0 {
		out["first_seen"], out["last_seen"] = time.Unix(res.First, 0).UTC(), time.Unix(res.Last, 0).UTC()
	}
	// Which devices asked is per-device detail.
	if p.Can(store.PermQueryLog) {
		keys := make([]string, len(res.Rows))
		for i, row := range res.Rows {
			keys[i] = row.Key
		}
		l := a.newLabeler(r.Context(), keys)
		devs := []topRow{}
		for _, row := range res.Rows {
			devs = append(devs, topRow{Row: row, Label: l.names[row.Key], DeviceID: l.device[row.Key], Addrs: []string{row.Key}})
		}
		out["devices"] = devs
	}
	writeJSON(w, http.StatusOK, out)
}

// analyticsAlsoOn lists the enabled lists with a rule for a name. It
// reads the saved list files, so it runs only when someone opens a domain.
func (a *API) analyticsAlsoOn(w http.ResponseWriter, r *http.Request, p *Principal) {
	name := filter.Normalize(strings.TrimSpace(r.URL.Query().Get("name")))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if a.AlsoOn == nil {
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "lists": []filter.ListHit{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	hits := a.AlsoOn(ctx, name)
	if hits == nil {
		hits = []filter.ListHit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "lists": hits, "partial": ctx.Err() != nil})
}

func (a *API) virusTotalStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"configured": a.VirusTotal != nil && a.VirusTotal.Configured()})
}

// virusTotalSetKey stores (or, empty, removes) the owner's VirusTotal key.
// The key is never returned.
func (a *API) virusTotalSetKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Key = strings.TrimSpace(in.Key)
	if len(in.Key) > 128 || strings.ContainsAny(in.Key, " \t\r\n") {
		writeErr(w, http.StatusBadRequest, "that doesn't look like a VirusTotal API key")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpVirusTotalKey, p.Actor(), store.VirusTotalKey{Key: in.Key})); !ok {
		return
	}
	if a.VirusTotal != nil {
		a.VirusTotal.Forget()
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": in.Key != ""})
}

// virusTotalLookup asks VirusTotal about one domain. It runs only when
// someone clicks the button; nothing is sent otherwise.
func (a *API) virusTotalLookup(w http.ResponseWriter, r *http.Request, p *Principal) {
	name := filter.Normalize(strings.TrimSpace(r.URL.Query().Get("name")))
	if name == "" || !strings.Contains(name, ".") {
		writeErr(w, http.StatusBadRequest, "a domain name is required")
		return
	}
	if a.VirusTotal == nil {
		writeErr(w, http.StatusConflict, virustotal.ErrNoKey.Error())
		return
	}
	rep, cached, err := a.VirusTotal.Lookup(r.Context(), name)
	switch {
	case errors.Is(err, virustotal.ErrNoKey):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, virustotal.ErrBusy):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		writeErr(w, http.StatusBadGateway, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"report": rep, "cached": cached})
	}
}

func (a *API) searchQuery(w http.ResponseWriter, r *http.Request, p *Principal) (analytics.Query, bool) {
	q, ok := a.parseQuery(w, r, p, analytics.KindSearch)
	if !ok {
		return q, false
	}
	v := r.URL.Query()
	q.Name, q.Result = v.Get("search"), v.Get("result")
	q.Before, _ = strconv.ParseInt(v.Get("before"), 10, 64)
	return q, true
}

func (a *API) analyticsQueries(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.searchQuery(w, r, p)
	if !ok {
		return
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	q.Limit = min(q.Limit, 1000)
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	addrs := make([]string, len(res.Entries))
	for i, e := range res.Entries {
		addrs[i] = e.Client
	}
	l := a.newLabeler(r.Context(), addrs)
	// Flag risky domains so the log can mark them.
	risk := map[string]threat.Risk{}
	if a.Intel != nil {
		for _, e := range res.Entries {
			if _, done := risk[e.Name]; !done {
				risk[e.Name] = a.Intel.Score(e.Name)
			}
			// What this answer pointed to, as the history writer checks it.
			if len(e.IPs)+len(e.CNAMEs) > 0 {
				var ips []netip.Addr
				for _, s := range e.IPs {
					if ip, err := netip.ParseAddr(s); err == nil {
						ips = append(ips, ip)
					}
				}
				if sc, why := a.Intel.CheckAnswer(e.Name, ips, e.CNAMEs); sc > risk[e.Name].Score {
					risk[e.Name] = withFlag(risk[e.Name], &analytics.Flag{Name: e.Name, Reason: why, Score: sc})
				}
			}
		}
		maps.DeleteFunc(risk, func(_ string, r threat.Risk) bool { return r.Score < threat.Medium })
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queries": orEmpty(res.Entries), "device_names": l.names, "risk": risk,
		"detail": res.Detail, "nodes": nodes,
	})
}

// maxExport bounds a CSV export.
const maxExport = 50000

func (a *API) analyticsExport(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.Can(store.PermQueryLog) {
		writeErr(w, http.StatusForbidden, "exporting queries also needs permission to see the query log")
		return
	}
	q, ok := a.searchQuery(w, r, p)
	if !ok {
		return
	}
	if q.Limit == 0 {
		q.Limit = maxExport
	}
	q.Limit = min(q.Limit, maxExport)
	res, _, err := a.ask(r.Context(), q, 15*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	addrs := make([]string, len(res.Entries))
	for i, e := range res.Entries {
		addrs[i] = e.Client
	}
	l := a.newLabeler(r.Context(), addrs)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dnserv-queries-`+a.now().Format("2006-01-02-1504")+`.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "server", "client", "device", "domain", "type", "result", "allowed_by_rule", "rcode", "answers", "ms", "rule", "list", "risk"})
	scores := map[string]string{}
	for _, e := range res.Entries {
		sc, ok := scores[e.Name]
		if !ok && a.Intel != nil {
			sc = strconv.Itoa(a.Intel.Score(e.Name).Score)
			scores[e.Name] = sc
		}
		cw.Write([]string{e.Time, e.Node, e.Client, csvSafe(l.names[e.Client]), e.Name, e.Type, e.Result, strconv.FormatBool(e.Allowed),
			e.Rcode, strconv.Itoa(e.Answers), strconv.FormatFloat(e.Ms, 'f', 2, 64), csvSafe(e.Rule), csvSafe(e.List), sc})
	}
	cw.Flush()
}

// csvSafe stops spreadsheet apps from running a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// analyticsRisky lists the riskiest domains devices looked up in the
// period, across every node.
func (a *API) analyticsRisky(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindTop)
	if !ok {
		return
	}
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	// Every domain seen (up to a generous cap), scored here.
	q.By, q.Limit, q.Flags = analytics.TopDomains, 20000, true
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	out := []*topRow{}
	var queries int64
	if a.Intel != nil {
		flags := map[string]*analytics.Flag{}
		for i := range res.Flags {
			flags[res.Flags[i].Name] = &res.Flags[i]
		}
		for _, row := range res.Rows {
			risk := withFlag(a.Intel.Score(row.Key), flags[row.Key])
			if risk.Score < threat.Medium {
				continue
			}
			queries += row.Total
			s := a.statusOf(row.Key)
			out = append(out, &topRow{Row: row, Now: &s, Risk: &risk, Type: a.Intel.TypeOf(row.Key)})
		}
	}
	slices.SortStableFunc(out, func(x, y *topRow) int {
		if x.Risk.Score != y.Risk.Score {
			return y.Risk.Score - x.Risk.Score
		}
		return int(y.Total - x.Total)
	})
	domains := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rows": out, "domains": domains, "queries": queries,
		"feeds": a.Intel != nil && a.Intel.Enabled(), "nodes": nodes,
	})
}

func (a *API) intelStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Intel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "sources": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": a.Intel.Enabled(), "sources": a.Intel.Status(),
		"abusech_key": a.Store.State().AbuseCHKey != ""})
}

// abuseCHSetKey stores (or, empty, removes) the abuse.ch Auth-Key for the
// URLhaus and ThreatFox feeds. The key is never returned.
func (a *API) abuseCHSetKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Key = strings.TrimSpace(in.Key)
	if len(in.Key) > 128 || strings.ContainsAny(in.Key, " \t\r\n/?#%") {
		writeErr(w, http.StatusBadRequest, "that doesn't look like an abuse.ch Auth-Key")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpAbuseCHKey, p.Actor(), store.AbuseCHKey{Key: in.Key})); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": in.Key != ""})
}
