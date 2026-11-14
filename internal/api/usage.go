package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/usage"
)

// The weekly anonymous usage summary: whether to send it, and exactly
// what it holds. Admins only.

func (a *API) usageRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/usage", a.authed(store.PermCluster, a.getUsage))
	m.HandleFunc("PUT /api/v1/usage", a.authed(store.PermCluster, a.putUsage))
}

type usageView struct {
	// Choice is "" (not asked yet), "yes" or "no". AskAgain: they said
	// yes to an older, smaller summary, so it isn't sent until they
	// look again.
	Choice   string `json:"choice"`
	AskAgain bool   `json:"ask_again,omitempty"`
	// Off: DNSERV_USAGE_REPORT=off on this server stops it whatever the
	// choice.
	Off      bool            `json:"off,omitempty"`
	By       string          `json:"by,omitempty"`
	At       *time.Time      `json:"at,omitempty"`
	SentAt   *time.Time      `json:"sent_at,omitempty"`
	Last     json.RawMessage `json:"last,omitempty"`
	Preview  *usage.Report   `json:"preview,omitempty"`
	URL      string          `json:"url"`
	Schema   int             `json:"schema"`
	Fields   []string        `json:"features"`
	Problems string          `json:"preview_error,omitempty"`
}

func (a *API) getUsage(w http.ResponseWriter, r *http.Request, p *Principal) {
	u := a.Store.State().Usage
	v := usageView{Choice: u.Choice, By: u.By, Last: u.Last, URL: usage.DefaultURL, Schema: usage.Schema, Fields: usage.Features}
	if u.Choice == "yes" && u.Schema < usage.Schema {
		v.Choice, v.AskAgain = "", true
	}
	if !u.At.IsZero() {
		v.At = &u.At
	}
	if !u.SentAt.IsZero() {
		v.SentAt = &u.SentAt
	}
	if a.Usage != nil {
		v.Off = a.Usage.Off
		if a.Usage.URL != "" {
			v.URL = a.Usage.URL
		}
		if r.URL.Query().Get("preview") != "" {
			if rep, err := a.Usage.Preview(r.Context()); err != nil {
				v.Problems = err.Error()
			} else {
				v.Preview = &rep
			}
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) putUsage(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Send *bool `json:"send"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Send == nil {
		writeErr(w, http.StatusBadRequest, "send must be true or false")
		return
	}
	if _, ok := a.apply(w, a.stamp(store.NewCommand(store.OpUsageChoice, p.Actor(), store.UsageChoice{Send: *req.Send, Schema: usage.Schema}))); !ok {
		return
	}
	a.getUsage(w, r, p)
}

// UsageStats gathers what the weekly summary needs from the whole
// cluster: last 7 days of totals and answer times, and which features
// are on. Nothing here names a domain, device, address or server.
func (a *API) UsageStats(ctx context.Context) (usage.Stats, error) {
	st := a.Store.State()
	eff := a.Effective()
	var s usage.Stats
	for _, n := range st.Cluster.Nodes {
		if n.Witness {
			s.Witnesses++
		} else {
			s.Servers++
		}
	}
	if s.Servers == 0 {
		s.Servers = 1
	}
	s.UpstreamMode = eff.Upstream.Mode
	for _, l := range eff.Filtering.Lists {
		if l.Enabled {
			s.Lists++
		}
	}

	to := time.Now().UTC().Truncate(time.Hour)
	from := to.Add(-7 * 24 * time.Hour)
	if sum, _, err := a.ask(ctx, analytics.Query{Kind: analytics.KindSummary, From: from, To: to, Step: 86400}, 10*time.Second); err == nil {
		if c := sum.Counts; c != nil {
			s.Lookups7d, s.Blocked7d, s.Failed7d = c.Total, c.Blocked, c.Failed
		}
		seen := map[string]bool{}
		for _, c := range sum.Clients {
			if d := st.DeviceByAddr(c); d != nil {
				seen["d:"+d.ID] = true
			} else {
				seen[c] = true
			}
		}
		s.Devices = len(seen)
	} else {
		return s, err
	}
	if perf, _, err := a.ask(ctx, analytics.Query{Kind: analytics.KindPerf, From: from, To: to, Step: 86400, Limit: 1}, 10*time.Second); err == nil && perf.Perf != nil {
		v := analytics.Report(perf.Perf, 86400, 7*24).Summary
		s.P50, s.P95, s.CacheHit = v.P50, v.P95, v.CacheHit
	}

	on := func(b bool, name string) {
		if b {
			s.Features = append(s.Features, name)
		}
	}
	passkeys := false
	for _, u := range st.Users {
		if len(u.Passkeys) > 0 {
			passkeys = true
		}
	}
	schedules := false
	for _, g := range st.Groups {
		if len(g.Schedules) > 0 {
			schedules = true
		}
	}
	on(st.HTTPS.Mode != "", "https")
	on(st.Backup.Configured(), "backups")
	on(st.BackupS3 != nil, "backups_s3")
	on(st.BackupSMB != nil, "backups_smb")
	on(passkeys, "passkeys")
	on(len(st.Groups) > 0, "groups")
	on(schedules, "schedules")
	on(len(eff.Filtering.BlockedServices) > 0, "blocked_services")
	on(eff.Filtering.SafeSearch, "safe_search")
	on(eff.Filtering.BlockBypass, "block_bypass")
	on(len(eff.DNS.Records) > 0, "local_names")
	on(eff.History.Days > 0, "query_history")
	on(eff.Analytics.ThreatFeeds, "threat_feeds")
	on(st.Updates.Auto, "auto_updates")
	return s, nil
}
