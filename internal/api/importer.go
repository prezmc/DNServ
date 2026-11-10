package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prezmc/dnserve/internal/adguard"
	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/store"
)

// imports holds what was read from AdGuard Home between the preview and
// the import, so the password is used once and never kept.
type imports struct {
	mu sync.Mutex
	m  map[string]*pendingImport
}

type pendingImport struct {
	user string
	snap *adguard.Snapshot
	at   time.Time
}

const importTTL = 30 * time.Minute

func (a *API) importRoutes(m *http.ServeMux) {
	// Admin only: an import touches every part of the settings.
	m.HandleFunc("POST /api/v1/import/adguard/preview", a.authed(store.PermUsers, a.adguardPreview))
	m.HandleFunc("POST /api/v1/import/adguard/apply", a.authed(store.PermUsers, a.adguardApply))
}

// fetchAdGuard can be replaced in tests.
var fetchAdGuard = adguard.Fetch

func (a *API) adguardPreview(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		URL      string
		Username string
		Password string
		Insecure bool
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	snap, err := fetchAdGuard(ctx, adguard.Conn{URL: req.URL, Username: req.Username, Password: req.Password, Insecure: req.Insecure})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	id := auth.RandomID(12)
	a.imp.mu.Lock()
	if a.imp.m == nil {
		a.imp.m = map[string]*pendingImport{}
	}
	for k, v := range a.imp.m {
		if a.now().Sub(v.at) > importTTL || v.user == p.User.ID {
			delete(a.imp.m, k)
		}
	}
	a.imp.m[id] = &pendingImport{user: p.User.ID, snap: snap, at: a.now()}
	a.imp.mu.Unlock()
	a.Log.Info("read AdGuard Home settings for import", "source", snap.Source, "version", snap.Version, "by", p.Actor())
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "plan": adguard.Build(snap, a.Store.State(), a.Effective(), nil)})
}

// importResult counts what an import changed.
type importResult struct {
	Lists      int    `json:"lists"`
	Allowlists int    `json:"allowlists"`
	Rules      int    `json:"rules"`
	Records    int    `json:"records"`
	Devices    int    `json:"devices"`
	Groups     int    `json:"groups"`
	Settings   int    `json:"settings"` // upstream, router, blocking, access
	Summary    string `json:"summary"`
}

func (a *API) adguardApply(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		ID       string
		Sections []string
		Exclude  []string // item ids left out
	}
	if !readJSON(w, r, &req) {
		return
	}
	a.imp.mu.Lock()
	pi := a.imp.m[req.ID]
	if pi != nil && (pi.user != p.User.ID || a.now().Sub(pi.at) > importTTL) {
		pi = nil
	}
	a.imp.mu.Unlock()
	if pi == nil {
		writeErr(w, http.StatusGone, "this preview has expired; connect to AdGuard Home again")
		return
	}
	sel := map[string]bool{}
	for _, s := range req.Sections {
		sel[s] = true
	}
	ex := map[string]bool{}
	for _, id := range req.Exclude {
		ex[id] = true
	}
	// Plan again against the state now, so nothing is added twice.
	plan := adguard.Build(pi.snap, a.Store.State(), a.Effective(), ex)
	patch := plan.Patch(sel)
	if patch.Rules != nil {
		for _, rule := range *patch.Rules {
			if _, ok, _ := filter.ParseLine(rule); !ok {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("rule %q isn't supported", rule))
				return
			}
		}
	}
	if patch.Records != nil {
		recs, err := config.NormalizeRecords(*patch.Records)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		patch.Records = &recs
	}
	next := a.Store.State().Settings
	next.Merge(patch)
	if err := next.Overlay(a.Base).Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var res importResult
	count := func(key string) int {
		if !sel[key] {
			return 0
		}
		if s := plan.Section(key); s != nil {
			return len(s.Items)
		}
		return 0
	}
	res.Lists, res.Allowlists, res.Rules, res.Records = count(adguard.KeyLists), count(adguard.KeyAllowlists), count(adguard.KeyRules), count(adguard.KeyRecords)
	res.Settings = count(adguard.KeyUpstream) + count(adguard.KeyLocalDNS) + count(adguard.KeyBlocking) + count(adguard.KeyAccess)
	partial := func(err error) {
		a.writeStoreErr(w, fmt.Errorf("%w (part of the import was saved; running it again adds only what's missing)", err))
	}

	// Groups first, so devices can join them.
	groupIDs := make([]string, len(plan.Groups))
	if sel[adguard.KeyGroups] {
		for i, g := range plan.Groups {
			id := auth.RandomID(9)
			if _, err := a.Store.Apply(store.NewCommand(store.OpGroupSave, p.Actor(), store.Group{ID: id, Name: g.Name, SkipBlocklists: g.SkipBlocklists, Rules: g.Rules})); err != nil {
				partial(err)
				return
			}
			groupIDs[i] = id
			res.Groups++
		}
	}
	for _, d := range plan.Devices {
		group := ""
		if d.Group >= 0 {
			group = groupIDs[d.Group]
		}
		if d.Existing != "" {
			old := a.Store.State().Devices[d.Existing]
			if group == "" || old == nil || old.Group != "" {
				continue
			}
			nd := *old
			nd.Group = group
			if _, err := a.Store.Apply(store.NewCommand(store.OpDeviceSave, p.Actor(), nd)); err != nil {
				partial(err)
				return
			}
			continue
		}
		// A device with its own group is created with the group even if
		// device names weren't chosen.
		if !sel[adguard.KeyDevices] && group == "" {
			continue
		}
		if _, err := a.Store.Apply(store.NewCommand(store.OpDeviceSave, p.Actor(), store.Device{ID: auth.RandomID(9), Name: d.Name, Addrs: d.Addrs, Group: group})); err != nil {
			partial(err)
			return
		}
		res.Devices++
	}
	if up, nw, lists, rules := patch.Touches(); up || nw || lists || rules {
		if _, err := a.Store.Apply(store.NewCommand(store.OpSettingsUpdate, p.Actor(), patch)); err != nil {
			partial(err)
			return
		}
	}
	res.Summary = importSummary(res)
	a.imp.mu.Lock()
	delete(a.imp.m, req.ID)
	a.imp.mu.Unlock()
	a.Log.Info("imported from AdGuard Home", "source", pi.snap.Source, "by", p.Actor(),
		"lists", res.Lists+res.Allowlists, "rules", res.Rules, "records", res.Records, "devices", res.Devices, "groups", res.Groups)
	writeJSON(w, http.StatusOK, res)
}

// importSummary is a person-readable line about an import, for the UI.
func importSummary(r importResult) string {
	var parts []string
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, many))
		}
	}
	add(r.Lists+r.Allowlists, "list", "lists")
	add(r.Rules, "rule", "rules")
	add(r.Records, "local name", "local names")
	add(r.Devices, "device", "devices")
	add(r.Groups, "group", "groups")
	add(r.Settings, "setting", "settings")
	return strings.Join(parts, ", ")
}
