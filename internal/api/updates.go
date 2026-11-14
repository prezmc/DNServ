package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/update"
)

// Updates: is a newer DNServ out, what changed, which servers run what,
// and installing it (one server at a time) where the updater is set up.
// Admins only (cluster.manage), since it restarts servers.

func (a *API) updateRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/updates", a.authed(store.PermCluster, a.getUpdates))
	m.HandleFunc("POST /api/v1/updates/check", a.authed(store.PermCluster, a.checkUpdates))
	m.HandleFunc("POST /api/v1/updates/install", a.authed(store.PermCluster, a.installUpdate))
	m.HandleFunc("POST /api/v1/updates/rollback", a.authed(store.PermCluster, a.rollBack))
	m.HandleFunc("PUT /api/v1/updates/prefs", a.authed(store.PermCluster, a.putUpdatePrefs))
}

type updatesView struct {
	Latest     *update.Release   `json:"latest,omitempty"`
	CheckedAt  *time.Time        `json:"checked_at,omitempty"`
	CheckError string            `json:"check_error,omitempty"`
	Changes    *update.Changes   `json:"changes,omitempty"`
	Nodes      []update.NodeInfo `json:"nodes"`
	// Available: some server runs an older version than Latest.
	Available bool `json:"available"`
	// CanInstall: some server that's behind has an updater.
	CanInstall bool `json:"can_install"`
	// Skipped: the newest version is one someone rolled back from.
	Skipped bool `json:"skipped,omitempty"`
	// CanRollBack: the last update can be undone.
	CanRollBack bool `json:"can_rollback"`
	// BackupsOn: a backup is made before every update.
	BackupsOn bool              `json:"backups_on"`
	Rollout   *update.Rollout   `json:"rollout,omitempty"`
	Prefs     store.UpdatePrefs `json:"prefs"`
}

func (a *API) updatesView(r *http.Request) updatesView {
	st := a.Store.State()
	v := updatesView{Nodes: []update.NodeInfo{}, Prefs: st.Updates, BackupsOn: st.Backup.Configured()}
	if a.Updates == nil {
		return v
	}
	rel, at, errMsg := a.Updates.Latest()
	v.Latest, v.CheckError = rel, errMsg
	if !at.IsZero() {
		v.CheckedAt = &at
	}
	v.Nodes = a.Updates.Nodes(r.Context())
	for _, n := range v.Nodes {
		if n.Behind {
			v.Available = true
			if n.Updater != nil && !n.Updater.Pinned {
				v.CanInstall = true
			}
		}
	}
	if v.Available {
		v.Changes = a.Updates.Changes(r.Context())
	}
	v.Skipped = rel != nil && rel.Revision == st.Updates.Skip
	v.Rollout = a.Updates.Rollout()
	v.CanRollBack = a.Updates.CanRollBack()
	return v
}

func (a *API) getUpdates(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, a.updatesView(r))
}

func (a *API) checkUpdates(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Updates == nil {
		writeErr(w, http.StatusNotImplemented, "updates aren't available on this server")
		return
	}
	if _, err := a.Updates.Check(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, "couldn't check for a new version: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a.updatesView(r))
}

func (a *API) installUpdate(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Nodes []string `json:"nodes"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if a.Updates == nil {
		writeErr(w, http.StatusNotImplemented, "updates aren't available on this server")
		return
	}
	if _, err := a.Updates.Install(r.Context(), p.Actor(), req.Nodes, false); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, update.ErrNothingToDo) && a.Updates.Rollout() == nil {
			status = http.StatusBadGateway
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, a.updatesView(r))
}

func (a *API) rollBack(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Updates == nil {
		writeErr(w, http.StatusNotImplemented, "updates aren't available on this server")
		return
	}
	if _, err := a.Updates.RollBack(r.Context(), p.Actor()); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, a.updatesView(r))
}

func (a *API) putUpdatePrefs(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req store.UpdatePrefs
	if !readJSON(w, r, &req) {
		return
	}
	if _, ok := a.apply(w, a.stamp(store.NewCommand(store.OpUpdatePrefs, p.Actor(), req))); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.Store.State().Updates)
}
