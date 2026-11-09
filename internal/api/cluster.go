package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/cluster"
	"github.com/prezmc/dnserve/internal/store"
)

func (a *API) clusterRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/cluster", a.authed(store.PermCluster, a.clusterStatus))
	m.HandleFunc("POST /api/v1/cluster/join-codes", a.authed(store.PermCluster, a.joinCode))
	m.HandleFunc("PUT /api/v1/cluster/nodes/{id}", a.authed(store.PermCluster, a.updateNode))
	m.HandleFunc("DELETE /api/v1/cluster/nodes/{id}", a.authed(store.PermCluster, a.removeNode))
	m.HandleFunc("POST /api/v1/cluster/preferred", a.authed(store.PermCluster, a.preferLeader))
	m.HandleFunc("POST /api/v1/cluster/transfer", a.authed(store.PermCluster, a.transferLeader))
	m.HandleFunc("POST /api/v1/cluster/recover", a.authed(store.PermCluster, a.forceRecover))
	m.HandleFunc("POST /api/v1/cluster/join", a.authed(store.PermCluster, a.joinOther))
	m.HandleFunc("POST /api/v1/setup/join", a.setupJoin)
}

func (a *API) needCluster(w http.ResponseWriter) bool {
	if a.Cluster == nil {
		writeErr(w, http.StatusNotFound, "clustering isn't running on this node")
		return false
	}
	return true
}

func (a *API) clusterStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !a.needCluster(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	st := a.Cluster.Status(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"cluster": st, "can_join": a.Cluster.CanJoin() == nil})
}

// joinCode makes a one-time code for adding a node. host is the address
// the dashboard was opened at; it becomes this node's cluster address
// unless the config sets one.
func (a *API) joinCode(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Host string }
	if !a.needCluster(w) || !readJSON(w, r, &req) {
		return
	}
	a.Cluster.LearnHost(req.Host)
	code, exp, err := a.Cluster.CreateJoinCode(p.Actor())
	if err != nil {
		a.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires_at": exp, "advertise": a.Cluster.Status(r.Context()).Advertise})
}

func (a *API) updateNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Name        *string
		NeverLeader *bool `json:"never_leader"`
	}
	if !a.needCluster(w) || !readJSON(w, r, &req) {
		return
	}
	n := a.Store.State().Cluster.Nodes[r.PathValue("id")]
	if n == nil {
		writeErr(w, http.StatusNotFound, "no such node")
		return
	}
	upd := *n
	if req.Name != nil {
		upd.Name = *req.Name
	}
	if req.NeverLeader != nil {
		upd.NeverLeader = *req.NeverLeader
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpClusterNode, p.Actor(), upd)); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) removeNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !a.needCluster(w) {
		return
	}
	id := r.PathValue("id")
	switch id {
	case a.Cluster.ID():
		writeErr(w, http.StatusConflict, "a node can't remove itself; remove it from another node's dashboard")
		return
	case a.Cluster.LocalStatus().LeaderID:
		writeErr(w, http.StatusConflict, "that node is the leader; move leadership to another node first")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpClusterRemove, p.Actor(), store.IDOnly{ID: id})); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) preferLeader(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ ID string }
	if !a.needCluster(w) || !readJSON(w, r, &req) {
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpClusterPreferred, p.Actor(), store.IDOnly{ID: req.ID})); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) transferLeader(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ To string }
	if !a.needCluster(w) || !readJSON(w, r, &req) {
		return
	}
	if err := a.Cluster.TransferLeadership(req.To); err != nil {
		a.writeStoreErr(w, err)
		return
	}
	a.Log.Info("leadership transferred", "actor", p.Actor(), "to", req.To)
	w.WriteHeader(http.StatusNoContent)
}

// forceRecover makes this node a cluster of one after the others are lost.
func (a *API) forceRecover(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Password   string
		AcceptRisk bool `json:"accept_risk"`
	}
	if !a.needCluster(w) || !readJSON(w, r, &req) || !a.sessionWithPassword(w, r, p, req.Password) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := a.Cluster.ForceRecover(ctx, p.Actor(), req.AcceptRisk)
	var risk *cluster.RiskError
	switch {
	case errors.As(err, &risk):
		writeJSON(w, http.StatusConflict, map[string]any{"error": risk.Error(), "risk": true, "nodes": risk.Nodes})
	case err != nil:
		writeErr(w, http.StatusConflict, err.Error())
	default:
		a.Log.Warn("forced cluster recovery", "actor", p.Actor())
		w.WriteHeader(http.StatusNoContent)
	}
}

// joinOther moves a node that is set up already (alone, or cut off from
// its cluster) into another cluster. Its own users and settings go.
func (a *API) joinOther(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		JoinCode string `json:"join_code"`
		Host     string
		Password string
	}
	if !a.needCluster(w) || !readJSON(w, r, &req) || !a.sessionWithPassword(w, r, p, req.Password) {
		return
	}
	a.doJoin(w, r, req.JoinCode, req.Host)
}

// setupJoin is the first-run alternative to creating an admin: join an
// existing cluster and take its users and settings. Like setup, it needs
// the one-time code from the container log.
func (a *API) setupJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string
		JoinCode string `json:"join_code"`
		Host     string
	}
	if !a.needCluster(w) || !readJSON(w, r, &req) {
		return
	}
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	ip := clientIP(r)
	if ok, wait := a.Throttle.Allowed("setup:" + ip); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	a.setupOnce.Lock()
	defer a.setupOnce.Unlock()
	if a.setupCode == "" || len(a.Store.State().Users) > 0 {
		writeErr(w, http.StatusConflict, "this node is already set up; sign in and use Cluster to join another node")
		return
	}
	if subtle.ConstantTimeCompare([]byte(auth.NormalizeSetupCode(req.Code)), []byte(auth.NormalizeSetupCode(a.setupCode))) != 1 {
		a.Throttle.Fail("setup:" + ip)
		writeErr(w, http.StatusForbidden, "that setup code doesn't match; check the container log (a restart prints a new one)")
		return
	}
	a.doJoin(w, r, req.JoinCode, req.Host)
}

func (a *API) doJoin(w http.ResponseWriter, r *http.Request, code, host string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	name, err := a.Cluster.Join(ctx, code, host)
	if err != nil {
		a.writeStoreErr(w, err)
		return
	}
	a.Log.Info("joined a cluster", "node", name)
	writeJSON(w, http.StatusOK, map[string]any{"name": name})
}

func (a *API) writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrUnavailable):
		writeErr(w, http.StatusServiceUnavailable, unavailableMsg)
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

const unavailableMsg = "Changes are paused: this node can't reach the cluster leader. DNS keeps working with the current settings. Bring the other node back, or use Cluster → Recover on this one if the other is gone."
