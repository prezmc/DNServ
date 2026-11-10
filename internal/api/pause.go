package api

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// pauseOptions are the durations the dashboard offers, in minutes (0 is
// until turned back on). The API takes any length up to store.MaxPause.
var pauseOptions = []int{1, 5, 15, 30, 60, 0}

func (a *API) pauseRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/pause", a.authed(store.PermDashboard, a.getPause))
	m.HandleFunc("POST /api/v1/pause", a.authed(store.PermPause, a.setPause))
	m.HandleFunc("DELETE /api/v1/pause", a.authed(store.PermPause, a.resume))
}

// pauseEntry is one pause in force. Remaining lets the browser count
// down without trusting its own clock.
type pauseEntry struct {
	// Node is a node ID, or "*" for every node.
	Node     string `json:"node"`
	NodeName string `json:"node_name,omitempty"`
	// Indefinite: paused until someone turns filtering back on.
	Indefinite bool       `json:"indefinite,omitempty"`
	Until      *time.Time `json:"until,omitempty"`
	Remaining  float64    `json:"remaining_seconds,omitempty"`
	Since      time.Time  `json:"since"`
	By         string     `json:"by"`
}

type pauseNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Self bool   `json:"self,omitempty"`
}

// pauseView is what the dashboard's pause control shows.
type pauseView struct {
	// Paused: some pause is in force (on every node or on some).
	Paused bool         `json:"paused"`
	Pauses []pauseEntry `json:"pauses"`
	// Nodes are the servers that answer DNS, offered when there is more
	// than one.
	Nodes []pauseNode `json:"nodes"`
	// FilteringEnabled is the Settings switch; when it's off there is
	// nothing to pause.
	FilteringEnabled bool  `json:"filtering_enabled"`
	CanPause         bool  `json:"can_pause"`
	Options          []int `json:"options"`
}

func (a *API) pauseState(p *Principal) pauseView {
	st := a.Store.State()
	now := a.now()
	v := pauseView{
		Pauses: []pauseEntry{}, Nodes: []pauseNode{},
		FilteringEnabled: a.Effective().Filtering.Enabled, CanPause: p.Can(store.PermPause), Options: pauseOptions,
	}
	self := ""
	if a.Cluster != nil {
		self = a.Cluster.ID()
	}
	for _, n := range st.Cluster.Nodes {
		if !n.Witness {
			v.Nodes = append(v.Nodes, pauseNode{ID: n.ID, Name: n.Name, Self: n.ID == self})
		}
	}
	slices.SortFunc(v.Nodes, func(x, y pauseNode) int { return cmp.Compare(x.Name, y.Name) })
	for key, pz := range st.Pauses {
		if !pz.Active(now) {
			continue
		}
		e := pauseEntry{Node: key, Since: pz.Since, By: pz.By}
		if n := st.Cluster.Nodes[key]; n != nil {
			e.NodeName = n.Name
		} else if key != store.AllNodes {
			continue // a node that has since left
		}
		if pz.Until.IsZero() {
			e.Indefinite = true
		} else {
			until := pz.Until
			e.Until, e.Remaining = &until, until.Sub(now).Seconds()
		}
		v.Pauses = append(v.Pauses, e)
	}
	// Every-node pause first, then by server name.
	slices.SortFunc(v.Pauses, func(x, y pauseEntry) int {
		if (x.Node == store.AllNodes) != (y.Node == store.AllNodes) {
			if x.Node == store.AllNodes {
				return -1
			}
			return 1
		}
		return cmp.Compare(x.NodeName, y.NodeName)
	})
	v.Paused = len(v.Pauses) > 0
	return v
}

func (a *API) getPause(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, a.pauseState(p))
}

// setPause pauses filtering: {"minutes": 5}, or {"minutes": 0} until
// turned back on; "node" names one server (default: every server).
func (a *API) setPause(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Minutes *float64 `json:"minutes"`
		Node    string   `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Minutes == nil {
		writeErr(w, http.StatusBadRequest, "say how many minutes to pause for (0: until turned back on)")
		return
	}
	secs := int64(*req.Minutes * 60)
	if *req.Minutes < 0 || (*req.Minutes > 0 && secs < 1) {
		writeErr(w, http.StatusBadRequest, "minutes must be positive, or 0 to pause until turned back on")
		return
	}
	if _, ok := a.apply(w, a.stamp(store.NewCommand(store.OpFilterPause, p.Actor(), store.FilterPause{Seconds: secs, Node: req.Node}))); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.pauseState(p))
}

// resume turns filtering back on: ?node=<id> ends that server's own
// pause; without it, every pause ends.
func (a *API) resume(w http.ResponseWriter, r *http.Request, p *Principal) {
	node := r.URL.Query().Get("node")
	if _, ok := a.apply(w, a.stamp(store.NewCommand(store.OpFilterResume, p.Actor(), store.FilterResume{Node: node}))); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.pauseState(p))
}

// stamp dates a command with the API's clock, which the pause view also
// uses.
func (a *API) stamp(c store.Command) store.Command {
	c.Time = a.now().UTC()
	return c
}
