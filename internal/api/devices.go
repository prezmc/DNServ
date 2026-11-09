package api

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/querylog"
	"github.com/prezmc/dnserve/internal/store"
)

// namesCache remembers router-provided device names for a while, so the
// device list doesn't ask the router on every refresh.
type namesCache struct {
	mu sync.Mutex
	m  map[netip.Addr]cachedName
}

type cachedName struct {
	name string
	at   time.Time
}

func (a *API) hostname(ctx context.Context, addr netip.Addr) string {
	if a.LookupName == nil {
		return ""
	}
	a.names.mu.Lock()
	if a.names.m == nil {
		a.names.m = map[netip.Addr]cachedName{}
	}
	c, ok := a.names.m[addr]
	a.names.mu.Unlock()
	if ok && a.now().Sub(c.at) < 10*time.Minute {
		return c.name
	}
	name := a.LookupName(ctx, addr)
	a.names.mu.Lock()
	a.names.m[addr] = cachedName{name: name, at: a.now()}
	a.names.mu.Unlock()
	return name
}

// deviceView merges a named device with what the query log has seen.
type deviceView struct {
	ID        string    `json:"id,omitempty"` // empty for devices seen but not named
	Name      string    `json:"name"`
	Hostname  string    `json:"hostname,omitempty"` // from the router
	Addrs     []string  `json:"addrs"`
	Queries   int64     `json:"queries"`
	Blocked   int64     `json:"blocked"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request, p *Principal) {
	st := a.Store.State()
	byAddr := map[string]*deviceView{}
	out := []*deviceView{}
	for _, d := range st.Devices {
		v := &deviceView{ID: d.ID, Name: d.Name, Addrs: slices.Clone(d.Addrs)}
		out = append(out, v)
		for _, ad := range d.Addrs {
			byAddr[ad] = v
		}
	}
	if a.QueryLog != nil {
		for _, c := range a.QueryLog.Clients() {
			key := c.Addr.String()
			v, ok := byAddr[key]
			if !ok {
				v = &deviceView{Addrs: []string{key}}
				byAddr[key] = v
				out = append(out, v)
			}
			v.Queries += c.Queries
			v.Blocked += c.Blocked
			if v.FirstSeen.IsZero() || c.FirstSeen.Before(v.FirstSeen) {
				v.FirstSeen = c.FirstSeen
			}
			if c.LastSeen.After(v.LastSeen) {
				v.LastSeen = c.LastSeen
			}
		}
	}
	// Router names, looked up in parallel with a short deadline.
	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for _, v := range out {
		if ip, err := netip.ParseAddr(v.Addrs[0]); err == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v.Hostname = a.hostname(ctx, ip)
			}()
		}
	}
	wg.Wait()
	slices.SortFunc(out, func(x, y *deviceView) int {
		if c := y.LastSeen.Compare(x.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	writeJSON(w, http.StatusOK, out)
}

func (a *API) saveDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Name  string
		Addrs []string
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	status := http.StatusOK
	if id == "" {
		id, status = auth.RandomID(9), http.StatusCreated
	} else if _, ok := a.Store.State().Devices[id]; !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpDeviceSave, p.Actor(), store.Device{ID: id, Name: req.Name, Addrs: req.Addrs})); !ok {
		return
	}
	writeJSON(w, status, a.Store.State().Devices[id])
}

func (a *API) deleteDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	if _, ok := a.apply(w, store.NewCommand(store.OpDeviceDelete, p.Actor(), store.IDOnly{ID: r.PathValue("id")})); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// queries lists recent queries. client may be an IP or a device id.
func (a *API) queries(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.QueryLog == nil {
		writeJSON(w, http.StatusOK, map[string]any{"queries": []any{}})
		return
	}
	q := r.URL.Query()
	f := querylog.Filter{Search: q.Get("search"), Result: q.Get("result")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Before, _ = strconv.ParseUint(q.Get("before"), 10, 64)
	st := a.Store.State()
	if c := q.Get("client"); c != "" {
		if d, ok := st.Devices[c]; ok {
			for _, ad := range d.Addrs {
				if ip, err := netip.ParseAddr(ad); err == nil {
					f.Clients = append(f.Clients, ip)
				}
			}
		} else if ip, err := netip.ParseAddr(c); err == nil {
			f.Clients = []netip.Addr{ip.Unmap()}
		} else {
			writeErr(w, http.StatusBadRequest, "client must be an IP address or device id")
			return
		}
	}
	entries := a.QueryLog.Query(f)
	// Name each client once for the UI.
	names := map[string]string{}
	for _, e := range entries {
		k := e.Client.String()
		if _, ok := names[k]; !ok {
			if d := st.DeviceByAddr(k); d != nil {
				names[k] = d.Name
			} else {
				names[k] = ""
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": entries, "device_names": names, "held": a.QueryLog.Len(), "capacity": a.QueryLog.Cap()})
}

// checkDomain says whether a name would be blocked, and why.
func (a *API) checkDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	name := filter.Normalize(strings.TrimSpace(r.URL.Query().Get("name")))
	if rules, ok, _ := filter.ParseLine(name); name == "" || !ok || len(rules) != 1 || rules[0].Domain != name {
		writeErr(w, http.StatusBadRequest, "not a valid domain")
		return
	}
	out := map[string]any{"name": name, "blocked": false, "allowed": false}
	if a.CheckDomain != nil {
		m := a.CheckDomain(name)
		out["blocked"], out["allowed"] = m.Blocked, m.Allowed
		if m.Blocked || m.Allowed {
			out["rule"], out["list"] = m.Rule.Text(), m.Source
			out["custom"] = m.Source == "Custom rules"
		}
	}
	writeJSON(w, http.StatusOK, out)
}
