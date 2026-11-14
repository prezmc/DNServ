package api

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
)

// How many entries each column of the traffic map shows; the rest are
// summed into "Other …".
const (
	mapDevices  = 10
	mapServices = 10
	mapBlocked  = 4
)

// flowNode is one box in the traffic map.
type flowNode struct {
	ID    string `json:"id"`
	Col   int    `json:"col"` // 0 devices, 1 servers, 2 answered by, 3 services
	Label string `json:"label"`
	Kind  string `json:"kind,omitempty"` // cache, upstream, blocked, local, failed, other
	N     int64  `json:"n"`
	// Device is the device id (or address) a device box links to;
	// Domains are a service box's busiest domains.
	Device  string   `json:"device,omitempty"`
	Domains []string `json:"domains,omitempty"`
	// By category: Group is the category a category box stands for (it
	// can be opened), and Parent the opened category a site box is in.
	Group  string `json:"group,omitempty"`
	Parent string `json:"parent,omitempty"`
}

// flowLink is a band between two boxes, for one kind of lookup
// (internet, internal or blocked), so the map can leave kinds out.
type flowLink struct {
	S    string `json:"s"`
	T    string `json:"t"`
	Kind string `json:"kind"`
	N    int64  `json:"n"`
}

// analyticsFlow builds the traffic map: devices → DNS servers → how each
// lookup was answered → the services it was for. group is "company"
// (default) or "category" ("type" is the old name); by category, open is
// a category to break out into its apps and sites.
func (a *API) analyticsFlow(w http.ResponseWriter, r *http.Request, p *Principal) {
	q, ok := a.parseQuery(w, r, p, analytics.KindFlow)
	if !ok {
		return
	}
	byCat := slices.Contains([]string{"category", "type"}, r.URL.Query().Get("group"))
	open := ""
	if byCat {
		open = r.URL.Query().Get("open")
	}
	res, nodes, ok := a.askOrFail(w, r, q)
	if !ok {
		return
	}
	devices := p.Can(store.PermQueryLog)

	g := newFlowGraph()
	// Devices, merged by device (a device can have several addresses) and
	// across servers.
	var addrs []string
	for _, f := range res.Flows {
		for _, c := range f.Clients {
			if c.Key != "" {
				addrs = append(addrs, c.Key)
			}
		}
	}
	devKey := func(addr string) string { return "dev:" + addr }
	devLabel := map[string]string{}
	devLink := map[string]string{}
	if devices {
		l := a.newLabeler(r.Context(), addrs)
		devKey = func(addr string) string {
			if addr == "" {
				return "dev:"
			}
			if id := l.device[addr]; id != "" {
				devLabel["dev:"+id], devLink["dev:"+id] = l.names[addr], id
				return "dev:" + id
			}
			devLabel["dev:"+addr], devLink["dev:"+addr] = cmp.Or(l.names[addr], addr), addr
			return "dev:" + addr
		}
	}
	devTotal := map[string]int64{}
	type devSrv struct{ dev, srv, kind string }
	devSrvN := map[devSrv]int64{}
	for _, f := range res.Flows {
		srv := "srv:" + f.Node
		for _, c := range f.Clients {
			k := "dev:"
			if devices {
				k = devKey(c.Key)
			}
			devTotal[k] += c.N
			devSrvN[devSrv{k, srv, c.Kind}] += c.N
		}
	}
	keepDev := topKeys(devTotal, mapDevices, "dev:")
	others := 0
	for k := range devTotal {
		if !keepDev[k] && k != "dev:" {
			others++
		}
	}
	for k, n := range devSrvN {
		dev := k.dev
		if !keepDev[dev] {
			dev = "dev:"
		}
		g.link(dev, k.srv, k.kind, n)
	}
	for k := range keepDev {
		g.node(k, 0, devLabel[k], "", devLink[k])
	}
	switch {
	case !devices:
		g.node("dev:", 0, "All devices", "other", "")
	case others > 0:
		g.node("dev:", 0, fmt.Sprintf("Other devices (%d)", others), "other", "")
	default:
		g.node("dev:", 0, "Other devices", "other", "")
	}

	// Servers and how they answered.
	svcTotal := map[string]int64{}
	type svcKey struct{ path, svc, kind string }
	pathSvc := map[svcKey]int64{}
	domains := map[string]map[string]int64{}
	for _, f := range res.Flows {
		srv := "srv:" + f.Node
		g.node(srv, 1, f.Node, "server", "")
		for _, pth := range f.Paths {
			label, kind := pathLabel(pth.Key)
			id := "path:" + kind + ":" + label
			g.node(id, 2, label, kind, "")
			g.link(srv, id, analytics.PathKind(pth.Key), pth.N)
		}
		for _, nm := range f.Names {
			label, kind := pathLabel(nm.Path)
			path := "path:" + kind + ":" + label
			svc := a.serviceOf(nm.Name, kind, byCat, open)
			svcTotal[svc] += nm.N
			pathSvc[svcKey{path, svc, analytics.PathKind(nm.Path)}] += nm.N
			if nm.Name != "" {
				if domains[svc] == nil {
					domains[svc] = map[string]int64{}
				}
				domains[svc][nm.Name] += nm.N
			}
		}
	}
	// Keep the busiest services; blocked and allowed are ranked apart so
	// a few big ad networks don't crowd out the sites people use.
	// By category every category is shown (there are few), and the
	// opened one's busiest apps and sites.
	allowed, blocked := map[string]int64{}, map[string]int64{}
	inAllowed, inBlocked := map[string]int64{}, map[string]int64{}
	for k, n := range svcTotal {
		switch {
		case strings.HasPrefix(k, svcBlockedIn):
			inBlocked[k] = n
		case strings.HasPrefix(k, "svc:blocked:"):
			blocked[k] = n
		case strings.HasPrefix(k, svcIn):
			inAllowed[k] = n
		case k != "svc:local" && k != "svc:failed":
			allowed[k] = n
		}
	}
	nAllowed, nBlocked := mapServices, mapBlocked
	if byCat {
		nAllowed, nBlocked = 20, 8
	}
	keep := topKeys(allowed, nAllowed, "svc:other")
	for k := range topKeys(blocked, nBlocked, "svc:blocked:") {
		keep[k] = true
	}
	for k := range topKeys(inAllowed, mapOpened, svcIn) {
		keep[k] = true
	}
	for k := range topKeys(inBlocked, mapBlocked, svcBlockedIn) {
		keep[k] = true
	}
	keep["svc:local"], keep["svc:failed"] = true, true
	for k, n := range pathSvc {
		svc := k.svc
		if !keep[svc] {
			switch {
			case strings.HasPrefix(svc, svcBlockedIn):
				svc = svcBlockedIn
			case strings.HasPrefix(svc, "svc:blocked:"):
				svc = "svc:blocked:"
			case strings.HasPrefix(svc, svcIn):
				svc = svcIn
			default:
				svc = "svc:other"
			}
		}
		g.link(k.path, svc, k.kind, n)
	}
	for svc := range g.targets(3) {
		label, kind := serviceLabel(svc)
		n := g.node(svc, 3, label, kind, "")
		switch {
		case svc == svcIn:
			n.Label, n.Kind, n.Parent = "More "+strings.ToLower(open), "other", open
		case svc == svcBlockedIn:
			n.Label, n.Parent = "More blocked "+strings.ToLower(open), open
		case strings.HasPrefix(svc, svcIn) || strings.HasPrefix(svc, svcBlockedIn):
			n.Parent = open
		case byCat && strings.HasPrefix(svc, "svc:cat:"):
			n.Group = n.Label
		case byCat && strings.HasPrefix(svc, "svc:blocked:"):
			n.Group = cmp.Or(n.Label, threat.CatOther)
			if svc == "svc:blocked:" {
				n.Group = threat.CatOther
			}
		}
		if d := domains[svc]; d != nil && keep[svc] {
			for _, row := range topFlowRows(d, 5) {
				n.Domains = append(n.Domains, row)
			}
		}
	}
	nodesOut, links := g.result()
	var total int64
	for _, n := range devTotal {
		total += n
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodesOut, "links": links, "total": total, "devices": devices,
		"group": map[bool]string{true: "category", false: "company"}[byCat], "open": open, "servers": nodes})
}

// pathLabel names a traffic map path and says what kind it is.
func pathLabel(path string) (label, kind string) {
	switch path {
	case analytics.PathCache:
		return "Cache", "cache"
	case analytics.PathBlocked:
		return "Blocked", "blocked"
	case analytics.PathLocal:
		return "Local names", "local"
	case analytics.PathFailed:
		return "No answer", "failed"
	}
	return upstreamLabel(strings.TrimPrefix(path, analytics.PathUp)), "upstream"
}

// upstreamLabel turns an upstream address into a short name:
// "dns.quad9.net (HTTPS)", "9.9.9.9 (TLS)", "192.168.1.1".
func upstreamLabel(s string) string {
	if s == "" {
		return "Upstream"
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
		return host + " (HTTPS)"
	case "tls":
		return host + " (TLS)"
	case "tcp":
		return host + " (TCP)"
	}
	return host
}

// Node ids of the apps and sites in an opened category; these alone are
// the remainder.
const (
	svcIn        = "svc:in:"
	svcBlockedIn = "svc:blocked:in:"
	mapOpened    = 12
)

// serviceOf groups a domain for the traffic map: by the company that runs
// it (else its registrable domain), blocked domains by type; or, by
// category, by what it is used for, with the opened category's domains by
// app or site. The result is a node id.
func (a *API) serviceOf(name, kind string, byCat bool, open string) string {
	switch kind {
	case "local":
		return "svc:local"
	case "failed":
		return "svc:failed"
	}
	if byCat {
		c := threat.Category{Name: threat.CatOther}
		var t *threat.Type
		if name != "" && a.Intel != nil {
			t = a.Intel.TypeOf(name)
			c = threat.CategoryOf(name, t)
		}
		pre := "svc:cat:"
		if kind == "blocked" {
			pre = "svc:blocked:"
		}
		if name == "" || c.Name != open {
			if kind == "blocked" && c.Name == threat.CatOther {
				return pre
			}
			return pre + c.Name
		}
		site := c.Service
		if site == "" && t != nil && t.Company != "" {
			site = shortCompany(t.Company)
		}
		if site == "" {
			site = name
			if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
				site = d
			}
		}
		if kind == "blocked" {
			return svcBlockedIn + site
		}
		return svcIn + site
	}
	var category, company string
	if name != "" && a.Intel != nil {
		if t := a.Intel.TypeOf(name); t != nil {
			category, company = t.Category, t.Company
			if category == "Other" {
				category = ""
			}
		}
	}
	if kind == "blocked" {
		return "svc:blocked:" + category
	}
	if name == "" {
		return "svc:other"
	}
	if company != "" {
		return "svc:co:" + company
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return "svc:site:" + d
	}
	return "svc:site:" + name
}

// serviceLabel names a service node.
func serviceLabel(id string) (label, kind string) {
	switch {
	case id == "svc:local":
		return "Local devices", "local"
	case id == "svc:failed":
		return "No answer", "failed"
	case id == "svc:other":
		return "Other sites", "other"
	case id == "svc:blocked:":
		return "Other blocked", "blocked"
	case strings.HasPrefix(id, svcBlockedIn):
		return strings.TrimPrefix(id, svcBlockedIn), "blocked"
	case strings.HasPrefix(id, "svc:blocked:"):
		return strings.TrimPrefix(id, "svc:blocked:"), "blocked"
	case strings.HasPrefix(id, svcIn):
		return strings.TrimPrefix(id, svcIn), "service"
	case strings.HasPrefix(id, "svc:cat:"):
		return strings.TrimPrefix(id, "svc:cat:"), "service"
	case strings.HasPrefix(id, "svc:co:"):
		return shortCompany(strings.TrimPrefix(id, "svc:co:")), "service"
	}
	return strings.TrimPrefix(id, "svc:site:"), "service"
}

// topKeys returns the limit largest keys, leaving out rest (the key for
// the remainder).
func topKeys(m map[string]int64, limit int, rest string) map[string]bool {
	ks := make([]string, 0, len(m))
	for k := range m {
		if k != rest {
			ks = append(ks, k)
		}
	}
	slices.SortFunc(ks, func(x, y string) int { return cmp.Or(cmp.Compare(m[y], m[x]), cmp.Compare(x, y)) })
	out := map[string]bool{}
	for _, k := range ks[:min(limit, len(ks))] {
		out[k] = true
	}
	return out
}

func topFlowRows(m map[string]int64, limit int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(x, y string) int { return cmp.Or(cmp.Compare(m[y], m[x]), cmp.Compare(x, y)) })
	return ks[:min(limit, len(ks))]
}

// flowGraph collects boxes and bands, summing repeated bands.
type flowGraph struct {
	nodes map[string]*flowNode
	links map[[3]string]int64
}

func newFlowGraph() *flowGraph {
	return &flowGraph{nodes: map[string]*flowNode{}, links: map[[3]string]int64{}}
}

func (g *flowGraph) node(id string, col int, label, kind, device string) *flowNode {
	n := g.nodes[id]
	if n == nil {
		n = &flowNode{ID: id, Col: col, Label: label, Kind: kind, Device: device}
		g.nodes[id] = n
	}
	return n
}

func (g *flowGraph) link(s, t, kind string, n int64) {
	if n > 0 {
		g.links[[3]string{s, t, kind}] += n
	}
}

// targets lists the ids that bands lead to from column col-1.
func (g *flowGraph) targets(col int) map[string]bool {
	out := map[string]bool{}
	for k := range g.links {
		if s := g.nodes[k[0]]; s != nil && s.Col == col-1 {
			out[k[1]] = true
		}
	}
	return out
}

// result returns the boxes that have bands, sized by their larger side,
// biggest first within each column, and the bands.
func (g *flowGraph) result() ([]*flowNode, []flowLink) {
	in, out := map[string]int64{}, map[string]int64{}
	var links []flowLink
	for k, n := range g.links {
		if g.nodes[k[0]] == nil || g.nodes[k[1]] == nil {
			continue
		}
		links = append(links, flowLink{k[0], k[1], k[2], n})
		out[k[0]] += n
		in[k[1]] += n
	}
	var nodes []*flowNode
	for id, n := range g.nodes {
		n.N = max(in[id], out[id])
		if n.N > 0 {
			nodes = append(nodes, n)
		}
	}
	// "Other" boxes go last in their group; an opened category's apps
	// and sites go together, before the other categories.
	last := func(n *flowNode) int {
		if n.Kind == "other" || n.ID == "svc:blocked:" || n.ID == svcBlockedIn || n.Kind == "local" || n.Kind == "failed" || n.ID == "svc:cat:"+threat.CatOther {
			return 1
		}
		return 0
	}
	order := func(n *flowNode) int {
		in := 0
		if n.Parent == "" {
			in = 1
		}
		switch n.Kind {
		case "blocked":
			return 2 + in
		case "local", "failed":
			return 4
		}
		return in
	}
	slices.SortFunc(nodes, func(x, y *flowNode) int {
		return cmp.Or(cmp.Compare(x.Col, y.Col), cmp.Compare(order(x), order(y)), cmp.Compare(last(x), last(y)), cmp.Compare(y.N, x.N), cmp.Compare(x.ID, y.ID))
	})
	slices.SortFunc(links, func(x, y flowLink) int {
		return cmp.Or(cmp.Compare(y.N, x.N), cmp.Compare(x.S, y.S), cmp.Compare(x.T, y.T), cmp.Compare(x.Kind, y.Kind))
	})
	return nodes, links
}

// shortCompany drops legal suffixes: "Apple Inc." is Apple, "Microsoft
// Corporation" is Microsoft.
func shortCompany(s string) string { return threat.ShortCompany(s) }
