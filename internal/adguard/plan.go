package adguard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/store"
)

// Plan says what an import would change, section by section.
type Plan struct {
	Source   string     `json:"source"`
	Version  string     `json:"version"`
	Sections []*Section `json:"sections"`

	patches map[string]store.Settings
	Devices []DevicePlan `json:"-"`
	Groups  []GroupPlan  `json:"-"`
}

// Section is one area of settings, imported or left as a whole.
type Section struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Note explains the section, or warns about it.
	Note string `json:"note,omitempty"`
	// Default says whether the section is ticked to start with.
	Default bool `json:"default"`
	// Info sections are only for reading: nothing is imported.
	Info bool `json:"info,omitempty"`
	// Items are what would be added; Have are already in DNServ.
	Items   []Item `json:"items"`
	Have    []Item `json:"have,omitempty"`
	Skipped []Item `json:"skipped,omitempty"`
}

// Item is one thing in a section.
type Item struct {
	// ID is stable for the same AdGuard Home data, so the person can
	// leave single items out.
	ID     string `json:"id,omitempty"`
	Text   string `json:"text"`
	Detail string `json:"detail,omitempty"`
}

// DevicePlan is a device to name. Existing is set when DNServ already
// has it (only its group would change).
type DevicePlan struct {
	ItemID   string
	Name     string
	Addrs    []string
	Existing string
	Group    int // index into Groups, or -1
}

// GroupPlan is a group made for a device with its own AdGuard Home
// settings.
type GroupPlan struct {
	ItemID         string
	Name           string
	SkipBlocklists bool
	Rules          []string
}

// Section keys.
const (
	KeyLists      = "lists"
	KeyAllowlists = "allowlists"
	KeyRules      = "rules"
	KeyRecords    = "records"
	KeyUpstream   = "upstream"
	KeyLocalDNS   = "local_dns"
	KeyBlocking   = "blocking"
	KeyAccess     = "access"
	KeyDevices    = "devices"
	KeyGroups     = "groups"
	KeyOther      = "other"
)

// Patch merges the settings changes of the chosen sections.
func (p *Plan) Patch(sections map[string]bool) store.Settings {
	var out store.Settings
	for _, s := range p.Sections {
		if sections[s.Key] {
			if pt, ok := p.patches[s.Key]; ok {
				out.Merge(pt)
			}
		}
	}
	return out
}

// Section returns a section by key, or nil.
func (p *Plan) Section(key string) *Section {
	for _, s := range p.Sections {
		if s.Key == key {
			return s
		}
	}
	return nil
}

// Build works out what importing s would change, given DNServ's current
// state and effective configuration. Items whose ID is in exclude are left
// out (and not listed), so Build can be re-run with the person's choices.
func Build(s *Snapshot, st *store.State, eff config.Config, exclude map[string]bool) *Plan {
	b := &builder{s: s, st: st, eff: eff, ex: exclude, p: &Plan{Source: s.Source, Version: s.Version, patches: map[string]store.Settings{}}}
	b.lists(KeyLists, "Blocklists", s.Filters, eff.Filtering.Lists)
	b.lists(KeyAllowlists, "Allowlists", s.Whitelist, eff.Filtering.Allowlists)
	recordCands := b.rules()
	b.records(recordCands)
	b.upstream()
	b.localDNS()
	b.blocking()
	b.access()
	b.devicesAndGroups()
	b.other()
	var out []*Section
	for _, sec := range b.p.Sections {
		if len(sec.Items)+len(sec.Have)+len(sec.Skipped) > 0 || sec.Info && sec.Note != "" {
			out = append(out, sec)
		}
	}
	b.p.Sections = out
	return b.p
}

type builder struct {
	s   *Snapshot
	st  *store.State
	eff config.Config
	ex  map[string]bool
	p   *Plan

	upstreamLocal []string // private resolvers found in domain-specific upstreams
	services      []string // global blocked services, for per-device allow rules
}

func (b *builder) section(key, title string) *Section {
	sec := &Section{Key: key, Title: title, Default: true, Items: []Item{}}
	b.p.Sections = append(b.p.Sections, sec)
	return sec
}

func (b *builder) skip(id string) bool { return b.ex[id] }

func (b *builder) lists(key, title string, in []Filter, cur []config.ListConfig) {
	sec := b.section(key, title)
	have := map[string]bool{}
	for _, l := range cur {
		have[strings.TrimSpace(l.URL)] = true
	}
	next := slices.Clone(cur)
	added := false
	for _, f := range in {
		u := strings.TrimSpace(f.URL)
		name := strings.TrimSpace(f.Name)
		if name == "" {
			name = u
		}
		state := ""
		if !f.Enabled {
			state = "turned off in AdGuard Home; imported turned off"
		}
		it := Item{ID: key + ":" + u, Text: name, Detail: joinDetail(u, state)}
		switch {
		case u == "":
			continue
		case !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://"):
			it.ID, it.Detail = "", u+": a file on the AdGuard Home server, which DNServ can't read. Copy its rules into Custom rules instead."
			sec.Skipped = append(sec.Skipped, it)
		case have[u]:
			it.ID = ""
			sec.Have = append(sec.Have, it)
		case b.skip(it.ID):
		default:
			have[u] = true
			sec.Items = append(sec.Items, it)
			next = append(next, config.ListConfig{Name: name, URL: u, Enabled: f.Enabled})
			added = true
		}
	}
	if added {
		b.p.patches[key] = store.Settings{Lists: ptrIf(key == KeyLists, next), Allowlists: ptrIf(key == KeyAllowlists, next)}
	}
	if key == KeyLists {
		sec.Note = "Added next to the lists DNServ already uses. A list on both is downloaded once."
	}
}

func ptrIf(ok bool, v []config.ListConfig) *[]config.ListConfig {
	if !ok {
		return nil
	}
	return &v
}

// recordCand is a local name found in a rewrite or a rule.
type recordCand struct {
	rec  config.Record
	from string
}

// defaultBlockedHosts are in every AdGuard Home's access settings.
var defaultBlockedHosts = map[string]bool{"version.bind": true, "id.server": true, "hostname.bind": true}

func (b *builder) rules() []recordCand {
	sec := b.section(KeyRules, "Custom rules")
	sec.Note = "Added after your DNServ rules. Rules that answer with an address become Local names."
	have := map[string]bool{}
	for _, r := range b.eff.Filtering.Rules {
		have[strings.TrimSpace(r)] = true
	}
	next := slices.Clone(b.eff.Filtering.Rules)
	var recs []recordCand
	add := func(rule, text, detail string) {
		id := "rules:" + rule
		switch {
		case have[rule]:
			sec.Have = append(sec.Have, Item{Text: text, Detail: detail})
		case b.skip(id):
		default:
			have[rule] = true
			next = append(next, rule)
			sec.Items = append(sec.Items, Item{ID: id, Text: text, Detail: detail})
		}
	}
	for _, line := range b.s.UserRules {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}
		if rc, ok := ruleRecords(line); ok {
			recs = append(recs, rc...)
			continue
		}
		if _, ok, _ := filter.ParseLine(line); ok {
			add(line, line, "")
			continue
		}
		sec.Skipped = append(sec.Skipped, Item{Text: line, Detail: unsupportedReason(line)})
	}

	// Services blocked for everyone become ordinary rules.
	for _, id := range b.s.BlockedServices {
		sv, ok := b.s.Services[id]
		if !ok {
			sec.Skipped = append(sec.Skipped, Item{Text: "Blocked service: " + id, Detail: "AdGuard Home didn't list this service's domains."})
			continue
		}
		b.services = append(b.services, id)
		rules, dropped := serviceRules(sv)
		detail := fmt.Sprintf("%d rules", len(rules))
		if dropped > 0 {
			detail += fmt.Sprintf(" (%d more use AdGuard-only options and are left out)", dropped)
		}
		itemID := "rules:service:" + id
		if b.skip(itemID) {
			continue
		}
		allHave := true
		for _, r := range rules {
			if !have[r] {
				allHave = false
			}
		}
		if allHave {
			sec.Have = append(sec.Have, Item{Text: "Blocked service: " + sv.Name, Detail: detail})
			continue
		}
		for _, r := range rules {
			if !have[r] {
				have[r] = true
				next = append(next, r)
			}
		}
		sec.Items = append(sec.Items, Item{ID: itemID, Text: "Blocked service: " + sv.Name, Detail: detail})
	}
	if b.s.ServicesSchedule {
		sec.Skipped = append(sec.Skipped, Item{Text: "The schedule for blocked services", Detail: "Blocked services are imported as always on. To block them only at some times, use a group schedule on the Devices page."})
	}
	for _, hst := range b.s.Access.BlockedHosts {
		hst = strings.TrimSpace(hst)
		if hst == "" || defaultBlockedHosts[strings.ToLower(hst)] {
			continue
		}
		rule := hst
		if r, ok, _ := filter.ParseLine(hst); ok && len(r) == 1 && r[0].Kind == filter.Exact && !r[0].Allow {
			rule = "||" + r[0].Domain + "^" // AdGuard Home refuses the domain and its subdomains
		}
		if _, ok, _ := filter.ParseLine(rule); !ok {
			sec.Skipped = append(sec.Skipped, Item{Text: hst, Detail: "A disallowed domain DNServ can't read as a rule."})
			continue
		}
		add(rule, rule, "from Access settings: disallowed domains")
	}
	if len(next) != len(b.eff.Filtering.Rules) {
		b.p.patches[KeyRules] = store.Settings{Rules: &next}
	}
	return recs
}

func serviceRules(sv Service) (rules []string, dropped int) {
	for _, r := range sv.Rules {
		r = strings.TrimSpace(r)
		if _, ok, _ := filter.ParseLine(r); ok {
			rules = append(rules, r)
		} else if r != "" {
			dropped++
		}
	}
	return
}

// ruleRecords turns AdGuard Home rules that answer with an address into
// local records: hosts lines with a real address, and simple $dnsrewrite.
func ruleRecords(line string) ([]recordCand, bool) {
	if i := strings.Index(line, "$dnsrewrite="); i > 0 {
		pat, val := line[:i], line[i+len("$dnsrewrite="):]
		if strings.ContainsAny(val, ",$") {
			return nil, false
		}
		if parts := strings.Split(val, ";"); len(parts) == 3 {
			if !strings.EqualFold(parts[0], "NOERROR") {
				return nil, false
			}
			switch strings.ToUpper(parts[1]) {
			case "A", "AAAA", "CNAME":
				val = parts[2]
			default:
				return nil, false
			}
		} else if len(parts) != 1 {
			return nil, false
		} else if _, err := netip.ParseAddr(val); err != nil && !strings.Contains(val, ".") {
			return nil, false // a response code such as REFUSED
		}
		name := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(pat, "||"), "|"), "^")
		if name == "" || strings.ContainsAny(name, "*/|^@$") || strings.HasPrefix(pat, "@@") {
			return nil, false
		}
		return []recordCand{{rec: config.Record{Name: name, Value: val}, from: line}}, true
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return nil, false
	}
	ip, err := netip.ParseAddr(f[0])
	if err != nil || ip.IsUnspecified() || ip.IsLoopback() {
		return nil, false // a blocking hosts line
	}
	var out []recordCand
	for _, n := range f[1:] {
		if n = config.NormalizeName(n); n != "" && n != "localhost" {
			out = append(out, recordCand{rec: config.Record{Name: n, Value: ip.Unmap().String()}, from: line})
		}
	}
	return out, len(out) > 0
}

func unsupportedReason(line string) string {
	l := strings.TrimPrefix(line, "@@")
	switch {
	case strings.HasPrefix(l, "/") && strings.HasSuffix(strings.SplitN(l, "$", 2)[0], "/"):
		return "Regular expressions aren't supported."
	case strings.Contains(l, "$client="):
		return "Rules for one device: add it to a group on the Devices page and put the rule there."
	case strings.Contains(l, "$ctag="):
		return "Rules for device types (tags) aren't supported. Put the rule in a group instead."
	case strings.Contains(l, "$dnsrewrite"):
		return "Only simple rewrites to one address or name can be moved. Add it on the Local names page."
	case strings.Contains(l, "$denyallow"):
		return "$denyallow isn't supported."
	case strings.Contains(l, "$badfilter"):
		return "$badfilter isn't supported: add an allow rule (@@||domain^) instead."
	case strings.Contains(l, "$"):
		return "This rule uses options DNServ doesn't support."
	case strings.ContainsAny(l, "*/"):
		return "Wildcards are only supported at the start, like *.example.com."
	}
	return "DNServ can't read this rule."
}

func (b *builder) records(fromRules []recordCand) {
	sec := b.section(KeyRecords, "Local names")
	sec.Note = "From DNS rewrites and rules that answer with an address. They work the same way on the Local names page."
	cur := b.eff.DNS.Records
	have := map[[2]string]bool{}
	for _, r := range cur {
		have[[2]string{r.Name, r.Value}] = true
	}
	next := slices.Clone(cur)
	var cands []recordCand
	for _, rw := range b.s.Rewrites {
		r := config.Record{Name: rw.Domain, Value: strings.TrimSpace(rw.Answer)}
		text := config.NormalizeName(rw.Domain) + " → " + r.Value
		if rw.Enabled != nil && !*rw.Enabled {
			sec.Skipped = append(sec.Skipped, Item{Text: text, Detail: "Turned off in AdGuard Home."})
			continue
		}
		if v := strings.ToUpper(r.Value); v == "A" || v == "AAAA" {
			sec.Skipped = append(sec.Skipped, Item{Text: text, Detail: "Keeps the real " + v + " answer: DNServ does that without a record."})
			continue
		}
		cands = append(cands, recordCand{rec: r, from: "DNS rewrite"})
	}
	cands = append(cands, fromRules...)
	added := false
	for _, c := range cands {
		norm, err := config.NormalizeRecords([]config.Record{c.rec})
		text := config.NormalizeName(c.rec.Name) + " → " + strings.TrimSpace(c.rec.Value)
		if err != nil {
			sec.Skipped = append(sec.Skipped, Item{Text: text, Detail: err.Error()})
			continue
		}
		r := norm[0]
		r.Note = "From AdGuard Home"
		text = r.Name + " → " + r.Value
		detail := ""
		if c.from != "DNS rewrite" {
			detail = "from the rule " + c.from
		}
		key := [2]string{r.Name, r.Value}
		id := "records:" + r.Name + ">" + r.Value
		switch {
		case have[key]:
			sec.Have = append(sec.Have, Item{Text: text, Detail: detail})
			continue
		case b.skip(id):
			continue
		}
		trial := append(slices.Clone(next), r)
		if _, err := config.NormalizeRecords(trial); err != nil {
			sec.Skipped = append(sec.Skipped, Item{Text: text, Detail: err.Error()})
			continue
		}
		have[key] = true
		next = trial
		added = true
		sec.Items = append(sec.Items, Item{ID: id, Text: text, Detail: detail})
	}
	if added {
		b.p.patches[KeyRecords] = store.Settings{Records: &next}
	}
}

// mapUpstream turns an AdGuard Home upstream into a DNServ server URL.
func mapUpstream(s string) (string, string) {
	low := strings.ToLower(s)
	for _, p := range []struct{ prefix, why string }{
		{"quic://", "DNS over QUIC isn't supported. Use the same provider's https:// or tls:// address."},
		{"h3://", "DNS over HTTP/3 isn't supported. Use the https:// address instead."},
		{"sdns://", "DNS stamps aren't supported. Use the server's https:// or tls:// address."},
	} {
		if strings.HasPrefix(low, p.prefix) {
			return "", p.why
		}
	}
	var host string
	out := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", "Not an address DNServ understands."
		}
		switch u.Scheme {
		case "https", "tls", "udp", "tcp":
		default:
			return "", fmt.Sprintf("%s:// isn't supported.", u.Scheme)
		}
		host = u.Hostname()
	} else {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			host = ap.Addr().String()
		} else if a, err := netip.ParseAddr(s); err == nil {
			host, out = a.String(), "udp://"+netip.AddrPortFrom(a, 53).String()
		} else if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		} else if !strings.ContainsAny(s, "/[] ") {
			host = s
		} else {
			return "", "Not an address DNServ understands."
		}
		if !strings.HasPrefix(out, "udp://") {
			out = "udp://" + s
		}
	}
	if host == "localhost" {
		return "", loopbackWhy
	}
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		return "", loopbackWhy
	}
	return out, ""
}

const loopbackWhy = "This is a resolver on the AdGuard Home machine itself (often Unbound), which DNServ can't reach. DNServ has its own: choose Full recursion under Settings → Privacy."

func (b *builder) upstream() {
	sec := b.section(KeyUpstream, "Upstream DNS servers")
	var servers []string
	encrypted := true
	for _, line := range b.s.DNS.Upstreams {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "[/") {
			end := strings.Index(line, "/]")
			if end < 0 {
				sec.Skipped = append(sec.Skipped, Item{Text: line, Detail: "Not an address DNServ understands."})
				continue
			}
			for _, addr := range strings.Fields(line[end+2:]) {
				if a, ok := privateResolver(addr); ok {
					b.upstreamLocal = append(b.upstreamLocal, a)
				}
			}
			sec.Skipped = append(sec.Skipped, Item{Text: line, Detail: "DNServ sends every name to the same servers. Names for your local network go to your router instead (see Device names)."})
			continue
		}
		for _, one := range strings.Fields(line) { // "a b" are parallel upstreams
			out, why := mapUpstream(one)
			if why != "" {
				sec.Skipped = append(sec.Skipped, Item{Text: one, Detail: why})
				continue
			}
			if slices.Contains(servers, out) {
				continue
			}
			if !strings.HasPrefix(out, "https://") && !strings.HasPrefix(out, "tls://") {
				encrypted = false
			}
			servers = append(servers, out)
		}
	}
	if b.s.DNS.UpstreamsFile != "" {
		sec.Skipped = append(sec.Skipped, Item{Text: b.s.DNS.UpstreamsFile, Detail: "Upstreams from a file on the AdGuard Home server can't be read. Add them under Settings → Privacy."})
	}
	cur := b.eff.Upstream
	same := cur.Mode == "forward" && slices.Equal(cur.Servers, servers)
	var kept []string
	for _, srv := range servers {
		id := "upstream:" + srv
		switch {
		case same:
			sec.Have = append(sec.Have, Item{Text: srv})
		case b.skip(id):
		default:
			kept = append(kept, srv)
			sec.Items = append(sec.Items, Item{ID: id, Text: srv})
		}
	}
	if len(kept) == 0 {
		return
	}
	mode := "forward"
	patch := store.Settings{UpstreamMode: &mode, UpstreamServers: kept}
	// AdGuard Home's "parallel requests" and "fastest IP address" both ask
	// every server at once; its default load balancing is closest to
	// DNServ's fastest-first, which is the default here too.
	if d := b.s.DNS; d.UpstreamMode == "parallel" || d.UpstreamMode == "fastest_addr" || d.ParallelRequests {
		strategy := "parallel"
		patch.UpstreamStrategy = &strategy
	}
	b.p.patches[KeyUpstream] = patch
	now := strings.Join(cur.Servers, ", ")
	if cur.Mode != "forward" {
		now = map[string]string{"recursive": "full recursion", "tunnel": "recursion through a VPN"}[cur.Mode]
	}
	sec.Note = "Replaces DNServ's upstream (now " + now + ")."
	if patch.UpstreamStrategy != nil {
		sec.Note += " Every server is asked at once and the first answer is used, as AdGuard Home does now."
	}
	unchanged := b.st.Settings.UpstreamMode == nil && b.st.Settings.UpstreamServers == nil
	sec.Default = encrypted && unchanged
	if !encrypted {
		sec.Note += " Some of these servers are unencrypted, so your internet provider could see and change lookups; DNServ's encrypted default is more private."
	} else if !unchanged {
		sec.Note += " You've already chosen an upstream in DNServ, so this is off to start with."
	}
}

// privateResolver accepts "192.168.1.1", "192.168.1.1:53" or
// "udp://192.168.1.1" when the address is on the local network.
func privateResolver(s string) (string, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "udp://"), "tcp://")
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if a := ap.Addr().Unmap(); a.IsPrivate() || a.IsLinkLocalUnicast() {
			if ap.Port() == 53 {
				return a.String(), true
			}
			return netip.AddrPortFrom(a, ap.Port()).String(), true
		}
		return "", false
	}
	if a, err := netip.ParseAddr(s); err == nil && (a.Unmap().IsPrivate() || a.IsLinkLocalUnicast()) {
		return a.Unmap().String(), true
	}
	return "", false
}

func (b *builder) localDNS() {
	sec := b.section(KeyLocalDNS, "Router for device names")
	var cand string
	for _, s := range b.s.DNS.LocalPTR {
		if a, ok := privateResolver(strings.TrimSpace(s)); ok {
			cand = a
			break
		}
	}
	if cand == "" && len(b.upstreamLocal) > 0 {
		cand = b.upstreamLocal[0]
	}
	if cand == "" {
		return
	}
	cur := b.eff.DNS.LocalDNS
	if norm, err := config.LocalDNSAddr(cur); err == nil {
		if want, _ := config.LocalDNSAddr(cand); want == norm {
			sec.Have = append(sec.Have, Item{Text: cand})
			return
		}
	}
	id := "local_dns:" + cand
	if b.skip(id) {
		return
	}
	sec.Items = append(sec.Items, Item{ID: id, Text: cand, Detail: "AdGuard Home asked this address for local names and device names."})
	sec.Note = "DNServ asks your router what each device is called and sends local names (like printer.lan) to it."
	if cur != "" {
		sec.Note += " Replaces " + cur + "."
		sec.Default = false
	}
	b.p.patches[KeyLocalDNS] = store.Settings{LocalDNS: &cand}
}

func (b *builder) blocking() {
	sec := b.section(KeyBlocking, "How blocked names are answered")
	m := b.s.DNS.BlockingMode
	if m == "" {
		return
	}
	mode, detail := "null_ip", ""
	switch m {
	case "default", "null_ip":
	case "refused", "nxdomain":
		mode = m
	case "custom_ip":
		detail = "AdGuard Home answered with your own address; DNServ answers 0.0.0.0 instead."
	default:
		return
	}
	text := map[string]string{"null_ip": "Answer 0.0.0.0", "nxdomain": "Say the name doesn't exist (NXDOMAIN)", "refused": "Refuse the lookup (REFUSED)"}[mode]
	if b.eff.Filtering.BlockMode == mode {
		sec.Have = append(sec.Have, Item{Text: text, Detail: detail})
		return
	}
	id := "blocking:" + mode
	if b.skip(id) {
		return
	}
	sec.Items = append(sec.Items, Item{ID: id, Text: text, Detail: detail})
	b.p.patches[KeyBlocking] = store.Settings{BlockMode: &mode}
}

func (b *builder) access() {
	sec := b.section(KeyAccess, "Allowed networks")
	var nets []string
	for _, c := range b.s.Access.Allowed {
		c = strings.TrimSpace(c)
		if p, err := netip.ParsePrefix(c); err == nil {
			nets = append(nets, p.Masked().String())
		} else if a, err := netip.ParseAddr(c); err == nil {
			nets = append(nets, a.Unmap().String())
		} else if c != "" {
			sec.Skipped = append(sec.Skipped, Item{Text: c, Detail: "Only addresses and ranges can be allowed, not client IDs."})
		}
	}
	for _, c := range b.s.Access.Disallowed {
		if c = strings.TrimSpace(c); c != "" {
			sec.Skipped = append(sec.Skipped, Item{Text: c, Detail: "DNServ has no list of refused devices: it answers only the networks you allow."})
		}
	}
	if len(nets) == 0 {
		return
	}
	if slices.Equal(nets, b.eff.DNS.AllowedNets) {
		for _, n := range nets {
			sec.Have = append(sec.Have, Item{Text: n})
		}
		return
	}
	var kept []string
	for _, n := range nets {
		id := "access:" + n
		if !b.skip(id) {
			kept = append(kept, n)
			sec.Items = append(sec.Items, Item{ID: id, Text: n})
		}
	}
	if len(kept) == 0 {
		return
	}
	sec.Default = false
	sec.Note = "Only these devices and networks will be able to use DNServ. Check it includes every network your devices are on."
	b.p.patches[KeyAccess] = store.Settings{AllowedNets: kept}
}

// macKey normalizes a MAC address, or returns "".
func macKey(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return hw.String()
}

func clipName(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 64 {
		s = string([]rune(s)[:64])
	}
	return s
}

func (b *builder) devicesAndGroups() {
	devs := b.section(KeyDevices, "Device names")
	devs.Note = "Names show on the Devices page, Analytics and the Query log."
	groups := b.section(KeyGroups, "Devices with their own settings")
	groups.Note = "Each becomes a group on the Devices page, holding that device."

	byMAC := map[string]string{}
	for _, l := range b.s.StaticLeases {
		if k := macKey(l.MAC); k != "" {
			byMAC[k] = l.IP
		}
	}
	claimed := map[string]string{} // address -> device name, from this import
	groupNames := map[string]bool{}
	for _, g := range b.st.Groups {
		groupNames[strings.ToLower(g.Name)] = true
	}

	addDevice := func(name string, addrs []string, from string) int {
		name = clipName(name)
		if name == "" {
			return -1
		}
		var fresh []string
		existing := ""
		for _, a := range addrs {
			if other, ok := claimed[a]; ok {
				devs.Skipped = append(devs.Skipped, Item{Text: name + " (" + a + ")", Detail: "Also listed for " + other + "; the first one keeps it."})
				continue
			}
			if d := b.st.DeviceByAddr(a); d != nil {
				existing = d.ID
				if !strings.EqualFold(d.Name, name) {
					devs.Skipped = append(devs.Skipped, Item{Text: name + " (" + a + ")", Detail: "Already named " + d.Name + " in DNServ."})
				} else {
					devs.Have = append(devs.Have, Item{Text: name, Detail: a})
				}
				continue
			}
			fresh = append(fresh, a)
		}
		for _, a := range fresh {
			claimed[a] = name
		}
		if len(fresh) == 0 {
			if existing == "" {
				return -1
			}
			b.p.Devices = append(b.p.Devices, DevicePlan{Name: name, Existing: existing, Group: -1})
			return len(b.p.Devices) - 1
		}
		id := "devices:" + name + "@" + strings.Join(fresh, ",")
		if b.skip(id) {
			return -1
		}
		devs.Items = append(devs.Items, Item{ID: id, Text: name, Detail: joinDetail(strings.Join(fresh, ", "), from)})
		b.p.Devices = append(b.p.Devices, DevicePlan{ItemID: id, Name: name, Addrs: fresh, Group: -1})
		return len(b.p.Devices) - 1
	}

	global := map[string]bool{}
	for _, s := range b.services {
		global[s] = true
	}
	for _, c := range b.s.Clients {
		var addrs []string
		from := ""
		for _, id := range c.IDs {
			id = strings.TrimSpace(id)
			if a, err := netip.ParseAddr(id); err == nil {
				addrs = append(addrs, a.Unmap().String())
			} else if _, err := netip.ParsePrefix(id); err == nil {
				devs.Skipped = append(devs.Skipped, Item{Text: c.Name + " (" + id + ")", Detail: "A range of addresses: DNServ names single addresses. Put the devices in a group instead."})
			} else if k := macKey(id); k != "" {
				if ip, ok := byMAC[k]; ok {
					if a, err := netip.ParseAddr(ip); err == nil {
						addrs = append(addrs, a.Unmap().String())
						from = "address from its DHCP reservation"
						continue
					}
				}
				devs.Skipped = append(devs.Skipped, Item{Text: c.Name + " (" + id + ")", Detail: "DNServ sees addresses, not MAC addresses. Give the device a fixed address in your router, then name it on the Devices page."})
			} else {
				devs.Skipped = append(devs.Skipped, Item{Text: c.Name + " (" + id + ")", Detail: "Client IDs (from encrypted DNS addresses) aren't supported yet."})
			}
		}
		addrs = dedupe(addrs)
		di := -1
		if len(addrs) > 0 {
			di = addDevice(c.Name, addrs, from)
		}

		// Its own settings become a group.
		g := GroupPlan{Name: clipName(c.Name)}
		var why []string
		if !c.UseGlobalSettings && !c.FilteringEnabled {
			g.SkipBlocklists = true
			why = append(why, "no blocklists")
		}
		if !c.UseGlobalServices {
			own := map[string]bool{}
			for _, id := range c.BlockedServices {
				own[id] = true
				if global[id] {
					continue
				}
				if sv, ok := b.s.Services[id]; ok {
					r, _ := serviceRules(sv)
					g.Rules = append(g.Rules, r...)
					why = append(why, "blocks "+sv.Name)
				}
			}
			for _, id := range b.services {
				if !own[id] {
					r, _ := serviceRules(b.s.Services[id])
					for _, x := range r {
						g.Rules = append(g.Rules, "@@"+x)
					}
					why = append(why, "allows "+b.s.Services[id].Name)
				}
			}
			if hasSchedule(c.Schedule) {
				groups.Skipped = append(groups.Skipped, Item{Text: c.Name + ": blocked services schedule", Detail: "Recreate it as a group schedule on the Devices page."})
			}
		}
		if len(why) == 0 {
			continue
		}
		text := g.Name + ": " + strings.Join(why, ", ")
		switch {
		case di < 0:
			groups.Skipped = append(groups.Skipped, Item{Text: text, Detail: "The device has no address DNServ can use."})
			continue
		case len(g.Rules) > store.MaxGroupRules:
			groups.Skipped = append(groups.Skipped, Item{Text: text, Detail: fmt.Sprintf("More than %d rules.", store.MaxGroupRules)})
			continue
		case groupNames[strings.ToLower(g.Name)]:
			groups.Have = append(groups.Have, Item{Text: text, Detail: "There's already a group with this name."})
			continue
		}
		if d := b.p.Devices[di]; d.Existing != "" {
			if old := b.st.Devices[d.Existing]; old != nil && old.Group != "" {
				groups.Skipped = append(groups.Skipped, Item{Text: text, Detail: old.Name + " is already in a DNServ group."})
				continue
			}
		}
		g.ItemID = "groups:" + g.Name
		if b.skip(g.ItemID) {
			continue
		}
		groupNames[strings.ToLower(g.Name)] = true
		b.p.Groups = append(b.p.Groups, g)
		b.p.Devices[di].Group = len(b.p.Groups) - 1
		groups.Items = append(groups.Items, Item{ID: g.ItemID, Text: text})
	}
	for _, l := range b.s.StaticLeases {
		a, err := netip.ParseAddr(strings.TrimSpace(l.IP))
		if err != nil || strings.TrimSpace(l.Hostname) == "" {
			continue
		}
		addr := a.Unmap().String()
		if _, ok := claimed[addr]; ok {
			continue
		}
		if d := b.st.DeviceByAddr(addr); d != nil {
			continue
		}
		addDevice(l.Hostname, []string{addr}, "DHCP reservation")
	}
}

func hasSchedule(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for k, v := range m {
		if k != "time_zone" && string(v) != "null" {
			return true
		}
	}
	return false
}

func (b *builder) other() {
	sec := b.section(KeyOther, "Not moved")
	sec.Info = true
	sec.Default = false
	note := func(text, detail string) { sec.Skipped = append(sec.Skipped, Item{Text: text, Detail: detail}) }
	if b.s.DHCPEnabled {
		note("AdGuard Home is handing out addresses (DHCP)", "DNServ doesn't do DHCP. Turn DHCP back on in your router before you switch AdGuard Home off, or devices will lose their connection.")
	}
	if b.s.SafeBrowsing {
		note("Safe browsing", "DNServ doesn't use AdGuard's lookup service. Tick Extra malware and phishing protection under Settings → Filtering to block scam and malware sites.")
	}
	if b.s.Parental {
		note("Parental control", "Add an adult-content blocklist under Settings → Filtering, or give children's devices a group with a schedule.")
	}
	safe, own, perDevice := b.s.SafeSearch, 0, 0
	for _, c := range b.s.Clients {
		if !c.UseGlobalSettings && (c.SafeSearchOld || c.SafeSearch != nil && c.SafeSearch.Enabled || c.ParentalEnabled || c.SafeBrowsing) {
			perDevice++
		}
		if len(c.Upstreams) > 0 {
			own++
		}
	}
	if safe {
		note("Safe search", "DNServ doesn't force safe search yet.")
	}
	if perDevice > 0 {
		note(fmt.Sprintf("Safe search, safe browsing or parental control for %d devices", perDevice), "Not available per device in DNServ.")
	}
	if own > 0 {
		note(fmt.Sprintf("Upstream servers for %d devices", own), "Every device uses the same upstream in DNServ.")
	}
	if !b.s.FilteringEnabled && len(b.s.Filters) > 0 {
		note("Filtering is turned off in AdGuard Home", "Lists are still imported, and DNServ keeps filtering on.")
	}
	if b.s.AutoClients > 0 {
		names := "names"
		if b.s.AutoClients == 1 {
			names = "name"
		}
		note(fmt.Sprintf("%d device %s AdGuard Home found by itself", b.s.AutoClients, names), "DNServ asks your router for names instead (Router for device names, above).")
	}
	if len(b.s.Missing) > 0 {
		note("Couldn't read: "+strings.Join(b.s.Missing, ", "), "This version of AdGuard Home doesn't offer them, or the account can't see them.")
	}
	note("Query log and statistics", "History starts fresh in DNServ.")
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func joinDetail(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " · ")
}
