// Package policy compiles device groups into per-client filtering
// decisions: a group's own rules, its schedules, and whether it uses the
// shared blocklists.
package policy

import (
	"net/netip"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/store"
)

// Set maps client addresses to their group. A nil *Set has no groups.
type Set struct {
	byAddr map[netip.Addr]*Group
	byID   map[string]*Group
}

// Group is one compiled group.
type Group struct {
	ID, Name string
	// Shared picks the shared lists and household rules the group uses;
	// nil means the household's. Shared.Empty() means none at all.
	Shared *filter.Selection
	// SafeSearch overrides the household setting when not nil.
	SafeSearch *bool
	rules      *filter.Index
	schedules  []schedule
}

type schedule struct {
	name       string
	days       uint8 // bit per weekday, Sunday = bit 0
	start, end int   // minutes after midnight
	blockAll   bool
	rules      *filter.Index
}

// Build compiles the groups in st, with the custom rules in st's settings.
func Build(st *store.State) *Set {
	var rules []string
	if st.Settings.Rules != nil {
		rules = *st.Settings.Rules
	}
	return BuildWith(st, rules)
}

// BuildWith compiles the groups in st. rules are the household's custom
// rules: the ones with a $client modifier are added to the groups, devices
// and addresses they name, as if they were their own rules. Rules that
// don't parse are skipped (the API refuses them, so this only matters for
// hand-edited state).
func BuildWith(st *store.State, rules []string) *Set {
	s := &Set{byAddr: map[netip.Addr]*Group{}, byID: map[string]*Group{}}
	compiled := s.byID
	for id, g0 := range st.Groups {
		g := g0.Shared()
		cg := &Group{ID: id, Name: g.Name, rules: index("Group "+g.Name, g.Rules, g.Services, nil)}
		if g.ListMode == "choose" || g.HouseholdRules == "off" {
			sel := &filter.Selection{NoHousehold: g.HouseholdRules == "off"}
			if g.ListMode == "choose" {
				sel.Lists = map[string]bool{}
				for _, u := range g.Lists {
					sel.Lists[u] = true
				}
			}
			cg.Shared = sel
		}
		switch g.SafeSearch {
		case "on", "off":
			on := g.SafeSearch == "on"
			cg.SafeSearch = &on
		}
		for _, sc := range g.Schedules {
			start, err1 := store.ParseClock(sc.Start)
			end, err2 := store.ParseClock(sc.End)
			if err1 != nil || err2 != nil {
				continue
			}
			c := schedule{name: sc.Name, start: start, end: end, blockAll: sc.BlockAll, rules: index("Schedule "+sc.Name, sc.Rules, sc.Services, nil)}
			for _, d := range sc.Days {
				c.days |= 1 << (d % 7)
			}
			cg.schedules = append(cg.schedules, c)
		}
		compiled[id] = cg
	}
	for _, d := range st.Devices {
		g := compiled[d.Group]
		if g == nil {
			continue
		}
		for _, a := range d.Addrs {
			if ip, err := netip.ParseAddr(a); err == nil {
				s.byAddr[ip.Unmap()] = g
			}
		}
	}
	s.addTargeted(st, rules)
	return s
}

// addTargeted gives each address named by a $client rule (through its
// group, its device or itself) a copy of its group with those rules added.
func (s *Set) addTargeted(st *store.State, rules []string) {
	byAddr := map[netip.Addr][]string{}
	add := func(a string, rule string) {
		if ip, err := netip.ParseAddr(a); err == nil {
			ip = ip.Unmap()
			if l := byAddr[ip]; len(l) == 0 || l[len(l)-1] != rule {
				byAddr[ip] = append(l, rule)
			}
		}
	}
	for _, line := range rules {
		rest, clients, has, err := filter.ClientTargets(line)
		if !has || err != nil {
			continue
		}
		for _, c := range clients {
			if _, err := netip.ParseAddr(c); err == nil {
				add(c, rest)
				continue
			}
			for _, d := range st.Devices {
				in := strings.EqualFold(d.Name, c)
				if g := st.Groups[d.Group]; g != nil && strings.EqualFold(g.Name, c) {
					in = true
				}
				if in {
					for _, a := range d.Addrs {
						add(a, rest)
					}
				}
			}
		}
	}
	if len(byAddr) == 0 {
		return
	}
	// Addresses with the same group and the same extra rules share a copy.
	shared := map[string]*Group{}
	for ip, extra := range byAddr {
		base := s.byAddr[ip]
		key := strings.Join(extra, "\n")
		if base != nil {
			key = base.ID + "\x00" + key
		}
		g := shared[key]
		if g == nil {
			if base != nil {
				cp := *base
				g = &cp
				src := st.Groups[base.ID].Shared()
				g.rules = index("Group "+base.Name, src.Rules, src.Services, extra)
			} else {
				g = &Group{rules: index("", nil, nil, extra)}
			}
			shared[key] = g
		}
		s.byAddr[ip] = g
	}
}

// index compiles a group's (or schedule's) own rules and services, plus
// targeted household custom rules (shown as "Custom rules").
func index(source string, lines, services, targeted []string) *filter.Index {
	if len(lines) == 0 && len(services) == 0 && len(targeted) == 0 {
		return nil
	}
	b := filter.NewBuilder()
	add := func(src uint16, lines []string) {
		for _, l := range lines {
			rules, ok, _ := filter.ParseLine(l)
			if !ok {
				continue
			}
			for _, r := range rules {
				b.Add(src, r)
			}
		}
	}
	if len(targeted) > 0 {
		add(b.AddSource("Custom rules", filter.TierCustom), targeted)
	}
	filter.AddServices(b, services)
	if len(lines) > 0 {
		add(b.AddSource(source, filter.TierCustom), lines)
	}
	return b.Build()
}

// Group returns a compiled group by id, or nil.
func (s *Set) Group(id string) *Group {
	if s == nil {
		return nil
	}
	return s.byID[id]
}

// For returns the group of a client, or nil.
func (s *Set) For(addr netip.Addr) *Group {
	if s == nil || len(s.byAddr) == 0 {
		return nil
	}
	return s.byAddr[addr.Unmap()]
}

// Check applies the group's own policy to a normalized name at time now
// (in the node's time zone). decided is true when the group settled the
// question: m.Blocked says which way. Otherwise the shared filter decides,
// with the group's Shared selection.
//
// Order: the group's allow rules win over everything, then active
// schedules, then the group's block rules.
func (g *Group) Check(name string, now time.Time) (m filter.Match, decided bool) {
	gm := g.rules.Lookup(name)
	if gm.Allowed {
		return gm, true
	}
	for i := range g.schedules {
		sc := &g.schedules[i]
		if !sc.active(now) {
			continue
		}
		if sc.blockAll {
			return filter.Match{Blocked: true, Source: "Schedule " + sc.name}, true
		}
		if sm := sc.rules.Lookup(name); sm.Blocked {
			return sm, true
		}
	}
	if gm.Blocked {
		return gm, true
	}
	return filter.Match{}, false
}

// CheckSchedules is Check limited to the group's schedules, for while
// filtering is paused: an allow rule in the group still wins, and only
// a schedule running at now blocks.
func (g *Group) CheckSchedules(name string, now time.Time) filter.Match {
	if len(g.schedules) == 0 {
		return filter.Match{}
	}
	allowChecked := false
	for i := range g.schedules {
		sc := &g.schedules[i]
		if !sc.active(now) {
			continue
		}
		if !allowChecked {
			if g.rules.Lookup(name).Allowed {
				return filter.Match{}
			}
			allowChecked = true
		}
		if sc.blockAll {
			return filter.Match{Blocked: true, Source: "Schedule " + sc.name}
		}
		if sm := sc.rules.Lookup(name); sm.Blocked {
			return sm
		}
	}
	return filter.Match{}
}

// HasSchedules reports whether the group has any schedules.
func (g *Group) HasSchedules() bool { return len(g.schedules) > 0 }

// Active lists the names of the group's schedules running at now.
func (g *Group) Active(now time.Time) []string {
	var out []string
	for i := range g.schedules {
		if g.schedules[i].active(now) {
			out = append(out, g.schedules[i].name)
		}
	}
	return out
}

func (sc *schedule) active(now time.Time) bool {
	m := now.Hour()*60 + now.Minute()
	wd := int(now.Weekday())
	on := func(d int) bool { return sc.days&(1<<d) != 0 }
	if sc.start < sc.end {
		return on(wd) && m >= sc.start && m < sc.end
	}
	// Runs past midnight: started today, or started yesterday.
	return (on(wd) && m >= sc.start) || (on((wd+6)%7) && m < sc.end)
}
