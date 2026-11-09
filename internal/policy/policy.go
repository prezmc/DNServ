// Package policy compiles device groups into per-client filtering
// decisions: a group's own rules, its schedules, and whether it uses the
// shared blocklists.
package policy

import (
	"net/netip"
	"time"

	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/store"
)

// Set maps client addresses to their group. A nil *Set has no groups.
type Set struct {
	byAddr map[netip.Addr]*Group
	byID   map[string]*Group
}

// Group is one compiled group.
type Group struct {
	ID, Name string
	// SkipShared means the shared blocklists and custom rules don't apply.
	SkipShared bool
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

// Build compiles the groups in st. Rules that don't parse are skipped
// (the API refuses them, so this only matters for hand-edited state).
func Build(st *store.State) *Set {
	s := &Set{byAddr: map[netip.Addr]*Group{}, byID: map[string]*Group{}}
	compiled := s.byID
	for id, g := range st.Groups {
		cg := &Group{ID: id, Name: g.Name, SkipShared: g.SkipBlocklists, rules: index("Group "+g.Name, g.Rules)}
		for _, sc := range g.Schedules {
			start, err1 := store.ParseClock(sc.Start)
			end, err2 := store.ParseClock(sc.End)
			if err1 != nil || err2 != nil {
				continue
			}
			c := schedule{name: sc.Name, start: start, end: end, blockAll: sc.BlockAll, rules: index("Schedule "+sc.Name, sc.Rules)}
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
	return s
}

func index(source string, lines []string) *filter.Index {
	if len(lines) == 0 {
		return nil
	}
	b := filter.NewBuilder()
	src := b.AddSource(source, filter.TierCustom)
	for _, l := range lines {
		rules, ok, _ := filter.ParseLine(l)
		if !ok {
			continue
		}
		for _, r := range rules {
			b.Add(src, r)
		}
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
// unless SkipShared.
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
