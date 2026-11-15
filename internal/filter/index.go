package filter

import (
	"encoding/binary"
	"math/bits"
	"slices"
	"strings"
)

// Source identifies where a rule came from.
type Source struct {
	ID   uint16
	Name string
	// Tier orders precedence: custom rules (TierCustom) win over lists.
	Tier Tier
	// Key names the source for a Selection: "list:<url>" for a list,
	// "custom", "bypass" or "service:<id>" for the household's own rules.
	Key string
	// Household is true when the source applies to devices that follow
	// the household settings. A list only some groups use is not.
	Household bool
}

// Tier is a precedence level. Within a tier, allow beats block.
type Tier uint8

const (
	TierList Tier = iota
	TierCustom
)

// Match explains a filtering decision.
type Match struct {
	Blocked bool
	// Allowed is true when an allow rule matched (whether or not a block
	// rule also matched).
	Allowed bool
	Rule    Rule
	Source  string
}

// Index is an immutable compiled set of rules. Lookups cost one map probe
// per label of the queried name, independent of the number of rules.
//
// Each entry also records every source that has it (as an interned set),
// so a group can use a different choice of sources (LookupFor) at the
// same cost per label.
type Index struct {
	sources []Source
	sets    [][]uint64 // bit per source id; sets[0] is empty
	block   tierMaps
	allow   tierMaps
	count   int
}

type tierMaps struct {
	exact, suffix, sub map[string]ref
	pats               *patterns
}

// ref is packed to keep the maps small: the strongest household source
// and its tier (src is noSrc when no household source has the entry), and
// the set of every source that has it.
type ref struct {
	set  uint32
	src  uint16
	tier Tier
}

const noSrc = ^uint16(0)

func newTierMaps() tierMaps {
	return tierMaps{exact: map[string]ref{}, suffix: map[string]ref{}, sub: map[string]ref{}, pats: &patterns{}}
}

// Builder accumulates rules into a new Index.
type Builder struct {
	idx *Index
	// pats maps a pattern rule's text to its place in its tier's list.
	pats map[string]int
	bad  []Rule
	// setIDs interns source sets; union memoizes set + source -> set.
	setIDs map[string]uint32
	union  map[uint64]uint32
}

// NewBuilder starts an empty index.
func NewBuilder() *Builder {
	return &Builder{idx: &Index{block: newTierMaps(), allow: newTierMaps(), sets: [][]uint64{nil}},
		pats: map[string]int{}, setIDs: map[string]uint32{"": 0}, union: map[uint64]uint32{}}
}

// AddSource registers a household source and returns its id.
func (b *Builder) AddSource(name string, tier Tier) uint16 {
	return b.AddSourceKey(name, tier, "", true)
}

// AddSourceKey registers a source with a Selection key, saying whether it
// applies to the household.
func (b *Builder) AddSourceKey(name string, tier Tier, key string, household bool) uint16 {
	id := uint16(len(b.idx.sources))
	b.idx.sources = append(b.idx.sources, Source{ID: id, Name: name, Tier: tier, Key: key, Household: household})
	return id
}

// with returns the id of set plus src.
func (b *Builder) with(set uint32, src uint16) uint32 {
	k := uint64(set)<<16 | uint64(src)
	if id, ok := b.union[k]; ok {
		return id
	}
	n := slices.Clone(b.idx.sets[set])
	for len(n) <= int(src/64) {
		n = append(n, 0)
	}
	n[src/64] |= 1 << (src % 64)
	buf := make([]byte, 0, 8*len(n))
	for _, w := range n {
		buf = binary.LittleEndian.AppendUint64(buf, w)
	}
	id, ok := b.setIDs[string(buf)]
	if !ok {
		id = uint32(len(b.idx.sets))
		b.idx.sets = append(b.idx.sets, n)
		b.setIDs[string(buf)] = id
	}
	b.union[k] = id
	return id
}

// merge adds source s (id src) to the entry old (ok: it exists).
func (b *Builder) merge(old ref, ok bool, src uint16, s Source) ref {
	if !ok {
		old = ref{src: noSrc}
	}
	old.set = b.with(old.set, src)
	if s.Household && (old.src == noSrc || s.Tier > old.tier) {
		old.src, old.tier = src, s.Tier
	}
	return old
}

// Add inserts a rule from a source. When the same domain appears in
// several sources, every source is remembered; a lookup reports the one
// with the higher tier, and within a tier the first.
func (b *Builder) Add(src uint16, r Rule) {
	s := b.idx.sources[src]
	m := &b.idx.block
	if r.Allow {
		m = &b.idx.allow
	}
	if r.Bad {
		b.bad = append(b.bad, r)
		return
	}
	var target map[string]ref
	switch r.Kind {
	case Pattern:
		b.addPattern(m.pats, s, r)
		return
	case Exact:
		target = m.exact
	case Suffix:
		target = m.suffix
	default:
		target = m.sub
	}
	old, ok := target[r.Domain]
	if !ok {
		b.idx.count++
	}
	target[r.Domain] = b.merge(old, ok, src, s)
}

func (b *Builder) addPattern(ps *patterns, s Source, r Rule) {
	key := r.Text()
	if i, ok := b.pats[key]; ok {
		ps.list[i].ref = b.merge(ps.list[i].ref, true, s.ID, s)
		return
	}
	re, err := compilePattern(r.Domain)
	if err != nil {
		return
	}
	b.pats[key] = len(ps.list)
	ps.list = append(ps.list, newPattern(re, r, b.merge(ref{}, false, s.ID, s)))
	b.idx.count++
}

// Build returns the finished index, after $badfilter rules have switched
// off the rules they name. The builder must not be used after.
func (b *Builder) Build() *Index {
	for _, r := range b.bad {
		m := &b.idx.block
		if r.Allow {
			m = &b.idx.allow
		}
		var target map[string]ref
		switch r.Kind {
		case Exact:
			target = m.exact
		case Suffix:
			target = m.suffix
		case SubOnly:
			target = m.sub
		case Pattern:
			r.Bad = false
			key := r.Text()
			if _, ok := b.pats[key]; ok {
				delete(b.pats, key)
				m.pats.list = slices.DeleteFunc(m.pats.list, func(p pattern) bool { return p.rule.Text() == key })
				b.idx.count--
			}
			continue
		}
		if _, ok := target[r.Domain]; ok {
			delete(target, r.Domain)
			b.idx.count--
		}
	}
	b.idx.block.pats.build()
	b.idx.allow.pats.build()
	return b.idx
}

// Len is the number of distinct rules indexed.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return ix.count
}

// Lookup decides whether name (already normalized: lowercase, no trailing
// dot) is blocked, for a device that follows the household settings.
func (ix *Index) Lookup(name string) Match { return ix.lookup(name, nil) }

// LookupMask is Lookup using only the sources in mask (a bit per source
// id, from Selection), instead of the household's.
func (ix *Index) LookupMask(name string, mask []uint64) Match {
	if mask == nil {
		mask = []uint64{}
	}
	return ix.lookup(name, mask)
}

func (ix *Index) lookup(name string, mask []uint64) Match {
	if ix == nil {
		return Match{}
	}
	bRule, bSrc, bTier, bOK := ix.find(&ix.block, name, mask)
	aRule, aSrc, aTier, aOK := ix.find(&ix.allow, name, mask)
	switch {
	case aOK && (!bOK || aTier >= bTier):
		aRule.Allow = true
		return Match{Allowed: true, Rule: aRule, Source: ix.sources[aSrc].Name}
	case bOK:
		return Match{Blocked: true, Rule: bRule, Source: ix.sources[bSrc].Name}
	}
	return Match{}
}

// eff is the source and tier an entry counts as under mask (nil: the
// household's); ok is false when no source in mask has it.
func (ix *Index) eff(rf ref, mask []uint64) (uint16, Tier, bool) {
	if mask == nil {
		return rf.src, rf.tier, rf.src != noSrc
	}
	set := ix.sets[rf.set]
	best, bt := noSrc, Tier(0)
	for w := 0; w < len(set) && w < len(mask); w++ {
		for x := set[w] & mask[w]; x != 0; x &= x - 1 {
			id := uint16(w*64 + bits.TrailingZeros64(x))
			if t := ix.sources[id].Tier; best == noSrc || t > bt {
				best, bt = id, t
			}
		}
	}
	return best, bt, best != noSrc
}

// find returns the strongest-tier rule matching name; on ties the most
// specific match wins.
func (ix *Index) find(m *tierMaps, name string, mask []uint64) (Rule, uint16, Tier, bool) {
	var (
		best     Rule
		bestSrc  uint16
		bestTier Tier
		found    bool
	)
	consider := func(r Rule, rf ref) {
		src, t, ok := ix.eff(rf, mask)
		if ok && (!found || t > bestTier) {
			best, bestSrc, bestTier, found = r, src, t, true
		}
	}
	if rf, ok := m.exact[name]; ok {
		consider(Rule{Domain: name, Kind: Exact}, rf)
	}
	if rf, ok := m.suffix[name]; ok {
		consider(Rule{Domain: name, Kind: Suffix}, rf)
	}
	for d := name; ; {
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
		if rf, ok := m.suffix[d]; ok {
			consider(Rule{Domain: d, Kind: Suffix}, rf)
		}
		if rf, ok := m.sub[d]; ok {
			consider(Rule{Domain: d, Kind: SubOnly}, rf)
		}
	}
	if p, src, t, ok := m.pats.find(name, ix, mask); ok && (!found || t > bestTier) {
		best, bestSrc, bestTier, found = p.rule, src, t, true
	}
	return best, bestSrc, bestTier, found
}

// Sources lists the index's sources, by id.
func (ix *Index) Sources() []Source {
	if ix == nil {
		return nil
	}
	return ix.sources
}
