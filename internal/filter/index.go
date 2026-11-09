package filter

import "strings"

// Source identifies where a rule came from.
type Source struct {
	ID   uint16
	Name string
	// Tier orders precedence: custom rules (TierCustom) win over lists.
	Tier Tier
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
type Index struct {
	sources []Source
	block   tierMaps
	allow   tierMaps
	count   int
}

type tierMaps struct {
	exact, suffix, sub map[string]ref
}

// ref is packed to keep the maps small: source id and tier.
type ref struct {
	src  uint16
	tier Tier
}

func newTierMaps() tierMaps {
	return tierMaps{exact: map[string]ref{}, suffix: map[string]ref{}, sub: map[string]ref{}}
}

// Builder accumulates rules into a new Index.
type Builder struct {
	idx *Index
}

// NewBuilder starts an empty index.
func NewBuilder() *Builder {
	return &Builder{idx: &Index{block: newTierMaps(), allow: newTierMaps()}}
}

// AddSource registers a source and returns its id.
func (b *Builder) AddSource(name string, tier Tier) uint16 {
	id := uint16(len(b.idx.sources))
	b.idx.sources = append(b.idx.sources, Source{ID: id, Name: name, Tier: tier})
	return id
}

// Add inserts a rule from a source. When the same domain appears in
// several sources, the higher tier is kept; within a tier the first wins.
func (b *Builder) Add(src uint16, r Rule) {
	s := b.idx.sources[src]
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
	default:
		target = m.sub
	}
	if old, ok := target[r.Domain]; ok && old.tier >= s.Tier {
		return
	}
	target[r.Domain] = ref{src: src, tier: s.Tier}
	b.idx.count++
}

// Build returns the finished index. The builder must not be used after.
func (b *Builder) Build() *Index { return b.idx }

// Len is the number of distinct rules indexed.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return ix.count
}

// Lookup decides whether name (already normalized: lowercase, no trailing
// dot) is blocked.
func (ix *Index) Lookup(name string) Match {
	if ix == nil {
		return Match{}
	}
	bRule, bRef, bOK := ix.block.find(name)
	aRule, aRef, aOK := ix.allow.find(name)
	switch {
	case aOK && (!bOK || aRef.tier >= bRef.tier):
		aRule.Allow = true
		return Match{Allowed: true, Rule: aRule, Source: ix.sources[aRef.src].Name}
	case bOK:
		return Match{Blocked: true, Rule: bRule, Source: ix.sources[bRef.src].Name}
	}
	return Match{}
}

// find returns the strongest-tier rule matching name; on ties the most
// specific match wins.
func (m tierMaps) find(name string) (Rule, ref, bool) {
	var (
		best     Rule
		bestR    ref
		found    bool
		consider = func(r Rule, rf ref) {
			if !found || rf.tier > bestR.tier {
				best, bestR, found = r, rf, true
			}
		}
	)
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
	return best, bestR, found
}
