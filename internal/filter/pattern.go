package filter

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// compilePattern turns a pattern rule body into a regexp over the
// normalized query name. Regex rules (/.../) use Go's RE2 syntax, so
// lookaheads and backreferences are rejected and the rule is skipped.
func compilePattern(p string) (*regexp.Regexp, error) {
	if isRegexRule(p) {
		return regexp.Compile("(?i)" + p[1:len(p)-1])
	}
	var b strings.Builder
	switch {
	case strings.HasPrefix(p, "||"):
		b.WriteString(`(?:^|\.)`)
		p = p[2:]
	case strings.HasPrefix(p, "://"):
		b.WriteString("^")
		p = p[3:]
	case strings.HasPrefix(p, "|"):
		b.WriteString("^")
		p = p[1:]
	}
	end := ""
	for _, suf := range []string{"^|", "^", "|"} {
		if strings.HasSuffix(p, suf) {
			p, end = strings.TrimSuffix(p, suf), "$"
			break
		}
	}
	for i, part := range strings.Split(p, "*") {
		if i > 0 {
			b.WriteString(".*")
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString(end)
	return regexp.Compile(b.String())
}

type pattern struct {
	re *regexp.Regexp
	// lits is literal text every match contains, checked before the
	// regexp because it is far cheaper.
	lits []string
	// minLen and maxLen bound the length of a matching name (maxLen < 0:
	// no bound), which rules out most names for long regexes cheaply.
	minLen, maxLen int
	rule           Rule
	ref            ref
	except         []string
}

func newPattern(re *regexp.Regexp, r Rule, rf ref) pattern {
	lits, _ := hostLiterals(re)
	p := pattern{re: re, lits: lits, rule: r, ref: rf, except: splitExcept(r.Except), maxLen: -1}
	if tre, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		tre = tre.Simplify()
		p.minLen, _ = lenBounds(tre)
		if tre.Op == syntax.OpConcat && len(tre.Sub) > 1 &&
			tre.Sub[0].Op == syntax.OpBeginText && tre.Sub[len(tre.Sub)-1].Op == syntax.OpEndText {
			_, p.maxLen = lenBounds(tre)
		}
	}
	return p
}

// lenBounds gives the shortest and longest text (in bytes, for the ASCII
// names DNS uses) a regexp matches; max is -1 when unbounded.
func lenBounds(re *syntax.Regexp) (lo, hi int) {
	switch re.Op {
	case syntax.OpLiteral:
		return len(string(re.Rune)), len(string(re.Rune))
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1, 1
	case syntax.OpEmptyMatch, syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine,
		syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, 0
	case syntax.OpCapture:
		return lenBounds(re.Sub[0])
	case syntax.OpStar:
		return 0, -1
	case syntax.OpPlus:
		l, _ := lenBounds(re.Sub[0])
		return l, -1
	case syntax.OpQuest:
		_, h := lenBounds(re.Sub[0])
		return 0, h
	case syntax.OpRepeat:
		l, h := lenBounds(re.Sub[0])
		if re.Max < 0 || h < 0 {
			return l * re.Min, -1
		}
		return l * re.Min, h * re.Max
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			l, h := lenBounds(sub)
			lo += l
			if hi >= 0 {
				if h < 0 {
					hi = -1
				} else {
					hi += h
				}
			}
		}
		return lo, hi
	case syntax.OpAlternate:
		lo = -1
		for _, sub := range re.Sub {
			l, h := lenBounds(sub)
			if lo < 0 || l < lo {
				lo = l
			}
			if hi >= 0 && (h < 0 || h > hi) {
				hi = h
			}
		}
		return max(lo, 0), hi
	}
	return 0, -1
}

// hostLiterals returns the literals a match must contain, and
// whether the pattern can match a DNS name at all: one that needs ":",
// "/" or other URL characters never can, so lists' URL rules are skipped.
func hostLiterals(re *regexp.Regexp) (lits []string, possible bool) {
	tre, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil, false
	}
	tre = tre.Simplify()
	subs := []*syntax.Regexp{tre}
	if tre.Op == syntax.OpConcat {
		subs = tre.Sub
	}
	for _, sub := range subs {
		if sub.Op == syntax.OpCapture && len(sub.Sub) == 1 && sub.Sub[0].Op == syntax.OpLiteral {
			sub = sub.Sub[0]
		}
		if sub.Op != syntax.OpLiteral {
			continue
		}
		lit := strings.ToLower(string(sub.Rune))
		for i := 0; i < len(lit); i++ {
			switch c := lit[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
			default:
				return nil, false
			}
		}
		lits = append(lits, lit) // names are lowercase, so lowering a folded literal is safe
	}
	return lits, true
}

func (p *pattern) matches(name string) bool {
	if len(name) < p.minLen || p.maxLen >= 0 && len(name) > p.maxLen {
		return false
	}
	for _, l := range p.lits {
		if !strings.Contains(name, l) {
			return false
		}
	}
	if !p.re.MatchString(name) {
		return false
	}
	for _, d := range p.except {
		if name == d || strings.HasSuffix(name, "."+d) {
			return false
		}
	}
	return true
}

// patterns holds a tier's pattern rules, indexed by three letters of the
// literal text each needs, so a name only tries the patterns whose letters
// it contains.
type patterns struct {
	list  []pattern
	byTri map[string][]int32
	// tris has a bit set for each indexed three letters, by triHash, so
	// most of a name's letters are ruled out without a map probe.
	tris [triBits / 64]uint64
	scan []int32
}

func (ps *patterns) build() {
	ps.byTri = map[string][]int32{}
	ps.scan = nil
	seen := map[string]int{}
	for i := range ps.list {
		for _, l := range ps.list[i].lits {
			for j := 0; j+3 <= len(l); j++ {
				seen[l[j:j+3]]++
			}
		}
	}
	// Prefer three letters few patterns share and few names contain:
	// ones with a dot ("le.", ".co") or common words show up everywhere.
	score := func(t string) int {
		n := seen[t]
		if strings.IndexByte(t, '.') >= 0 || strings.IndexByte(t, '-') >= 0 {
			n += 1000
		}
		if commonTri[t] {
			n += 2000
		}
		return n
	}
	for i := range ps.list {
		tri := ""
		for _, l := range ps.list[i].lits {
			for j := 0; j+3 <= len(l); j++ {
				if t := l[j : j+3]; tri == "" || score(t) < score(tri) {
					tri = t
				}
			}
		}
		if tri == "" {
			ps.scan = append(ps.scan, int32(i))
			continue
		}
		ps.byTri[tri] = append(ps.byTri[tri], int32(i))
		h := triHash(tri[0], tri[1], tri[2])
		ps.tris[h/64] |= 1 << (h % 64)
	}
}

const triBits = 8192

// commonTri are letters most names contain, from TLDs and common words.
var commonTri = map[string]bool{"www": true, "com": true, "net": true, "org": true,
	"api": true, "app": true, "cdn": true, "img": true, "ads": true,
	"ser": true, "ver": true, "ion": true, "ing": true, "ent": true, "sta": true,
	"tic": true, "log": true, "tra": true, "ack": true, "con": true}

func triHash(a, b, c byte) uint32 {
	return (uint32(a)*977 ^ uint32(b)*31 ^ uint32(c)) * 2654435761 >> 19 % triBits
}

// find returns the strongest-tier pattern matching name, earliest first.
func (ps *patterns) find(name string) (*pattern, bool) {
	if ps == nil || len(ps.list) == 0 {
		return nil, false
	}
	best := int32(-1)
	try := func(ids []int32) {
		for _, i := range ids {
			if best >= 0 && (ps.list[i].ref.tier < ps.list[best].ref.tier ||
				ps.list[i].ref.tier == ps.list[best].ref.tier && i > best) {
				continue
			}
			if ps.list[i].matches(name) {
				best = i
			}
		}
	}
	for i := 0; i+3 <= len(name); i++ {
		if h := triHash(name[i], name[i+1], name[i+2]); ps.tris[h/64]&(1<<(h%64)) == 0 {
			continue
		}
		if ids, ok := ps.byTri[name[i:i+3]]; ok {
			try(ids)
		}
	}
	try(ps.scan)
	if best < 0 {
		return nil, false
	}
	return &ps.list[best], true
}

var patternCache sync.Map // pattern text -> *regexp.Regexp

func (r Rule) patternMatches(name string) bool {
	var re *regexp.Regexp
	if v, ok := patternCache.Load(r.Domain); ok {
		re = v.(*regexp.Regexp)
	} else {
		var err error
		if re, err = compilePattern(r.Domain); err != nil {
			return false
		}
		patternCache.Store(r.Domain, re)
	}
	p := newPattern(re, r, ref{})
	return p.matches(name)
}

func splitExcept(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "|")
}
