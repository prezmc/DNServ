// Package filter parses blocklists and custom rules and answers, for a
// domain, whether it is blocked and by what.
package filter

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// Kind says which names a rule covers.
type Kind uint8

const (
	// Exact matches only the domain itself (hosts lines, plain domains).
	Exact Kind = iota
	// Suffix matches the domain and all its subdomains (||domain^).
	Suffix
	// SubOnly matches subdomains but not the domain itself (*.domain).
	SubOnly
	// Pattern is a wildcard or regex rule (ad-*.example.com, /regex/),
	// or any rule with $denyallow. Domain then holds the pattern as written.
	Pattern
)

func (k Kind) String() string {
	switch k {
	case Exact:
		return "exact"
	case Suffix:
		return "suffix"
	case SubOnly:
		return "subdomains"
	case Pattern:
		return "pattern"
	}
	return "unknown"
}

// Rule is one parsed rule.
type Rule struct {
	Domain string
	Kind   Kind
	Allow  bool
	// Except lists domains ($denyallow) the rule does not apply to, with
	// their subdomains, separated by "|".
	Except string
	// Bad marks a $badfilter rule: it switches off the same rule in every
	// list instead of adding one.
	Bad bool
}

// Text renders the rule back in AdBlock syntax.
func (r Rule) Text() string {
	var s string
	switch r.Kind {
	case Suffix:
		s = "||" + r.Domain + "^"
	case SubOnly:
		s = "*." + r.Domain
	default:
		s = r.Domain
	}
	if r.Allow {
		s = "@@" + s
	}
	var mods []string
	if r.Except != "" {
		mods = append(mods, "denyallow="+r.Except)
	}
	if r.Bad {
		mods = append(mods, "badfilter")
	}
	if len(mods) > 0 {
		s += "$" + strings.Join(mods, ",")
	}
	return s
}

// ParseStats counts what a parse used and skipped.
type ParseStats struct {
	Lines   int
	Rules   int
	Skipped int
}

// ParseLine parses one line. ok is false for comments, blank lines and
// rules this engine does not support (regex, cosmetic, most modifiers);
// those are counted as skipped by ParseList when they are not comments.
func ParseLine(line string) (rules []Rule, ok bool, comment bool) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" || line[0] == '!' || line[0] == '#' || strings.HasPrefix(line, "[Adblock") {
		return nil, false, true
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#$#") {
		return nil, false, false // cosmetic rule
	}
	// Strip trailing inline comments in hosts files: "0.0.0.0 x.com # ad".
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	allow := false
	if strings.HasPrefix(line, "@@") {
		allow = true
		line = line[2:]
	}

	line, except, bad, ok := splitModifiers(line)
	if !ok {
		return nil, false, false
	}
	mark := func(r Rule) ([]Rule, bool, bool) {
		r.Allow, r.Except, r.Bad = allow, except, bad
		if except != "" && r.Kind != Pattern {
			// $denyallow needs the pattern matcher, which checks exceptions.
			switch r.Kind {
			case Suffix:
				r.Domain = "||" + r.Domain + "^"
			case SubOnly:
				r.Domain = "*." + r.Domain
			default:
				r.Domain = "|" + r.Domain + "^"
			}
			r.Kind = Pattern
		}
		return []Rule{r}, true, false
	}

	if isRegexRule(line) {
		if re, err := compilePattern(line); err != nil {
			return nil, false, false
		} else if _, possible := hostLiterals(re); !possible {
			return nil, false, false
		}
		return mark(Rule{Domain: line, Kind: Pattern})
	}

	if strings.HasPrefix(line, "||") {
		d := strings.TrimPrefix(line, "||")
		d = strings.TrimSuffix(d, "^|")
		d = strings.TrimSuffix(d, "^")
		if d2, ok := normalize(d); ok {
			return mark(Rule{Domain: d2, Kind: Suffix})
		}
		return parsePattern(line, mark)
	}

	if strings.HasPrefix(line, "*.") {
		if d, ok := normalize(line[2:]); ok {
			return mark(Rule{Domain: d, Kind: SubOnly})
		}
		return parsePattern(line, mark)
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		// Hosts format: IP followed by one or more names.
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			return nil, false, false
		}
		if except != "" || bad {
			return nil, false, false
		}
		for _, f := range fields[1:] {
			d, ok := normalize(f)
			if !ok || isHostsBoilerplate(d) {
				continue
			}
			rules = append(rules, Rule{Domain: d, Kind: Exact, Allow: allow})
		}
		return rules, len(rules) > 0, len(rules) == 0
	}

	if d, ok := normalize(strings.TrimSuffix(line, "^")); ok {
		return mark(Rule{Domain: d, Kind: Exact})
	}
	return parsePattern(line, mark)
}

// splitModifiers removes a $modifier list. Only modifiers that make sense
// for every client and query type are accepted: $important (treated as a
// plain rule), $badfilter and $denyallow. Rules with others ($client,
// $dnstype, $dnsrewrite, browser-only ones) are skipped.
func splitModifiers(line string) (body, except string, bad, ok bool) {
	i := strings.LastIndexByte(line, '$')
	if i < 0 || (isRegexRule(line) && strings.HasSuffix(line, "/")) {
		return line, "", false, true
	}
	if strings.HasPrefix(line, "/") && strings.LastIndexByte(line, '/') > i {
		return line, "", false, true // a "$" inside a regex
	}
	body = line[:i]
	for _, m := range strings.Split(line[i+1:], ",") {
		switch {
		case m == "important":
		case m == "badfilter":
			bad = true
		case strings.HasPrefix(m, "denyallow="):
			var ds []string
			for _, d := range strings.Split(m[len("denyallow="):], "|") {
				d, ok := normalize(d)
				if !ok {
					return "", "", false, false
				}
				ds = append(ds, d)
			}
			except = strings.Join(ds, "|")
		default:
			return "", "", false, false
		}
	}
	return body, except, bad, body != ""
}

func isRegexRule(s string) bool {
	return len(s) > 2 && s[0] == '/' && s[len(s)-1] == '/'
}

// parsePattern accepts AdBlock-style host patterns: "*" wildcards, "||"
// (start of a label), "|" or "://" (start of the name), "^" at the end
// (end of the name). Paths and other URL parts cannot match a DNS name and
// are skipped.
func parsePattern(line string, mark func(Rule) ([]Rule, bool, bool)) ([]Rule, bool, bool) {
	p := strings.ToLower(line)
	inner := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(p, "||"), "://"), "|")
	inner = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(inner, "^|"), "^"), "|")
	if inner == "" || strings.Trim(inner, "*.") == "" {
		return nil, false, false
	}
	for i := 0; i < len(inner); i++ {
		switch c := inner[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '*':
		default:
			return nil, false, false
		}
	}
	if re, err := compilePattern(p); err != nil {
		return nil, false, false
	} else if _, possible := hostLiterals(re); !possible {
		return nil, false, false
	}
	return mark(Rule{Domain: p, Kind: Pattern})
}

// ParseList parses a whole list, calling fn for each rule.
func ParseList(r io.Reader, fn func(Rule)) (ParseStats, error) {
	var st ParseStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		st.Lines++
		rules, ok, comment := ParseLine(sc.Text())
		if !ok {
			if !comment {
				st.Skipped++
			}
			continue
		}
		for _, rule := range rules {
			st.Rules++
			fn(rule)
		}
	}
	return st, sc.Err()
}

var hostsBoilerplate = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

func isHostsBoilerplate(d string) bool { return hostsBoilerplate[d] }

// normalize lowercases a domain, strips a trailing dot and checks that it
// looks like a hostname. Wildcards in the middle and paths are rejected.
func normalize(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", false
		}
	}
	if d[0] == '.' || strings.Contains(d, "..") {
		return "", false
	}
	return d, true
}

// Normalize is the exported form of normalize for query names.
func Normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
