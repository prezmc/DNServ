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
)

func (k Kind) String() string {
	switch k {
	case Exact:
		return "exact"
	case Suffix:
		return "suffix"
	case SubOnly:
		return "subdomains"
	}
	return "unknown"
}

// Rule is one parsed rule.
type Rule struct {
	Domain string
	Kind   Kind
	Allow  bool
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
	line = strings.TrimSpace(line)
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

	// Modifiers: only $important is accepted (treated as a plain rule).
	if i := strings.IndexByte(line, '$'); i >= 0 {
		if line[i+1:] != "important" {
			return nil, false, false
		}
		line = line[:i]
	}

	if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") && len(line) > 1 {
		return nil, false, false // regex
	}

	if strings.HasPrefix(line, "||") {
		d := strings.TrimPrefix(line, "||")
		d = strings.TrimSuffix(d, "^")
		d = strings.TrimSuffix(d, "^|")
		if d2, ok := normalize(d); ok {
			return []Rule{{Domain: d2, Kind: Suffix, Allow: allow}}, true, false
		}
		return nil, false, false
	}

	if strings.HasPrefix(line, "*.") {
		if d, ok := normalize(line[2:]); ok {
			return []Rule{{Domain: d, Kind: SubOnly, Allow: allow}}, true, false
		}
		return nil, false, false
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		// Hosts format: IP followed by one or more names.
		if _, err := netip.ParseAddr(fields[0]); err != nil {
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
		return []Rule{{Domain: d, Kind: Exact, Allow: allow}}, true, false
	}
	return nil, false, false
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
