package filter

import (
	"errors"
	"strings"
)

// ClientTargets splits the AdGuard-style $client modifier off a custom
// rule: "||games.example^$client=Kids|'Sam's laptop'|192.168.1.20".
// has is false when the rule has none. rest is the rule without it, and
// clients are the names (of groups or devices) and addresses it names,
// unquoted. Excluding clients ("~name") isn't supported.
func ClientTargets(line string) (rest string, clients []string, has bool, err error) {
	line = strings.TrimSpace(line)
	i := strings.LastIndexByte(line, '$')
	if i < 0 || isRegexRule(line) && strings.HasSuffix(line, "/") {
		return line, nil, false, nil
	}
	if strings.HasPrefix(line, "/") && strings.LastIndexByte(line, '/') > i {
		return line, nil, false, nil
	}
	mods := splitTop(line[i+1:], ',')
	var keep []string
	for _, m := range mods {
		v, ok := strings.CutPrefix(strings.TrimSpace(m), "client=")
		if !ok {
			keep = append(keep, m)
			continue
		}
		has = true
		for _, c := range splitTop(v, '|') {
			c = strings.TrimSpace(c)
			if strings.HasPrefix(c, "~") {
				return "", nil, true, errors.New(`excluding a device with "~" isn't supported in $client`)
			}
			if len(c) >= 2 && (c[0] == '\'' || c[0] == '"') && c[len(c)-1] == c[0] {
				c = strings.ReplaceAll(c[1:len(c)-1], `\`+c[:1], c[:1])
			}
			c = strings.TrimSpace(c)
			if c != "" {
				clients = append(clients, c)
			}
		}
	}
	if !has {
		return line, nil, false, nil
	}
	if len(clients) == 0 {
		return "", nil, true, errors.New("$client names no group, device or address")
	}
	rest = line[:i]
	if len(keep) > 0 {
		rest += "$" + strings.Join(keep, ",")
	}
	if strings.TrimSpace(strings.TrimPrefix(rest, "@@")) == "" {
		return "", nil, true, errors.New("the rule has nothing before $client")
	}
	return rest, clients, true, nil
}

// splitTop splits s at sep, except inside quotes ('...' or "...", where
// a backslash escapes the next character).
func splitTop(s string, sep byte) []string {
	var out []string
	var q byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0 && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q == 0 && c == sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
