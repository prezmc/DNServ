package server

import (
	"strings"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/policy"
)

// Safe search works the way Google, Microsoft and DuckDuckGo ask networks
// to do it: the search site's name is answered as an alias (CNAME) for
// the provider's own safe-search address.
var safeSearchNames = map[string]string{
	"www.bing.com": "strict.bing.com",
	"bing.com":     "strict.bing.com",

	"duckduckgo.com":       "safe.duckduckgo.com",
	"www.duckduckgo.com":   "safe.duckduckgo.com",
	"start.duckduckgo.com": "safe.duckduckgo.com",

	// YouTube's moderate restricted mode, as AdGuard Home uses.
	"www.youtube.com":          "restrictmoderate.youtube.com",
	"m.youtube.com":            "restrictmoderate.youtube.com",
	"youtube.com":              "restrictmoderate.youtube.com",
	"youtubei.googleapis.com":  "restrictmoderate.youtube.com",
	"youtube.googleapis.com":   "restrictmoderate.youtube.com",
	"www.youtube-nocookie.com": "restrictmoderate.youtube.com",
}

// safeSearchTarget returns the safe-search name for a normalized name, or "".
func safeSearchTarget(name string) string {
	if t, ok := safeSearchNames[name]; ok {
		return t
	}
	// Google's search on every country domain: google.com, www.google.de,
	// google.co.uk, www.google.com.au.
	rest, ok := strings.CutPrefix(name, "www.")
	if !ok {
		rest = name
	}
	if tld, ok := strings.CutPrefix(rest, "google."); ok && isCountryTLD(tld) {
		return "forcesafesearch.google.com"
	}
	return ""
}

// isCountryTLD accepts "com", "de", "co.uk", "com.au": one or two short
// labels of letters.
func isCountryTLD(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if len(p) < 2 || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 'a' || p[i] > 'z' {
				return false
			}
		}
	}
	return true
}

// safeSearchOn reports whether safe search applies to a client in group g.
func (s *Server) safeSearchOn(g *policy.Group) bool {
	f := s.live.Load().filtering
	if !f.Enabled {
		return false
	}
	if g != nil && g.SafeSearch != nil {
		return *g.SafeSearch
	}
	return f.SafeSearch
}

// safeSearchAnswer answers req (for a search site) with a CNAME to target
// followed by target's own answer, from the cache or upstream.
func (s *Server) safeSearchAnswer(req *dns.Msg, target string) (*dns.Msg, Outcome, string) {
	q := req.Question[0]
	treq := req.Copy()
	treq.Question[0].Name = dns.Fqdn(target)
	m, out, from := s.answer(treq, target)
	r := m.Copy()
	r.Id = req.Id
	r.Question = req.Question
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: dns.Fqdn(target)}
	r.Answer = append([]dns.RR{cname}, r.Answer...)
	return r, out, from
}

// safeSearchFor returns the safe-search target for name when safe search
// is on for group g. With it off, this costs one atomic load.
func (s *Server) safeSearchFor(g *policy.Group, name string) string {
	if !s.safeSearchOn(g) {
		return ""
	}
	return safeSearchTarget(name)
}
