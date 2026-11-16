package filter

import "strings"

// Top-level domains can be blocked like services: the id "tld:ru" blocks
// every name ending in .ru, for everyone or for a device group or
// schedule. It is one suffix rule, so it costs nothing extra per lookup.
const tldPrefix = "tld:"

// AbusedTLDs are top-level domains that host a large share of abuse for
// how much they are used (cheap or free registrations, little checking).
// Risk scoring uses the same list.
var AbusedTLDs = []string{
	"bond", "buzz", "cam", "cf", "click", "country", "cyou", "ga", "gq", "icu", "loan", "men",
	"ml", "monster", "mov", "quest", "rest", "sbs", "su", "tk", "top", "work", "xyz", "zip",
}

// CountryTLDs are the country-code top-level domains. Most are ISO 3166
// country codes; uk, eu, su and ac are the exceptions.
var CountryTLDs = strings.Fields(`ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr
ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp
ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz
na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw
sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz
ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw`)

// GenericCountryTLDs are country codes widely used worldwide as general
// endings (.io for tech, .tv for video, .me for personal sites), so
// blocking one blocks far more than that country's sites.
var GenericCountryTLDs = []string{"ac", "ai", "cc", "co", "fm", "gg", "io", "ly", "me", "sh", "to", "tv", "ws"}

// TLDServiceID is the service id that blocks a top-level domain.
func TLDServiceID(tld string) string { return tldPrefix + tld }

// validTLD accepts a top-level domain label: letters, or an international
// one (xn--...), 2 to 63 characters.
func validTLD(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	if strings.HasPrefix(s, "xn--") {
		for i := 4; i < len(s); i++ {
			if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		return len(s) > 4
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// tldService is the service for a "tld:xx" id.
func tldService(id string) (Service, bool) {
	tld, ok := strings.CutPrefix(id, tldPrefix)
	if !ok || !validTLD(tld) {
		return Service{}, false
	}
	return Service{ID: id, Name: "." + tld + " domains", Category: "Top-level domains", Domains: []string{tld}}, true
}
