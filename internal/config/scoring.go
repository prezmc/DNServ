package config

// RiskScoring is how domains are scored for risk (0-100). It never
// blocks anything; it only decides what the dashboard marks.
type RiskScoring struct {
	// Feeds are each threat feed's points, by feed ID (urlhaus, threatfox,
	// phishingarmy, hagezi-tif, feodo, drop4, drop6). 0 ignores a feed.
	Feeds map[string]int `yaml:"feeds" json:"feeds"`
	// Corroboration is added for each further list that has the domain.
	Corroboration int `yaml:"corroboration" json:"corroboration"`
	// Names are the points for each name check, by check ID.
	Names map[string]int `yaml:"names" json:"names"`
	// NameCap is the most name checks can add on their own; NameCapListed
	// the most they add to a domain already on a list.
	NameCap       int `yaml:"name_cap" json:"name_cap"`
	NameCapListed int `yaml:"name_cap_listed" json:"name_cap_listed"`
	// Medium and High are where those levels start (Low is anything above 0).
	Medium int `yaml:"medium" json:"medium"`
	High   int `yaml:"high" json:"high"`
}

// Name check IDs.
const (
	CheckTLD       = "tld"       // often-abused top-level domain
	CheckGenerated = "generated" // looks machine-generated
	CheckLookalike = "lookalike" // international (xn--) characters
	CheckDigits    = "digits"    // mostly digits
	CheckLong      = "long"      // unusually long
)

// DefaultRiskScoring is the "Balanced" scoring.
func DefaultRiskScoring() RiskScoring {
	return RiskScoring{
		Feeds:         map[string]int{"urlhaus": 90, "threatfox": 90, "phishingarmy": 80, "hagezi-tif": 70, "feodo": 90, "drop4": 85, "drop6": 85},
		Corroboration: 5,
		Names:         map[string]int{CheckTLD: 15, CheckGenerated: 25, CheckLookalike: 15, CheckDigits: 10, CheckLong: 10},
		NameCap:       45, NameCapListed: 10,
		Medium: 40, High: 70,
	}
}

func clamp(v, lo, hi int) int { return max(lo, min(hi, v)) }

// Normalized fills anything missing from the defaults and keeps every
// value in range, with Medium below High.
func (s RiskScoring) Normalized() RiskScoring {
	d := DefaultRiskScoring()
	out := RiskScoring{Feeds: map[string]int{}, Names: map[string]int{}}
	for id, v := range d.Feeds {
		if x, ok := s.Feeds[id]; ok {
			v = x
		}
		out.Feeds[id] = clamp(v, 0, 100)
	}
	for id, v := range d.Names {
		if x, ok := s.Names[id]; ok {
			v = x
		}
		out.Names[id] = clamp(v, 0, 50)
	}
	zero := s.Feeds == nil && s.Names == nil && s.Medium == 0 && s.High == 0
	if zero {
		return d
	}
	out.Corroboration = clamp(s.Corroboration, 0, 30)
	out.NameCap = clamp(s.NameCap, 0, 100)
	out.NameCapListed = clamp(s.NameCapListed, 0, 50)
	out.Medium = clamp(s.Medium, 2, 98)
	out.High = clamp(s.High, out.Medium+1, 100)
	return out
}
