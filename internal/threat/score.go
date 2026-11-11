package threat

import (
	"strconv"
	"strings"

	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
)

// How a score is worked out (the guide in the dashboard describes the
// same steps, from Scoring):
//
//  1. The strongest list that has the domain sets the score (its points).
//  2. Each further list that has it adds Corroboration.
//  3. Name checks add their points, up to NameCap, or NameCapListed when
//     the domain is already on a list. Domains of known companies skip
//     the name checks.
//  4. The total is capped at 100.
//
// What a domain's answers pointed to (CheckAnswer) is scored separately,
// when history is written, and the higher of the two counts.

// SetScoring sets how domains are scored. Scores are worked out when asked
// for, so a change applies at once to everything shown.
func (in *Intel) SetScoring(s config.RiskScoring) {
	n := s.Normalized()
	in.scoring.Store(&n)
}

// Scoring is how domains are scored now.
func (in *Intel) Scoring() config.RiskScoring { return *in.scoring.Load() }

// Level names a score under the current scoring: "", low, medium or high.
func (in *Intel) Level(score int) string { return levelFor(score, in.scoring.Load()) }

func levelFor(score int, s *config.RiskScoring) string {
	switch {
	case score >= s.High:
		return "high"
	case score >= s.Medium:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

// Score rates a domain under the current scoring.
func (in *Intel) Score(name string) Risk { return in.ScoreWith(name, in.scoring.Load()) }

// ScoreWith rates a domain under the given scoring (for previews).
func (in *Intel) ScoreWith(name string, s *config.RiskScoring) Risk {
	name = filter.Normalize(name)
	if in.trustedName(name) {
		return Risk{}
	}
	d := in.cur.Load()
	mask := d.feeds[name]
	parents(name, func(n string) bool {
		mask |= d.wildcard[n]
		return true
	})
	type hit struct {
		name string
		pts  int
	}
	var hits []hit
	for i, f := range Feeds {
		if pts := feedPoints(f, s); i < 8 && mask&(1<<i) != 0 && pts > 0 {
			hits = append(hits, hit{f.Name, pts})
		}
	}
	// Strongest first.
	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j].pts > hits[j-1].pts; j-- {
			hits[j], hits[j-1] = hits[j-1], hits[j]
		}
	}
	score := 0
	var reasons []string
	var parts []Part
	if len(hits) > 0 {
		score = hits[0].pts
		names := make([]string, len(hits))
		for i, h := range hits {
			names[i] = h.name
		}
		reasons = append(reasons, "On "+strings.Join(names, ", "))
		parts = append(parts, Part{What: "On " + hits[0].name, Points: hits[0].pts})
		for _, h := range hits[1:] {
			parts = append(parts, Part{What: "Also on " + h.name, Points: s.Corroboration})
			score += s.Corroboration
		}
	}
	// Name checks, unless the domain belongs to a known company.
	known := false
	parents(name, func(n string) bool {
		_, known = d.trackers[n]
		return !known
	})
	if !known {
		pts, np := nameChecks(name, s)
		limit := s.NameCap
		if score > 0 {
			limit = s.NameCapListed
		}
		for _, p := range np {
			reasons = append(reasons, p.What)
		}
		parts = append(parts, np...)
		if pts > limit {
			parts = append(parts, Part{What: "Name checks add at most " + strconv.Itoa(limit) + (map[bool]string{true: " to a listed domain", false: ""})[score > 0], Points: limit - pts})
			pts = limit
		}
		score += pts
	}
	if score > 100 {
		parts = append(parts, Part{What: "Capped at 100", Points: 100 - score})
		score = 100
	}
	return Risk{Score: score, Level: levelFor(score, s), Reasons: reasons, Parts: parts}
}

// feedPoints is a feed's points, by its kind when the scoring doesn't
// name it.
func feedPoints(f Feed, s *config.RiskScoring) int {
	if p, ok := s.Feeds[f.ID]; ok {
		return p
	}
	switch {
	case f.Kind&KindMalware != 0:
		return 90
	case f.Kind&KindPhishing != 0:
		return 80
	}
	return 70
}

// riskyTLDs are top-level domains that host a large share of abuse
// relative to legitimate use.
var riskyTLDs = map[string]bool{
	"zip": true, "mov": true, "top": true, "xyz": true, "tk": true, "ml": true, "ga": true, "cf": true, "gq": true,
	"click": true, "country": true, "work": true, "rest": true, "cam": true, "loan": true, "men": true, "buzz": true,
	"icu": true, "cyou": true, "sbs": true, "bond": true, "monster": true, "quest": true, "su": true,
}

// NameCheck describes one name check for the guide.
type NameCheck struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

// NameChecks are the checks on the name itself.
var NameChecks = []NameCheck{
	{config.CheckTLD, "Often-abused top-level domain", "Top-level domains that host a large share of abuse for how much they're used: ." + strings.Join(tldList(), ", .")},
	{config.CheckGenerated, "Looks machine-generated", "A long label (12+ characters, no hyphens) with high character variety and few vowels, typical of malware domain generators"},
	{config.CheckLookalike, "Look-alike characters", "International (xn--) characters, a common way to fake a familiar name"},
	{config.CheckDigits, "Mostly digits", "The registered name is at least half digits, 5 or more of them"},
	{config.CheckLong, "Unusually long name", "Over 70 characters, or more than 7 labels"},
}

func tldList() []string {
	out := make([]string, 0, len(riskyTLDs))
	for t := range riskyTLDs {
		out = append(out, t)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// nameChecks scores how suspicious a name looks, before any cap.
func nameChecks(name string, s *config.RiskScoring) (int, []Part) {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return 0, nil
	}
	tld := labels[len(labels)-1]
	reg := labels[len(labels)-2] // the label people register
	score := 0
	var parts []Part
	add := func(id, what string) {
		if p := s.Names[id]; p > 0 {
			score += p
			parts = append(parts, Part{What: what, Points: p})
		}
	}
	if riskyTLDs[tld] {
		add(config.CheckTLD, "Often-abused top-level domain ."+tld)
	}
	if dga(reg) {
		add(config.CheckGenerated, "Looks machine-generated")
	}
	for _, l := range labels {
		if strings.HasPrefix(l, "xn--") {
			add(config.CheckLookalike, "Uses look-alike (international) characters")
			break
		}
	}
	digits := 0
	for _, r := range reg {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits >= 5 && digits*2 >= len(reg) {
		add(config.CheckDigits, "Mostly digits")
	}
	if len(name) > 70 || len(labels) > 7 {
		add(config.CheckLong, "Unusually long name")
	}
	return score, parts
}

// heuristics is the name checks under the default scoring, capped.
func heuristics(name string) (int, []string) {
	d := config.DefaultRiskScoring()
	pts, parts := nameChecks(name, &d)
	why := make([]string, len(parts))
	for i, p := range parts {
		why[i] = p.What
	}
	return min(pts, d.NameCap), why
}

// Preset is a named scoring for the tuning page.
type Preset struct {
	ID      string             `json:"id"`
	Label   string             `json:"label"`
	About   string             `json:"about"`
	Scoring config.RiskScoring `json:"scoring"`
}

// Presets are ready-made scorings.
func Presets() []Preset {
	bal := config.DefaultRiskScoring()
	sens := config.DefaultRiskScoring()
	sens.Corroboration, sens.NameCap, sens.NameCapListed, sens.Medium, sens.High = 10, 55, 15, 30, 60
	for k, v := range sens.Names {
		sens.Names[k] = v + 5
	}
	quiet := config.DefaultRiskScoring()
	quiet.Corroboration, quiet.NameCap, quiet.NameCapListed, quiet.Medium, quiet.High = 5, 25, 5, 50, 80
	for k, v := range quiet.Names {
		quiet.Names[k] = v / 2
	}
	quiet.Feeds["hagezi-tif"] = 65
	return []Preset{
		{"balanced", "Balanced", "The defaults. Clear threats are High; a suspicious-looking name alone reaches Medium at most.", bal},
		{"sensitive", "Sensitive", "Flags more. Name checks count for more and the levels start lower. Expect more alerts, including some false alarms.", sens},
		{"quiet", "Quieter", "Fewer alerts. Only lists with strong evidence make a domain High, and name checks count for little.", quiet},
	}
}

// LevelWith names a score under the given scoring.
func LevelWith(score int, s config.RiskScoring) string { return levelFor(score, &s) }
