package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxGroupRules bounds a group's own rules (they live in the replicated
// state, unlike downloaded lists).
const MaxGroupRules = 2000

// ParseClock reads "HH:MM" as minutes after midnight.
func ParseClock(s string) (int, error) {
	var h, m int
	if n, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || n != 2 || len(s) != 5 || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q is not a time like 21:30", s)
	}
	return h*60 + m, nil
}

func cleanRules(in []string) []string {
	out := []string{}
	for _, r := range in {
		if r = strings.TrimSpace(r); r != "" && !strings.HasPrefix(r, "#") && !strings.HasPrefix(r, "!") {
			out = append(out, r)
		}
	}
	return out
}

func (g *Group) normalize() error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || utf8.RuneCountInString(g.Name) > 64 {
		return errors.New("a group needs a name of 1 to 64 characters")
	}
	g.Rules = cleanRules(g.Rules)
	total := len(g.Rules)
	if len(g.Schedules) > 20 {
		return errors.New("a group can have at most 20 schedules")
	}
	if g.Schedules == nil {
		g.Schedules = []Schedule{}
	}
	for i := range g.Schedules {
		s := &g.Schedules[i]
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			s.Name = fmt.Sprintf("Schedule %d", i+1)
		}
		if utf8.RuneCountInString(s.Name) > 64 {
			return errors.New("schedule names are at most 64 characters")
		}
		start, err := ParseClock(s.Start)
		if err != nil {
			return fmt.Errorf("%s: start %w", s.Name, err)
		}
		end, err := ParseClock(s.End)
		if err != nil {
			return fmt.Errorf("%s: end %w", s.Name, err)
		}
		if start == end {
			return fmt.Errorf("%s: start and end are the same time", s.Name)
		}
		days := []int{}
		for _, d := range s.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("%s: days are 0 (Sunday) to 6", s.Name)
			}
			if !slices.Contains(days, d) {
				days = append(days, d)
			}
		}
		if len(days) == 0 {
			return fmt.Errorf("%s: pick at least one day", s.Name)
		}
		slices.Sort(days)
		s.Days = days
		s.Rules = cleanRules(s.Rules)
		if !s.BlockAll && len(s.Rules) == 0 {
			return fmt.Errorf("%s: choose to pause the internet or list domains to block", s.Name)
		}
		total += len(s.Rules)
	}
	if total > MaxGroupRules {
		return fmt.Errorf("a group can have at most %d rules", MaxGroupRules)
	}
	return nil
}
