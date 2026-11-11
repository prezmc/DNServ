package store

import (
	"errors"
	"strings"
	"time"
)

// RiskDismiss sets a risky domain aside on the security overview, or
// (Undo) brings it back.
type RiskDismiss struct {
	Name string `json:"name"`
	Undo bool   `json:"undo,omitempty"`
}

// MaxDismissed is how many dismissals are kept; the oldest go first.
const MaxDismissed = 1000

func applyDismiss(st *State, c Command, d RiskDismiss) (any, *AuditEntry, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Name)), ".")
	if name == "" || len(name) > 253 {
		return nil, nil, errors.New("a domain name is required")
	}
	if d.Undo {
		if _, ok := st.Dismissed[name]; !ok {
			return nil, nil, nil
		}
		delete(st.Dismissed, name)
		if len(st.Dismissed) == 0 {
			st.Dismissed = nil
		}
		return nil, audit("restored risky domain "+name, nil, nil), nil
	}
	if st.Dismissed == nil {
		st.Dismissed = map[string]time.Time{}
	}
	st.Dismissed[name] = c.Time
	for len(st.Dismissed) > MaxDismissed {
		oldest, at := "", time.Time{}
		for n, t := range st.Dismissed {
			if oldest == "" || t.Before(at) {
				oldest, at = n, t
			}
		}
		delete(st.Dismissed, oldest)
	}
	return nil, audit("dismissed risky domain "+name, nil, nil), nil
}
