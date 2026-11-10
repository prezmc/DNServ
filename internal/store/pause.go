package store

import (
	"errors"
	"fmt"
	"time"
)

// MaxPause is the longest timed pause; longer than that, pause until
// turned back on.
const MaxPause = 24 * time.Hour

// AllNodes is the Pauses key for a pause on every node in the cluster.
const AllNodes = "*"

// Pause turns filtering off for a while, or until someone turns it back
// on. Each node compares Until with its own clock, so an expired pause
// needs no further command.
type Pause struct {
	// Until is when filtering comes back on. Zero means it stays off
	// until resumed.
	Until time.Time `json:"until,omitempty"`
	Since time.Time `json:"since"`
	By    string    `json:"by"`
}

// FilterPause is the data for OpFilterPause.
type FilterPause struct {
	// Seconds is how long to pause; 0 pauses until resumed.
	Seconds int64 `json:"seconds"`
	// Node is the node to pause; "" or AllNodes pauses every node.
	Node string `json:"node,omitempty"`
}

// FilterResume is the data for OpFilterResume.
type FilterResume struct {
	// Node is the node whose own pause ends; "" or AllNodes ends every
	// pause.
	Node string `json:"node,omitempty"`
}

// Active reports whether the pause is in force at now.
func (p *Pause) Active(now time.Time) bool {
	return p != nil && (p.Until.IsZero() || now.Before(p.Until))
}

// PauseFor returns the pause in force on node at now: its own or the
// cluster-wide one, whichever lasts longer. ok is false when filtering
// is on.
func (st *State) PauseFor(node string, now time.Time) (p Pause, ok bool) {
	for _, k := range []string{AllNodes, node} {
		q := st.Pauses[k]
		if !q.Active(now) || k == "" {
			continue
		}
		if !ok || q.Until.IsZero() || (!p.Until.IsZero() && q.Until.After(p.Until)) {
			p = *q
		}
		ok = true
	}
	return p, ok
}

// pruneExpired drops pauses that are over.
func (st *State) pruneExpired(now time.Time) {
	for k, p := range st.Pauses {
		if !p.Active(now) {
			delete(st.Pauses, k)
		}
	}
	if len(st.Pauses) == 0 {
		st.Pauses = nil
	}
}

func (st *State) pauseTarget(node string) (key, name string, err error) {
	if node == "" || node == AllNodes {
		return AllNodes, "", nil
	}
	n := st.Cluster.Nodes[node]
	if n == nil {
		return "", "", errors.New("there is no server with that id in the cluster")
	}
	if n.Witness {
		return "", "", fmt.Errorf("%s is a witness and doesn't answer DNS", n.Name)
	}
	return node, n.Name, nil
}

func applyPause(st *State, c Command, d FilterPause) (any, *AuditEntry, error) {
	if d.Seconds < 0 || time.Duration(d.Seconds)*time.Second > MaxPause {
		return nil, nil, errors.New("a timed pause must be between 1 second and 24 hours (or 0 to pause until turned back on)")
	}
	key, name, err := st.pauseTarget(d.Node)
	if err != nil {
		return nil, nil, err
	}
	st.pruneExpired(c.Time)
	p := &Pause{Since: c.Time, By: c.Actor}
	what := "paused filtering"
	if name != "" {
		what += " on " + name
	} else if len(st.Cluster.Nodes) > 1 {
		what += " on all servers"
	}
	if d.Seconds > 0 {
		dur := time.Duration(d.Seconds) * time.Second
		p.Until = c.Time.Add(dur)
		what += " for " + humanDuration(dur)
	} else {
		what += " until turned back on"
	}
	if st.Pauses == nil {
		st.Pauses = map[string]*Pause{}
	}
	st.Pauses[key] = p
	return p, audit(what, nil, p), nil
}

func applyResume(st *State, c Command, d FilterResume) (any, *AuditEntry, error) {
	st.pruneExpired(c.Time)
	what := "turned filtering back on"
	if d.Node == "" || d.Node == AllNodes {
		if len(st.Pauses) == 0 {
			return nil, nil, nil // already on: nothing to record
		}
		if len(st.Cluster.Nodes) > 1 {
			what += " for all servers"
		}
		st.Pauses = nil
		return nil, audit(what, nil, nil), nil
	}
	if st.Pauses[d.Node] == nil {
		return nil, nil, nil
	}
	if n := st.Cluster.Nodes[d.Node]; n != nil {
		what += " for " + n.Name
	}
	delete(st.Pauses, d.Node)
	st.pruneExpired(c.Time)
	return nil, audit(what, nil, nil), nil
}

func humanDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		if d == time.Hour {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", d/time.Hour)
	case d%time.Minute == 0:
		if d == time.Minute {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", d/time.Minute)
	}
	return d.String()
}
