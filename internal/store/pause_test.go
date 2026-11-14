package store

import (
	"testing"
	"time"
)

func TestPauseForSchedules(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	st := &State{Pauses: map[string]*Pause{
		AllNodes: {Until: now.Add(time.Minute), Schedules: true},
		"n1":     {Until: now.Add(time.Hour)},
	}}
	p, ok := st.PauseFor("n1", now)
	if !ok || !p.Until.Equal(now.Add(time.Hour)) || !p.Schedules {
		t.Fatalf("want the longer pause, with schedules from the other: %+v %v", p, ok)
	}
	if p, _ := st.PauseFor("n2", now); !p.Schedules {
		t.Fatalf("n2: %+v", p)
	}
	st.Pauses[AllNodes].Schedules = false
	if p, _ := st.PauseFor("n1", now); p.Schedules {
		t.Fatalf("neither pause covers schedules: %+v", p)
	}
}
