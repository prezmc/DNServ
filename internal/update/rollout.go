package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"
)

// Rollout states, for the whole rollout and for each step.
const (
	RolloutRunning = "running"
	RolloutDone    = "done"
	RolloutFailed  = "failed" // stopped at a server that didn't update; the rest weren't touched

	StepWaiting    = "waiting"
	StepUpdating   = "updating"
	StepRestarting = "restarting" // this server, which goes last
	StepDone       = "done"
	StepSkipped    = "skipped"
	StepFailed     = "failed"
)

// Rollout is one "install the new version" across the servers.
type Rollout struct {
	Revision string    `json:"revision"`
	By       string    `json:"by"`
	Auto     bool      `json:"auto,omitempty"`
	State    string    `json:"state"`
	Message  string    `json:"message,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	Steps    []Step    `json:"steps"`
}

// Step is one server in a rollout.
type Step struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Self    bool   `json:"self,omitempty"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// ErrNothingToDo means every server already runs the newest version.
var ErrNothingToDo = errors.New("every server already runs the newest version")

// Rollout returns the current or last rollout (nil: none).
func (m *Manager) Rollout() *Rollout {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rollout == nil {
		return nil
	}
	r := *m.rollout
	r.Steps = slices.Clone(r.Steps)
	return &r
}

func (m *Manager) step(i int, state, msg string) {
	m.mu.Lock()
	m.rollout.Steps[i].State, m.rollout.Steps[i].Message = state, msg
	r := *m.rollout
	m.mu.Unlock()
	m.saveRollout(&r)
}

func (m *Manager) end(state, msg string) {
	m.mu.Lock()
	m.rollout.State, m.rollout.Message, m.rollout.Finished = state, msg, time.Now()
	r := *m.rollout
	m.mu.Unlock()
	m.saveRollout(&r)
	m.Log.Info("update rollout finished", "state", state, "detail", msg)
}

// Install updates the servers in ids (all of them when empty) that run an
// older version, one at a time and this one last. It returns once the
// rollout has started.
func (m *Manager) Install(ctx context.Context, by string, ids []string, auto bool) (*Rollout, error) {
	m.mu.Lock()
	if m.rollout != nil && m.rollout.State == RolloutRunning {
		m.mu.Unlock()
		return nil, errors.New("an update is already being installed")
	}
	m.mu.Unlock()
	rel, _, _ := m.Latest()
	if rel == nil {
		var err error
		if rel, err = m.Check(ctx); err != nil {
			return nil, fmt.Errorf("couldn't find the newest version: %w", err)
		}
	}
	nodes := m.Nodes(ctx)
	var picked []NodeInfo
	for _, n := range nodes {
		if len(ids) > 0 && !slices.Contains(ids, n.ID) {
			continue
		}
		if n.Reachable && n.Revision == rel.Revision {
			continue
		}
		picked = append(picked, n)
	}
	if len(picked) == 0 {
		return nil, ErrNothingToDo
	}
	// Witnesses first (they answer no DNS), then the other servers, the
	// leader after the followers (one leader change, not several), and
	// this server last, since it runs the rollout.
	rank := func(n NodeInfo) int {
		switch {
		case n.Self:
			return 3
		case n.Witness:
			return 0
		case n.Leader:
			return 2
		}
		return 1
	}
	slices.SortStableFunc(picked, func(a, b NodeInfo) int { return rank(a) - rank(b) })

	r := &Rollout{Revision: rel.Revision, By: by, Auto: auto, State: RolloutRunning, Started: time.Now()}
	var names []string
	for _, n := range picked {
		r.Steps = append(r.Steps, Step{ID: n.ID, Name: n.Name, Self: n.Self, State: StepWaiting})
		names = append(names, n.Name)
	}
	m.mu.Lock()
	m.rollout = r
	out := *r
	out.Steps = slices.Clone(r.Steps)
	m.mu.Unlock()
	m.saveRollout(&out)
	if m.Audit != nil {
		m.Audit(by, rel.Revision, names, auto)
	}
	m.Log.Info("installing update", "revision", rel.Revision, "servers", names, "by", by)
	go m.runRollout(picked, rel.Revision)
	return &out, nil
}

func (m *Manager) durations() (wait, poll, settle time.Duration) {
	wait, poll, settle = m.StepWait, m.Poll, m.Settle
	if wait <= 0 {
		wait = 6 * time.Minute
	}
	if poll <= 0 {
		poll = 3 * time.Second
	}
	if settle <= 0 {
		settle = 10 * time.Second
	}
	return
}

func (m *Manager) runRollout(nodes []NodeInfo, target string) {
	ctx := context.Background()
	done := 0
	for i, n := range nodes {
		switch {
		case !n.Reachable:
			m.step(i, StepSkipped, "couldn't be reached: "+n.Error)
			continue
		case n.Updater == nil:
			why := "no updater on this server"
			if n.UpdaterError != "" {
				why = n.UpdaterError
			}
			m.step(i, StepSkipped, why+"; update it by hand (docker compose pull && docker compose up -d)")
			continue
		case n.Updater.Pinned:
			m.step(i, StepSkipped, "its image is pinned to one version ("+n.Updater.Image+")")
			continue
		}
		if n.Self {
			m.step(i, StepRestarting, "installing; this page reconnects when the server is back")
			if _, err := m.Sidecar.Start(ctx); err != nil {
				m.step(i, StepFailed, err.Error())
				m.end(RolloutFailed, "this server couldn't start its update: "+err.Error())
				return
			}
			// The updater stops this process soon; resume() finishes the
			// rollout's record after the restart.
			return
		}
		m.step(i, StepUpdating, "downloading and restarting")
		state, msg := m.updatePeer(ctx, n, target)
		m.step(i, state, msg)
		if state == StepFailed {
			m.end(RolloutFailed, n.Name+" didn't update ("+msg+"), so the rest were left alone and DNS keeps running on them")
			return
		}
		if state == StepDone {
			done++
		}
	}
	m.end(RolloutDone, fmt.Sprintf("%d of %d servers updated", done, len(nodes)))
}

// updatePeer has one other server update itself and waits until it
// answers DNS again on the new version.
func (m *Manager) updatePeer(ctx context.Context, n NodeInfo, target string) (string, string) {
	wait, poll, settle := m.durations()
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	raw, err := m.Peers.Ask(actx, n.ID, RPCStart, nil)
	cancel()
	if err != nil {
		return StepFailed, "couldn't start: " + err.Error()
	}
	var j Job
	_ = json.Unmarshal(raw, &j)
	started := j.Started
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(poll)
		info, err := m.askInfo(ctx, n.ID)
		if err != nil {
			continue // restarting
		}
		if info.Updater != nil && info.Updater.Job != nil && !info.Updater.Job.Started.Before(started) {
			switch job := info.Updater.Job; job.State {
			case JobRolledBack, JobFailed:
				return StepFailed, job.Message
			case JobUpToDate:
				return StepSkipped, "the registry still had the version it runs"
			}
		}
		// Ready on the new version, and its updater has finished
		// checking it (it could still undo the update).
		if info.Revision == target && info.Ready && (info.Updater == nil || !info.Updater.Job.Running()) {
			time.Sleep(settle)
			return StepDone, "running the new version"
		}
	}
	return StepFailed, fmt.Sprintf("wasn't back on the new version after %s", wait.Round(time.Second))
}

// resume picks up the record of a rollout this server was part of when
// it restarted itself, and finishes it.
func (m *Manager) resume(ctx context.Context) {
	if m.StateFile == "" {
		return
	}
	b, err := os.ReadFile(m.StateFile)
	if err != nil {
		return
	}
	var r Rollout
	if json.Unmarshal(b, &r) != nil {
		return
	}
	m.mu.Lock()
	m.rollout = &r
	m.mu.Unlock()
	if r.State != RolloutRunning {
		return
	}
	i := slices.IndexFunc(r.Steps, func(s Step) bool { return s.Self && s.State == StepRestarting })
	if i < 0 {
		// This server stopped in the middle of updating another one.
		m.end(RolloutFailed, "this server restarted while installing; check the versions below and try again")
		return
	}
	if RevisionOf(m.Version) == r.Revision {
		// The updater may still be checking this new container, and
		// would undo the update if it failed; then the old version
		// starts again and lands below.
		_, poll, _ := m.durations()
		for range 200 {
			st, err := m.Sidecar.Status(ctx)
			if err != nil || !st.Job.Running() {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(poll):
			}
		}
		m.step(i, StepDone, "running the new version")
		done := 0
		for _, s := range m.Rollout().Steps {
			if s.State == StepDone {
				done++
			}
		}
		m.end(RolloutDone, fmt.Sprintf("%d of %d servers updated", done, len(r.Steps)))
		return
	}
	msg := "restarted on the same version"
	if st, err := m.Sidecar.Status(ctx); err == nil && st.Job != nil && st.Job.Message != "" {
		msg = st.Job.Message
	}
	m.step(i, StepFailed, msg)
	m.end(RolloutFailed, "this server didn't update: "+msg)
}
