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

// Rollout is one "install the new version" (or "roll back") across the
// servers.
type Rollout struct {
	// Revision is the version installed; for a rollback, the version
	// rolled back from.
	Revision string `json:"revision"`
	Rollback bool   `json:"rollback,omitempty"`
	By       string `json:"by"`
	Auto     bool   `json:"auto,omitempty"`
	// Backup is the backup made just before (its file name in the
	// node's backups), "" when backups aren't set up.
	Backup   string    `json:"backup,omitempty"`
	BackupOn string    `json:"backup_on,omitempty"` // the server that has it
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
	From    string `json:"from,omitempty"` // revision before
	To      string `json:"to"`             // revision it goes to
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// ErrNothingToDo means every server already runs the version asked for.
var ErrNothingToDo = errors.New("every server already runs the newest version")

// ErrNoRollback means there is no finished update to undo.
var ErrNoRollback = errors.New("there is no update to roll back")

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

// CanRollBack reports whether the last rollout can be undone.
func (m *Manager) CanRollBack() bool {
	r := m.Rollout()
	return r != nil && len(rollbackSteps(r)) > 0
}

// rollbackSteps are the servers the last update changed, each going back
// to the version it had.
func rollbackSteps(r *Rollout) []Step {
	if r.State == RolloutRunning || r.Rollback {
		return nil
	}
	var out []Step
	for _, s := range r.Steps {
		if s.State == StepDone && s.From != "" && s.From != s.To {
			out = append(out, Step{ID: s.ID, Name: s.Name, Self: s.Self, From: s.To, To: s.From, State: StepWaiting})
		}
	}
	return out
}

func (m *Manager) step(i int, state, msg string) {
	m.mu.Lock()
	m.rollout.Steps[i].State, m.rollout.Steps[i].Message = state, msg
	r := *m.rollout
	r.Steps = slices.Clone(r.Steps)
	m.mu.Unlock()
	m.saveRollout(&r)
}

func (m *Manager) end(state, msg string) {
	m.mu.Lock()
	m.rollout.State, m.rollout.Message, m.rollout.Finished = state, msg, time.Now()
	r := *m.rollout
	r.Steps = slices.Clone(r.Steps)
	m.mu.Unlock()
	m.saveRollout(&r)
	m.Log.Info("update rollout finished", "state", state, "detail", msg)
}

// order puts witnesses first (they answer no DNS), then the other
// servers, the leader after the followers (one leader change, not
// several), and this server last, since it runs the rollout.
func order(steps []Step, nodes []NodeInfo) {
	byID := map[string]NodeInfo{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	rank := func(s Step) int {
		n := byID[s.ID]
		switch {
		case s.Self:
			return 3
		case n.Witness:
			return 0
		case n.Leader:
			return 2
		}
		return 1
	}
	slices.SortStableFunc(steps, func(a, b Step) int { return rank(a) - rank(b) })
}

// Install updates the servers in ids (all of them when empty) that run an
// older version, one at a time and this one last. It returns once the
// rollout has started.
func (m *Manager) Install(ctx context.Context, by string, ids []string, auto bool) (*Rollout, error) {
	if m.running() {
		return nil, errors.New("an update is already being installed")
	}
	rel, _, _ := m.Latest()
	if rel == nil {
		var err error
		if rel, err = m.Check(ctx); err != nil {
			return nil, fmt.Errorf("couldn't find the newest version: %w", err)
		}
	}
	if auto && rel.Revision == m.prefs().Skip {
		return nil, ErrNothingToDo // rolled back from; wait for a newer one
	}
	nodes := m.Nodes(ctx)
	var steps []Step
	for _, n := range nodes {
		if len(ids) > 0 && !slices.Contains(ids, n.ID) {
			continue
		}
		if n.Reachable && n.Revision == rel.Revision {
			continue
		}
		steps = append(steps, Step{ID: n.ID, Name: n.Name, Self: n.Self, From: n.Revision, To: rel.Revision, State: StepWaiting})
	}
	if len(steps) == 0 {
		return nil, ErrNothingToDo
	}
	if m.SetSkip != nil && m.prefs().Skip != "" && !auto {
		m.SetSkip(by, "") // installing by hand: nothing skipped any more
	}
	return m.start(&Rollout{Revision: rel.Revision, By: by, Auto: auto}, steps, nodes)
}

// RollBack puts every server the last update changed back on the version
// it ran before, one at a time and this one last, and skips the newer
// version until a newer one still is out.
func (m *Manager) RollBack(ctx context.Context, by string) (*Rollout, error) {
	if m.running() {
		return nil, errors.New("an update is already being installed")
	}
	last := m.Rollout()
	if last == nil {
		return nil, ErrNoRollback
	}
	steps := rollbackSteps(last)
	if len(steps) == 0 {
		return nil, ErrNoRollback
	}
	if m.SetSkip != nil {
		m.SetSkip(by, last.Revision)
	}
	return m.start(&Rollout{Revision: last.Revision, Rollback: true, By: by}, steps, m.Nodes(ctx))
}

func (m *Manager) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollout != nil && m.rollout.State == RolloutRunning
}

// start makes the safety backup, records the rollout and runs it.
func (m *Manager) start(r *Rollout, steps []Step, nodes []NodeInfo) (*Rollout, error) {
	order(steps, nodes)
	if m.Backup != nil {
		name, err := m.Backup()
		if err != nil {
			return nil, fmt.Errorf("couldn't make a backup first, so nothing was changed: %w", err)
		}
		r.Backup = name
		for _, n := range nodes {
			if n.Self {
				r.BackupOn = n.Name
			}
		}
	}
	r.State, r.Started, r.Steps = RolloutRunning, time.Now(), steps
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	m.mu.Lock()
	m.rollout = r
	out := *r
	out.Steps = slices.Clone(r.Steps)
	m.mu.Unlock()
	m.saveRollout(&out)
	if m.Audit != nil {
		m.Audit(r.By, r.Revision, names, r.Auto, r.Rollback)
	}
	m.Log.Info("installing", "revision", r.Revision, "rollback", r.Rollback, "servers", names, "by", r.By, "backup", r.Backup)
	go m.runRollout(nodes)
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

func (m *Manager) runRollout(nodes []NodeInfo) {
	ctx := context.Background()
	byID := map[string]NodeInfo{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	r := m.Rollout()
	rollback := r.Rollback
	verb := "update"
	if rollback {
		verb = "roll back"
	}
	done := 0
	for i, s := range r.Steps {
		n := byID[s.ID]
		switch {
		case !n.Reachable:
			m.step(i, StepSkipped, "couldn't be reached: "+n.Error)
			continue
		case n.Updater == nil:
			why := "no updater on this server"
			if n.UpdaterError != "" {
				why = n.UpdaterError
			}
			m.step(i, StepSkipped, why+"; "+verb+" it by hand")
			continue
		case n.Updater.Pinned:
			m.step(i, StepSkipped, "its image is pinned to one version ("+n.Updater.Image+")")
			continue
		}
		rev := ""
		if rollback {
			rev = s.To
		}
		if s.Self {
			m.step(i, StepRestarting, "restarting; this page reconnects when the server is back")
			if _, err := m.Sidecar.Start(ctx, rev); err != nil {
				m.step(i, StepFailed, err.Error())
				m.end(RolloutFailed, "this server couldn't start: "+err.Error())
				return
			}
			// The updater stops this process soon; resume() finishes the
			// rollout's record after the restart.
			return
		}
		m.step(i, StepUpdating, "downloading and restarting")
		state, msg := m.updatePeer(ctx, s, rev)
		m.step(i, state, msg)
		if state == StepFailed {
			m.end(RolloutFailed, s.Name+" didn't "+verb+" ("+msg+"), so the rest were left alone and DNS keeps running on them")
			return
		}
		if state == StepDone {
			done++
		}
	}
	m.end(RolloutDone, summary(done, len(r.Steps), rollback))
}

func summary(done, of int, rollback bool) string {
	if rollback {
		return fmt.Sprintf("%d of %d servers rolled back", done, of)
	}
	return fmt.Sprintf("%d of %d servers updated", done, of)
}

// updatePeer has one other server update itself and waits until it
// answers DNS again on the version asked for.
func (m *Manager) updatePeer(ctx context.Context, s Step, rev string) (string, string) {
	wait, poll, settle := m.durations()
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	raw, err := m.Peers.Ask(actx, s.ID, RPCStart, map[string]string{"revision": rev})
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
		info, err := m.askInfo(ctx, s.ID)
		if err != nil {
			continue // restarting
		}
		if info.Updater != nil && info.Updater.Job != nil && !info.Updater.Job.Started.Before(started) {
			switch job := info.Updater.Job; job.State {
			case JobRolledBack, JobFailed:
				return StepFailed, job.Message
			case JobUpToDate:
				return StepSkipped, "it already had that version"
			}
		}
		// Ready on the new version, and its updater has finished
		// checking it (it could still undo the change).
		if info.Revision == s.To && info.Ready && (info.Updater == nil || !info.Updater.Job.Running()) {
			time.Sleep(settle)
			return StepDone, "running " + short(s.To)
		}
	}
	return StepFailed, fmt.Sprintf("wasn't back on %s after %s", short(s.To), wait.Round(time.Second))
}

func short(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
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
	if RevisionOf(m.Version) == r.Steps[i].To {
		// The updater may still be checking this new container, and
		// would undo the change if it failed; then the old version
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
		m.step(i, StepDone, "running "+short(r.Steps[i].To))
		done := 0
		for _, s := range m.Rollout().Steps {
			if s.State == StepDone {
				done++
			}
		}
		m.end(RolloutDone, summary(done, len(r.Steps), r.Rollback))
		return
	}
	msg := "restarted on the same version"
	if st, err := m.Sidecar.Status(ctx); err == nil && st.Job != nil && st.Job.Message != "" {
		msg = st.Job.Message
	}
	m.step(i, StepFailed, msg)
	m.end(RolloutFailed, "this server didn't change version: "+msg)
}
