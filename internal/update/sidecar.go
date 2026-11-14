package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The updater ("sidecar") is the only part of DNServ that touches Docker.
// It runs as its own container with the Docker socket mounted, which is
// root on that server, so it is kept as small as possible:
//
//   - it opens no network port; it listens on a Unix socket in a volume
//     it shares only with the DNServ container it looks after;
//   - it updates only that one container (found as the other container
//     mounting that volume, or named in DNSERV_UPDATER_TARGET);
//   - it only ever pulls the image reference that container was created
//     from, so nothing it is told can make it run a different image;
//   - a replacement that doesn't come up healthy is undone, and the old
//     container is started again.

// SocketDir is where the updater's socket lives, in the shared volume.
const SocketDir = "/run/dnserv-updater"

// SocketPath is the updater's socket.
const SocketPath = SocketDir + "/updater.sock"

// Job states.
const (
	JobPulling    = "pulling"     // downloading the new image
	JobReplacing  = "replacing"   // stopping the old container, starting the new
	JobChecking   = "checking"    // waiting for the new container to be healthy
	JobDone       = "done"        // updated
	JobUpToDate   = "up_to_date"  // the pulled image was the one running
	JobRolledBack = "rolled_back" // the new one failed; the old one runs again
	JobFailed     = "failed"      // something went wrong before anything changed, or the undo failed
)

// Job is one update the updater ran or is running.
type Job struct {
	State    string    `json:"state"`
	Message  string    `json:"message,omitempty"`
	From     string    `json:"from,omitempty"` // revisions
	To       string    `json:"to,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
}

// Running reports whether the job is still going.
func (j *Job) Running() bool {
	return j != nil && j.Finished.IsZero()
}

// SidecarStatus is what the updater reports.
type SidecarStatus struct {
	Version   string    `json:"version"`
	Target    string    `json:"target,omitempty"` // container name
	Image     string    `json:"image,omitempty"`  // reference it runs from
	Revision  string    `json:"revision,omitempty"`
	Created   time.Time `json:"created,omitzero"` // of the running image
	Pinned    bool      `json:"pinned,omitempty"` // image@sha256:..., never updated
	Error     string    `json:"error,omitempty"`  // can't find or read its container
	Job       *Job      `json:"job,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Sidecar is the updater's state.
type Sidecar struct {
	Docker  *Docker
	Version string
	Log     *slog.Logger
	// Target is the container to look after (DNSERV_UPDATER_TARGET); empty
	// means the other container that mounts the socket volume.
	Target string
	// Self is this container's ID or name (default: the hostname, which
	// Docker sets to the short container ID).
	Self string
	// HealthWait is how long a new container gets to become healthy
	// (default 3 minutes).
	HealthWait time.Duration
	// Poll is how often health is checked (default 2s).
	Poll time.Duration

	// addVolume, set only by the installer (dnserv -install-updater), is
	// a named volume to mount at SocketDir in the replacement, so the
	// container can reach its new updater. The container is replaced even
	// when its image is current.
	addVolume string

	mu  sync.Mutex
	job *Job
}

// findTarget returns the container to update.
func (s *Sidecar) findTarget(ctx context.Context) (*Container, error) {
	if s.Target != "" {
		c, err := s.Docker.Inspect(ctx, s.Target)
		if err != nil {
			return nil, fmt.Errorf("can't find container %q (DNSERV_UPDATER_TARGET): %w", s.Target, err)
		}
		return c, nil
	}
	self := s.Self
	if self == "" {
		self, _ = os.Hostname()
	}
	me, err := s.Docker.Inspect(ctx, self)
	if err != nil {
		return nil, fmt.Errorf("can't find the updater's own container (%s) to work out which DNServ to look after; set DNSERV_UPDATER_TARGET: %w", self, err)
	}
	vol := ""
	for _, m := range me.Mounts {
		if m.Destination == SocketDir && m.Type == "volume" {
			vol = m.Name
		}
	}
	if vol == "" {
		return nil, fmt.Errorf("the updater needs a named volume at %s, shared with DNServ (or set DNSERV_UPDATER_TARGET)", SocketDir)
	}
	ids, err := s.Docker.ContainersWithVolume(ctx, vol)
	if err != nil {
		return nil, err
	}
	var others []string
	for _, id := range ids {
		if id != me.ID {
			others = append(others, id)
		}
	}
	if len(others) != 1 {
		return nil, fmt.Errorf("%d containers besides the updater use volume %s; it must be exactly one, or set DNSERV_UPDATER_TARGET", len(others), vol)
	}
	return s.Docker.Inspect(ctx, others[0])
}

// Status describes the target and the last job.
func (s *Sidecar) Status(ctx context.Context) SidecarStatus {
	st := SidecarStatus{Version: s.Version, CheckedAt: time.Now()}
	s.mu.Lock()
	if s.job != nil {
		j := *s.job
		st.Job = &j
	}
	s.mu.Unlock()
	c, err := s.findTarget(ctx)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Target, st.Image = c.Name, tracked(c)
	st.Pinned = strings.Contains(st.Image, "@")
	if im, err := s.Docker.InspectImage(ctx, c.Image); err == nil {
		l := im.Labels()
		st.Revision = l[labelRevision]
		if t, err := time.Parse(time.RFC3339, l[labelCreated]); err == nil {
			st.Created = t
		}
	}
	return st
}

// ErrBusy means an update is already running.
var ErrBusy = errors.New("an update is already running")

// labelTrack is set on a container that was put back on an older version:
// it is the image reference it normally follows, so the next update goes
// back to that (":latest") rather than staying on the older version.
const labelTrack = "dev.dnserv.updater.follows"

// tracked is the image reference a container follows.
func tracked(c *Container) string {
	if t := c.Config.Labels[labelTrack]; t != "" {
		return t
	}
	return c.Config.Image
}

var revPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// Channels are the tags an updater may move a container between:
// numbered releases, or every change merged to main.
const (
	ChannelStable = "stable"
	ChannelLatest = "latest"
)

// ValidChannel reports whether c names a channel ("" is the default,
// stable).
func ValidChannel(c string) bool { return c == "" || c == ChannelStable || c == ChannelLatest }

// Request is what DNServ may ask the updater: update to the newest image
// of a channel, or go back to one earlier published version.
type Request struct {
	Revision string `json:"revision,omitempty"`
	Channel  string `json:"channel,omitempty"`
}

// withTag is ref with its tag replaced.
func withTag(ref, tag string) string {
	base := ref
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		base = base[:i]
	}
	return base + ":" + tag
}

// revisionRef is the image for one published revision: the same
// repository, tagged sha-<7 hex>, as the publish workflow tags every
// image.
func revisionRef(follows, rev string) (string, error) {
	if !revPattern.MatchString(rev) {
		return "", fmt.Errorf("%q isn't a version", rev)
	}
	return withTag(follows, "sha-"+rev[:7]), nil
}

// Start begins an update in the background: to the newest image of the
// container's own tag, or, with rev, back to that earlier published
// version of the same image.
func (s *Sidecar) Start(req Request) (*Job, error) {
	rev, ch := req.Revision, req.Channel
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job.Running() {
		return nil, ErrBusy
	}
	if rev != "" && !revPattern.MatchString(rev) {
		return nil, fmt.Errorf("%q isn't a version", rev)
	}
	if !ValidChannel(ch) {
		return nil, fmt.Errorf("%q isn't an update channel", ch)
	}
	s.job = &Job{State: JobPulling, Started: time.Now()}
	j := *s.job
	go s.run(rev, ch)
	return &j, nil
}

func (s *Sidecar) set(f func(j *Job)) {
	s.mu.Lock()
	if s.job == nil {
		s.job = &Job{Started: time.Now()}
	}
	f(s.job)
	s.mu.Unlock()
}

func (s *Sidecar) finish(state, msg string) {
	s.set(func(j *Job) { j.State, j.Message, j.Finished = state, msg, time.Now() })
	if state == JobDone || state == JobUpToDate {
		s.Log.Info("update finished", "state", state, "detail", msg)
	} else {
		s.Log.Error("update didn't go through", "state", state, "detail", msg)
	}
}

func (s *Sidecar) run(rev, ch string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	state, msg := s.Replace(ctx, Request{Revision: rev, Channel: ch})
	s.finish(state, msg)
}

// Replace pulls the target's image and, if it changed, swaps the
// container for one made from the new image with the same settings. It
// returns a job state and a sentence for the dashboard. With rev it goes
// to that published version instead (a rollback).
func (s *Sidecar) Replace(ctx context.Context, req Request) (string, string) {
	rev := req.Revision
	old, err := s.findTarget(ctx)
	if err != nil {
		return JobFailed, err.Error()
	}
	follows := tracked(old)
	ref := follows
	if strings.Contains(ref, "@") {
		return JobFailed, "this container's image is pinned to one digest (" + ref + "), so it isn't updated"
	}
	if strings.HasPrefix(ref, "sha256:") || ref == "" {
		return JobFailed, "this container was started from an image ID, not a name, so there is nothing to update to"
	}
	if req.Channel != "" && !strings.Contains(follows, "@") {
		// The channel the owner picked: this and later updates follow it.
		follows = withTag(follows, req.Channel)
		ref = follows
	}
	if rev != "" {
		if ref, err = revisionRef(follows, rev); err != nil {
			return JobFailed, err.Error()
		}
	}
	oldImg, err := s.Docker.InspectImage(ctx, old.Image)
	if err != nil {
		// Gone from under the running container (Docker's containerd
		// image store drops an image as soon as its name moves to a newer
		// one, e.g. after a "docker compose pull"). Settings are then told
		// apart from the image's defaults by comparing with the new image.
		s.Log.Info("the running image is gone; comparing settings with the new image", "err", err)
		oldImg = nil
	}
	if oldImg != nil {
		s.set(func(j *Job) { j.From = oldImg.Labels()[labelRevision] })
	}
	s.Log.Info("pulling", "image", ref, "container", old.Name)
	if err := s.Docker.Pull(ctx, ref); err != nil {
		return JobFailed, err.Error()
	}
	newImg, err := s.Docker.InspectImage(ctx, ref)
	if err != nil {
		return JobFailed, "can't read the new image: " + err.Error()
	}
	s.set(func(j *Job) { j.To = newImg.Labels()[labelRevision] })
	if newImg.ID == old.Image && s.addVolume == "" {
		if rev != "" {
			return JobUpToDate, "already running that version"
		}
		return JobUpToDate, "already running the newest " + ref
	}

	base := oldImg
	if base == nil {
		base = newImg
	}
	body, err := recreateBody(old, base, ref, newImg.ID, follows, s.addVolume)
	if err != nil {
		return JobFailed, err.Error()
	}
	s.set(func(j *Job) { j.State = JobReplacing })
	stopWait := 30 * time.Second
	if t := old.Config.StopTimeout; t != nil && *t > 0 {
		stopWait = time.Duration(*t) * time.Second
	}
	name := old.Name
	parked := fmt.Sprintf("%s-old-%d", name, time.Now().Unix())
	s.Log.Info("replacing container", "container", name, "from", old.Image, "to", newImg.ID)
	// The old container stops before the new one starts: they use the
	// same ports. It is kept (renamed) until the new one is healthy.
	if err := s.Docker.Stop(ctx, old.ID, stopWait); err != nil {
		_ = s.Docker.Start(ctx, old.ID)
		return JobFailed, "couldn't stop the old container: " + err.Error()
	}
	undo := func(why string, newID string) (string, string) {
		bg, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if newID != "" {
			_ = s.Docker.Stop(bg, newID, 10*time.Second)
			_ = s.Docker.Remove(bg, newID)
		}
		var errs []string
		if err := s.Docker.Rename(bg, old.ID, name); err != nil {
			errs = append(errs, "rename back: "+err.Error())
		}
		if err := s.Docker.Start(bg, old.ID); err != nil {
			errs = append(errs, "start: "+err.Error())
		}
		if len(errs) > 0 {
			return JobFailed, why + ", and putting the old container back failed (" + strings.Join(errs, "; ") + "); start it with docker compose up -d"
		}
		return JobRolledBack, why + ", so the old version is running again"
	}
	if err := s.Docker.Rename(ctx, old.ID, parked); err != nil {
		_ = s.Docker.Start(ctx, old.ID)
		return JobFailed, "couldn't rename the old container: " + err.Error()
	}
	id, err := s.Docker.Create(ctx, name, body)
	if err != nil {
		return undo("the new container couldn't be created ("+err.Error()+")", "")
	}
	if err := s.Docker.Start(ctx, id); err != nil {
		return undo("the new container couldn't start ("+err.Error()+")", id)
	}
	s.set(func(j *Job) { j.State = JobChecking })
	if err := s.waitHealthy(ctx, id); err != nil {
		return undo("the new version "+err.Error(), id)
	}
	if err := s.Docker.Remove(ctx, old.ID); err != nil {
		s.Log.Warn("couldn't remove the old container", "container", parked, "err", err)
	}
	if err := s.Docker.RemoveImage(ctx, old.Image); err != nil {
		s.Log.Debug("old image kept", "image", old.Image, "err", err)
	}
	return JobDone, "updated " + name
}

func (s *Sidecar) waitHealthy(ctx context.Context, id string) error {
	wait, poll := s.HealthWait, s.Poll
	if wait <= 0 {
		wait = 3 * time.Minute
	}
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(wait)
	var runningSince time.Time
	for {
		c, err := s.Docker.Inspect(ctx, id)
		if err != nil {
			return fmt.Errorf("disappeared (%v)", err)
		}
		switch {
		case !c.State.Running && !c.State.Restarting && c.State.Status != "created":
			return fmt.Errorf("stopped with exit code %d", c.State.ExitCode)
		case c.State.Restarting:
			return errors.New("keeps restarting")
		case c.State.Health != nil && c.State.Health.Status == "healthy":
			return nil
		case c.State.Health != nil && c.State.Health.Status == "unhealthy":
			return errors.New("reported itself unhealthy")
		case c.State.Health == nil && c.State.Running:
			// No health check: running for a while has to do.
			if runningSince.IsZero() {
				runningSince = time.Now()
			} else if time.Since(runningSince) >= 15*time.Second {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wasn't healthy after %s", wait.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// recreateBody builds the create request for a copy of old that runs
// newImageID. Settings that only came from the old image (its env
// defaults, labels, command, health check...) are dropped so the new
// image's own apply; everything set on the container is kept.
// follows is the reference the container keeps following; when it isn't
// ref (a rollback), it is kept in a label for the next update.
func recreateBody(old *Container, oldImg *Image, ref, newImageID, follows, addVolume string) (map[string]any, error) {
	var cfg map[string]any
	if err := json.Unmarshal(old.Raw["Config"], &cfg); err != nil {
		return nil, fmt.Errorf("can't read the container's settings: %w", err)
	}
	var imgCfg map[string]any
	for k, v := range oldImg.Config {
		if imgCfg == nil {
			imgCfg = map[string]any{}
		}
		var x any
		_ = json.Unmarshal(v, &x)
		imgCfg[k] = x
	}
	// Docker sets the hostname to the short container ID unless told
	// otherwise; the new container gets its own.
	if hn, _ := cfg["Hostname"].(string); len(old.ID) >= 12 && hn == old.ID[:12] {
		delete(cfg, "Hostname")
	}
	if env, ok := cfg["Env"].([]any); ok {
		fromImage := map[string]bool{}
		if ie, ok := imgCfg["Env"].([]any); ok {
			for _, e := range ie {
				if s, ok := e.(string); ok {
					fromImage[s] = true
				}
			}
		}
		var keep []any
		for _, e := range env {
			if s, ok := e.(string); ok && fromImage[s] {
				continue
			}
			keep = append(keep, e)
		}
		cfg["Env"] = keep
	}
	if labels, ok := cfg["Labels"].(map[string]any); ok {
		il, _ := imgCfg["Labels"].(map[string]any)
		out := maps.Clone(labels)
		for k, v := range labels {
			// org.opencontainers.image.* always describe an image, never
			// a container setting.
			if iv, ok := il[k]; ok && iv == v || strings.HasPrefix(k, "org.opencontainers.image.") {
				delete(out, k)
			}
		}
		// Compose remembers the image it created the container from;
		// point it at the new one so "docker compose up -d" doesn't
		// replace the container again for no reason.
		if _, ok := out["com.docker.compose.image"]; ok {
			out["com.docker.compose.image"] = newImageID
		}
		cfg["Labels"] = out
	}
	labels, _ := cfg["Labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	delete(labels, labelTrack)
	if follows != "" && follows != ref {
		labels[labelTrack] = follows
	}
	cfg["Labels"] = labels
	for _, k := range []string{"Cmd", "Entrypoint", "Healthcheck", "WorkingDir", "User", "StopSignal", "Volumes", "ExposedPorts", "Shell", "OnBuild", "ArgsEscaped"} {
		if v, ok := cfg[k]; ok && reflect.DeepEqual(v, imgCfg[k]) {
			delete(cfg, k)
		}
	}
	cfg["Image"] = ref

	var host map[string]any
	if err := json.Unmarshal(old.Raw["HostConfig"], &host); err != nil {
		return nil, fmt.Errorf("can't read the container's host settings: %w", err)
	}
	body := cfg
	body["HostConfig"] = host
	if addVolume != "" {
		mounts, _ := host["Mounts"].([]any)
		host["Mounts"] = append(mounts, map[string]any{"Type": "volume", "Source": addVolume, "Target": SocketDir})
	}

	var ns struct {
		Networks map[string]struct {
			IPAMConfig any      `json:"IPAMConfig"`
			Links      []string `json:"Links"`
			Aliases    []string `json:"Aliases"`
			DriverOpts any      `json:"DriverOpts"`
		} `json:"Networks"`
	}
	if raw, ok := old.Raw["NetworkSettings"]; ok {
		_ = json.Unmarshal(raw, &ns)
	}
	if len(ns.Networks) > 0 {
		eps := map[string]any{}
		for name, n := range ns.Networks {
			ep := map[string]any{}
			if n.IPAMConfig != nil {
				ep["IPAMConfig"] = n.IPAMConfig
			}
			if len(n.Links) > 0 {
				ep["Links"] = n.Links
			}
			var aliases []string
			for _, a := range n.Aliases {
				// Docker adds the short ID as an alias by itself.
				if len(old.ID) >= 12 && a == old.ID[:12] {
					continue
				}
				aliases = append(aliases, a)
			}
			if len(aliases) > 0 {
				ep["Aliases"] = aliases
			}
			if n.DriverOpts != nil {
				ep["DriverOpts"] = n.DriverOpts
			}
			eps[name] = ep
		}
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": eps}
	}
	return body, nil
}

// Serve answers DNServ on the Unix socket at path until ctx ends. The
// socket is given to uid/gid owner (DNServ's user in the image) with
// mode 0660, so only DNServ (and root) can use it.
func (s *Sidecar) Serve(ctx context.Context, path string, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		s.Log.Warn("couldn't hand the socket to DNServ's user", "err", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Status(r.Context()))
	})
	mux.HandleFunc("POST /v1/update", func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		j, err := s.Start(req)
		if errors.Is(err, ErrBusy) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.Log.Info("update requested", "revision", req.Revision, "channel", req.Channel)
		writeJSON(w, http.StatusAccepted, j)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.Log.Info("updater listening", "socket", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
