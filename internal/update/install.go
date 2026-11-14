package update

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

// The installer adds the updater to a DNServ container that was set up
// before the updater existed, with one command on its server:
//
//	docker run --rm --pull always -u 0 -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/prezmc/dnserv -install-updater
//
// DNServ can't do this itself: it has no access to Docker, on purpose, so
// something that does (that command) has to start the updater once. It
//
//  1. finds the DNServ container on this server (or the one named),
//  2. starts the updater container next to it, sharing a new volume, and
//  3. replaces the DNServ container with an identical one that also mounts
//     that volume (newest image of its tag, checked healthy, undone if
//     not), so the dashboard can reach the updater.
//
// Compose files aren't edited. A container that came from compose keeps
// its compose labels, and the updater gets labels that make it part of
// the same project.

// ContainerSummary is one line of "docker ps".
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Command string            `json:"Command"`
	Labels  map[string]string `json:"Labels"`
}

// Name is the container's name without the slash.
func (c ContainerSummary) Name() string {
	if len(c.Names) == 0 {
		return c.ID[:12]
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// Containers lists the running containers.
func (d *Docker) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var out []ContainerSummary
	err := d.do(ctx, "GET", "/containers/json", url.Values{}, nil, &out)
	return out, err
}

// isDNServImage matches DNServ's images under either name, any registry
// and tag.
func isDNServImage(ref string) bool {
	r, err := ParseRef(ref)
	if err != nil {
		return false
	}
	name := r.Repo[strings.LastIndex(r.Repo, "/")+1:]
	return name == "dnserv" || name == "dnserve"
}

// InstallUpdater sets up the updater for target (a container name; empty:
// the only DNServ container running here). It reports progress on out.
func InstallUpdater(ctx context.Context, d *Docker, target string, out io.Writer, log *slog.Logger) error {
	if target == "" {
		self, _ := os.Hostname()
		if self == "" {
			self = "-"
		}
		list, err := d.Containers(ctx)
		if err != nil {
			return err
		}
		var found []ContainerSummary
		for _, c := range list {
			// Not this installer (it runs the same image), and not an
			// updater.
			if strings.Contains(c.Command, "updater") || strings.HasPrefix(c.ID, self) {
				continue
			}
			// "docker ps" shows an image ID once its tag has moved on, so
			// read the name the container was created from.
			img := c.Image
			if !isDNServImage(img) {
				full, err := d.Inspect(ctx, c.ID)
				if err != nil {
					continue
				}
				img = full.Config.Image
			}
			if isDNServImage(img) {
				found = append(found, c)
			}
		}
		switch len(found) {
		case 0:
			return fmt.Errorf("no running DNServ container found on this server; start it first, or name it with -target NAME")
		case 1:
			target = found[0].Name()
		default:
			var names []string
			for _, c := range found {
				names = append(names, c.Name())
			}
			return fmt.Errorf("more than one DNServ container here (%s); run this once for each, adding -target NAME", strings.Join(names, ", "))
		}
	}
	c, err := d.Inspect(ctx, target)
	if err != nil {
		return fmt.Errorf("can't find container %q: %w", target, err)
	}
	ref := tracked(c)
	for _, m := range c.Mounts {
		if m.Destination == SocketDir {
			fmt.Fprintf(out, "%s already has an updater volume (%s).\n", c.Name, m.Name)
			return ensureUpdater(ctx, d, c, m.Name, ref, out)
		}
	}
	vol := c.Name + "-updater"
	if err := ensureUpdater(ctx, d, c, vol, ref, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "Restarting %s with the updater connected (its DNS is down for a few seconds)...\n", c.Name)
	s := &Sidecar{Docker: d, Target: c.Name, Log: log, addVolume: vol}
	state, msg := s.Replace(ctx, Request{})
	if state != JobDone {
		return fmt.Errorf("%s: %s", state, msg)
	}
	fmt.Fprintf(out, "Done. Open the dashboard's Updates page: %s now has one-click updates.\n", c.Name)
	return nil
}

// ensureUpdater starts the updater container for c, unless one is
// running.
func ensureUpdater(ctx context.Context, d *Docker, c *Container, vol, ref string, out io.Writer) error {
	name := c.Name + "-updater"
	if u, err := d.Inspect(ctx, name); err == nil {
		if !u.State.Running {
			if err := d.Start(ctx, u.ID); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "Updater container %s is running.\n", name)
		return nil
	}
	labels := map[string]string{}
	// Part of the same compose project, so "docker compose" knows it.
	if p := c.Config.Labels["com.docker.compose.project"]; p != "" {
		for _, k := range []string{"com.docker.compose.project", "com.docker.compose.project.working_dir", "com.docker.compose.project.config_files"} {
			if v := c.Config.Labels[k]; v != "" {
				labels[k] = v
			}
		}
		labels["com.docker.compose.service"] = name
		labels["com.docker.compose.oneoff"] = "False"
		labels["com.docker.compose.container-number"] = "1"
	}
	body := map[string]any{
		"Image":       ref,
		"Cmd":         []string{"-updater"},
		"User":        "0:0",
		"Labels":      labels,
		"Env":         []string{"DNSERV_UPDATER_TARGET=" + c.Name},
		"Healthcheck": map[string]any{"Test": []string{"NONE"}},
		"HostConfig": map[string]any{
			"NetworkMode":   "none",
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"Mounts": []map[string]any{
				{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/var/run/docker.sock"},
				{"Type": "volume", "Source": vol, "Target": SocketDir},
			},
		},
	}
	fmt.Fprintf(out, "Starting updater container %s...\n", name)
	id, err := d.Create(ctx, name, body)
	if err != nil {
		return fmt.Errorf("couldn't create the updater: %w", err)
	}
	if err := d.Start(ctx, id); err != nil {
		return fmt.Errorf("couldn't start the updater: %w", err)
	}
	// Give it a moment to open its socket.
	time.Sleep(2 * time.Second)
	return nil
}
