//go:build docker

package update

// Runs the updater against a real Docker engine and a local registry:
//
//	go test -tags docker -run TestDockerReplace ./internal/update/
//
// It needs /var/run/docker.sock and pulls alpine and registry:2.

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func sh(t *testing.T, args ...string) string {
	t.Helper()
	var stderr strings.Builder
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = &stderr // pull progress goes here, not into the answer
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v: %v\n%s%s", args, err, out, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// pushVersion builds a tiny image that behaves as told and pushes it to
// the registry as updtest:latest. It is tagged under 127.0.0.1:5000, so
// the localhost:5000 name the container runs from only moves when the
// updater pulls, as on a real server.
func pushVersion(t *testing.T, rev, cmd string) {
	dir := t.TempDir()
	df := "FROM alpine:3.22\nLABEL org.opencontainers.image.revision=" + rev + "\nENV FROM_IMAGE=" + rev + "\nHEALTHCHECK --interval=1s --start-period=1s CMD test -f /tmp/up\nCMD [\"sh\",\"-c\",\"" + cmd + "\"]\n"
	if err := os.WriteFile(dir+"/Dockerfile", []byte(df), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, "docker", "build", "-q", "-t", "127.0.0.1:5000/updtest:latest", dir)
	sh(t, "docker", "push", "-q", "127.0.0.1:5000/updtest:latest")
	// Every published image also gets a sha-<7> tag, which rollbacks use.
	sh(t, "docker", "tag", "127.0.0.1:5000/updtest:latest", "127.0.0.1:5000/updtest:sha-"+rev[:7])
	sh(t, "docker", "push", "-q", "127.0.0.1:5000/updtest:sha-"+rev[:7])
}

// The test images' revisions.
var r1, r2, r3, r4 = strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40), strings.Repeat("4", 40)

func TestDockerReplace(t *testing.T) {
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("no Docker")
	}
	cleanup := func() {
		for _, c := range []string{"updtest", "updtest-self", "updtest-registry"} {
			exec.Command("docker", "rm", "-f", c).Run()
		}
		exec.Command("docker", "network", "rm", "updtest-net").Run()
		exec.Command("docker", "volume", "rm", "updtest-sock", "updtest-data").Run()
	}
	cleanup()
	t.Cleanup(cleanup)
	sh(t, "docker", "run", "-d", "--name", "updtest-registry", "-p", "5000:5000", "registry:2")
	time.Sleep(2 * time.Second)

	good := "trap 'exit 0' TERM; touch /tmp/up; sleep 3600 & wait"
	pushVersion(t, r1, good)
	sh(t, "docker", "pull", "-q", "localhost:5000/updtest:latest")
	sh(t, "docker", "network", "create", "updtest-net")
	sh(t, "docker", "run", "-d", "--name", "updtest", "--restart", "unless-stopped", "--network", "updtest-net", "--network-alias", "dns",
		"-p", "127.0.0.1:18053:53/udp", "-e", "TZ=Europe/Dublin", "-l", "com.example.mine=yes",
		"-v", "updtest-data:/data", "-v", "updtest-sock:"+SocketDir, "localhost:5000/updtest:latest")
	// Stand-in for the updater's own container, so the target is found
	// the way the real one finds it: the other user of the socket volume.
	self := sh(t, "docker", "run", "-d", "--name", "updtest-self", "-v", "updtest-sock:"+SocketDir, "alpine:3.22", "sleep", "3600")

	d := NewDocker("/var/run/docker.sock")
	s := &Sidecar{Docker: d, Self: self, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), HealthWait: 40 * time.Second, Poll: 500 * time.Millisecond}
	ctx := context.Background()
	// Pull of the same image: nothing to do.
	sh(t, "docker", "pull", "-q", "localhost:5000/updtest:latest")
	if st, msg := s.Replace(ctx, ""); st != JobUpToDate {
		t.Fatalf("same image: %s %s", st, msg)
	}
	if st := s.Status(ctx); st.Target != "updtest" || st.Revision != r1 || st.Image != "localhost:5000/updtest:latest" {
		t.Fatalf("status %+v", st)
	}

	// A good new version replaces the container, keeping its settings.
	pushVersion(t, r2, good)
	if st, msg := s.Replace(ctx, ""); st != JobDone {
		t.Fatalf("v2: %s %s", st, msg)
	}
	f := `{{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "com.example.mine"}} {{.HostConfig.RestartPolicy.Name}} {{(index (index .HostConfig.PortBindings "53/udp") 0).HostPort}} {{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}} {{range .Mounts}}{{.Name}},{{end}} {{.State.Health.Status}}`
	got := sh(t, "docker", "inspect", "-f", f, "updtest")
	if want := r2 + " yes unless-stopped 18053 updtest-net "; !strings.HasPrefix(got, want) || !strings.HasSuffix(got, " healthy") || !strings.Contains(got, "updtest-data,") || !strings.Contains(got, "updtest-sock,") {
		t.Fatalf("after update: %q", got)
	}
	env := sh(t, "docker", "inspect", "-f", "{{range .Config.Env}}{{.}} {{end}}", "updtest")
	if !strings.Contains(env, "TZ=Europe/Dublin") || !strings.Contains(env, "FROM_IMAGE="+r2) || strings.Contains(env, "FROM_IMAGE="+r1) {
		t.Fatalf("env %q", env)
	}
	if aliases := sh(t, "docker", "inspect", "-f", `{{(index .NetworkSettings.Networks "updtest-net").Aliases}}`, "updtest"); !strings.Contains(aliases, "dns") {
		t.Fatalf("aliases %q", aliases)
	}
	if n := sh(t, "docker", "ps", "-a", "-q", "--filter", "name=updtest-old"); n != "" {
		t.Fatal("old container left behind")
	}

	// Rolling back goes to the earlier version's sha- tag, and remembers
	// that the container follows :latest, so the next update returns.
	if st, msg := s.Replace(ctx, r1); st != JobDone {
		t.Fatalf("rollback to r1: %s %s", st, msg)
	}
	lf := `{{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "` + labelTrack + `"}}`
	if got := sh(t, "docker", "inspect", "-f", lf, "updtest"); got != r1+" localhost:5000/updtest:latest" {
		t.Fatalf("after rollback: %q", got)
	}
	if st := s.Status(ctx); st.Image != "localhost:5000/updtest:latest" || st.Revision != r1 {
		t.Fatalf("status after rollback %+v", st)
	}
	if st, msg := s.Replace(ctx, ""); st != JobDone {
		t.Fatalf("update after rollback: %s %s", st, msg)
	}
	if got := sh(t, "docker", "inspect", "-f", lf, "updtest"); got != r2 {
		t.Fatalf("after re-update: %q", got)
	}

	// A version that won't start is undone.
	pushVersion(t, r3, "exit 3")
	if st, msg := s.Replace(ctx, ""); st != JobRolledBack {
		t.Fatalf("v3: %s %s", st, msg)
	}
	if got := sh(t, "docker", "inspect", "-f", `{{index .Config.Labels "org.opencontainers.image.revision"}} {{.State.Running}}`, "updtest"); got != r2+" true" {
		t.Fatalf("after rollback: %q", got)
	}

	// One that starts but never becomes healthy is undone too.
	pushVersion(t, r4, "trap 'exit 0' TERM; sleep 3600 & wait")
	s.HealthWait = 8 * time.Second
	if st, msg := s.Replace(ctx, ""); st != JobRolledBack {
		t.Fatalf("v4: %s %s", st, msg)
	}
	if got := sh(t, "docker", "inspect", "-f", `{{index .Config.Labels "org.opencontainers.image.revision"}} {{.State.Running}}`, "updtest"); got != r2+" true" {
		t.Fatalf("after rollback: %q", got)
	}
}
