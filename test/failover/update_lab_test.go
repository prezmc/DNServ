//go:build failover && updatelab

package failover

// TestOneClickUpdate installs a new version on a two-node cluster with a
// witness from the dashboard API, the way the Updates page does, while a
// client asks both nodes for a name nonstop, like a device with two DNS
// servers. It checks that at every moment at least one node answered.
//
// It needs a registry on localhost:5000 holding the old version as
// dnserv:latest, and the new one tagged to push during the test:
//
//	docker run -d --name lab-registry -p 5000:5000 registry:2
//	(build v1 and v2 images; push v1 as localhost:5000/dnserv:latest)
//	DNSERV_IMAGE=localhost:5000/dnserv:latest NEW_IMAGE=localhost:5000/dnserv:v2 \
//	LAB_REGISTRY=http://<registry IP on a network the nodes can reach>:5000 \
//	  go test -tags 'failover updatelab' -run TestOneClickUpdate -v ./test/failover/

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type updView struct {
	Latest *struct{ Revision string }
	Nodes  []struct {
		Name     string
		Revision string
		Behind   bool
		Updater  *struct{ Error string }
	}
	Available  bool
	CanInstall bool `json:"can_install"`
	Rollout    *struct {
		State   string
		Message string
		Steps   []struct{ Name, State, Message string }
	}
}

func TestOneClickUpdate(t *testing.T) {
	newImage := os.Getenv("NEW_IMAGE")
	if newImage == "" || os.Getenv("LAB_REGISTRY") == "" {
		t.Skip("needs NEW_IMAGE and LAB_REGISTRY (see the comment above)")
	}
	l := newLab(t)
	l.updaters, l.registry = true, os.Getenv("LAB_REGISTRY")
	// The nodes reach the registry over the lan network.
	if _, err := docker("network", "connect", l.prefix+"-lan", "lab-registry"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { docker("network", "disconnect", l.prefix+"-lan", "lab-registry") })

	l.bootstrap("n1")
	l.addNode("n2", "n1")
	l.addWitness("w", "n1")
	l.waitHealthy("n1", "n1", "n2", "w")

	var v updView
	check := func() {
		if _, err := l.api("n1").do("POST", "/api/v1/updates/check", nil, &v); err != nil {
			t.Fatal(err)
		}
	}
	check()
	if v.Available {
		t.Fatalf("nothing new yet: %+v", v)
	}
	for _, n := range v.Nodes {
		if n.Updater == nil || n.Updater.Error != "" {
			t.Fatalf("%s has no working updater: %+v", n.Name, n.Updater)
		}
	}

	// Publish the new version.
	if _, err := docker("tag", newImage, "127.0.0.1:5000/dnserv:latest"); err != nil {
		t.Fatal(err)
	}
	if _, err := docker("push", "-q", "127.0.0.1:5000/dnserv:latest"); err != nil {
		t.Fatal(err)
	}
	check()
	if !v.Available || !v.CanInstall {
		t.Fatalf("the new version isn't offered: %+v", v)
	}
	target := v.Latest.Revision

	// A device with both nodes as DNS servers: every 50 ms it asks n1,
	// and n2 if n1 doesn't answer. Addresses are read again as containers
	// are replaced.
	ips := func() []string {
		var out []string
		for _, name := range []string{"n1", "n2"} {
			ip, _ := docker("inspect", "-f", `{{(index .NetworkSettings.Networks "`+l.prefix+`-lan").IPAddress}}`, l.node(name).container)
			out = append(out, ip)
		}
		return out
	}
	var mu sync.Mutex
	cur := ips()
	stop := make(chan struct{})
	var sent, neither, n1Missed, n2Missed int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
			fresh := ips()
			mu.Lock()
			cur = fresh
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			mu.Lock()
			a := cur
			mu.Unlock()
			e1 := lookup(a[0], probeName)
			e2 := lookup(a[1], probeName)
			sent++
			if e1 != nil {
				n1Missed++
			}
			if e2 != nil {
				n2Missed++
			}
			if e1 != nil && e2 != nil {
				neither++
			}
		}
	}()

	start := time.Now()
	if _, err := l.api("n1").do("POST", "/api/v1/updates/install", map[string]any{}, &v); err != nil {
		t.Fatal(err)
	}
	// n1 runs the rollout and goes last, so its API drops for a moment.
	l.waitFor("every server on the new version", 10*time.Minute, func() bool {
		var now updView
		via := "n2"
		// Replaced containers may have new addresses.
		for _, name := range []string{"n1", "n2"} {
			n := l.node(name)
			ip, _ := docker("inspect", "-f", `{{(index .NetworkSettings.Networks "`+l.prefix+`-lan").IPAddress}}`, n.container)
			if ip == "" || strings.Contains(ip, " ") {
				return false // restarting
			}
			l.mu.Lock()
			n.ip = ip
			n.api = newClient(l, n)
			l.mu.Unlock()
		}
		if _, err := l.api(via).do("GET", "/api/v1/updates", nil, &now); err != nil {
			return false
		}
		if len(now.Nodes) != 3 {
			return false
		}
		for _, n := range now.Nodes {
			if n.Revision != target {
				return false
			}
		}
		return true
	})
	took := time.Since(start)
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()

	// n1 finishes the record once its updater has seen it healthy.
	var fin updView
	l.waitFor("the rollout to finish", 2*time.Minute, func() bool {
		_, err := l.api("n1").do("GET", "/api/v1/updates", nil, &fin)
		return err == nil && fin.Rollout != nil && fin.Rollout.State != "running"
	})
	var steps []string
	if fin.Rollout != nil {
		for _, s := range fin.Rollout.Steps {
			steps = append(steps, s.Name+"="+s.State)
		}
	}
	t.Logf("rollout took %s; steps %s; %s", took.Round(time.Second), strings.Join(steps, ", "), fin.Rollout.Message)
	t.Logf("device lookups: %d sent, n1 missed %d, n2 missed %d, both missed at once %d", sent, n1Missed, n2Missed, neither)
	if fin.Rollout == nil || fin.Rollout.State != "done" || strings.Join(steps, ",") != "w=done,n2=done,n1=done" {
		t.Fatalf("rollout: %+v", fin.Rollout)
	}
	if neither > 0 {
		t.Fatalf("%d moments with neither server answering", neither)
	}
	if n1Missed == 0 || n2Missed == 0 {
		t.Fatalf("each node should have restarted once (missed n1 %d, n2 %d)", n1Missed, n2Missed)
	}
	l.waitHealthy("n1", "n1", "n2", "w")
	l.mustChange("n2")
}
