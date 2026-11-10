//go:build failover

// Package failover runs DNServe nodes in real containers and breaks them on
// purpose: it kills leaders, cuts the network between servers, restarts
// everything at once and upgrades one node at a time, while a client sends
// DNS queries to every node nonstop and counts any that go unanswered.
//
// It needs Docker. Run it with
//
//	go test -tags failover -v -timeout 30m ./test/failover/
//
// DNSERVE_IMAGE picks the image to test (default: build the repository's
// Dockerfile as dnserve:failover-test). FAILOVER_REPORT, when set, is a file
// the results table is written to, as Markdown.
package failover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserve/internal/auth"
)

const (
	adminUser = "owner"
	adminPass = "failover-lab-Passw0rd!"
	// probeName is a local record every node answers from its own copy of
	// the settings, so the probe measures DNServe and not an upstream.
	probeName = "probe.lab.home.arpa."
	probeIP   = "10.53.0.1"
	// probeEvery is the gap between queries to each node (50 per second).
	probeEvery   = 20 * time.Millisecond
	probeTimeout = 500 * time.Millisecond
)

var (
	imageOnce sync.Once
	imageName string
	imageErr  error
)

// image returns the image under test, building it once if needed.
func image(t *testing.T) string {
	t.Helper()
	imageOnce.Do(func() {
		if v := os.Getenv("DNSERVE_IMAGE"); v != "" {
			imageName = v
			return
		}
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		imageName = "dnserve:failover-test"
		out, err := exec.Command("docker", "build", "-q", "-t", imageName, root).CombinedOutput()
		if err != nil {
			imageErr = fmt.Errorf("docker build: %v\n%s", err, out)
		}
	})
	if imageErr != nil {
		t.Fatal(imageErr)
	}
	return imageName
}

func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// lab is one test's set of containers and networks. Every container is on
// two networks: "lan", where the test client sends DNS and API calls, and
// "raft", the only one node-to-node traffic uses (each node advertises a
// name that exists only there). Disconnecting a node from "raft" cuts it
// off from the other servers while devices can still reach it, which is
// what a broken link between two sites looks like.
type lab struct {
	t      *testing.T
	prefix string
	image  string

	mu     sync.Mutex
	nodes  map[string]*node
	order  []string
	steps  int64 // last TOTP step used; codes are never reused
	secret string
	// token is an API token for the admin. It is replicated, so it works
	// on every node and across restarts; sessions live in one node's
	// memory, and each sign-in uses up an authenticator code.
	token string

	records []map[string]string // local records, kept in step with the cluster

	probe   *prober
	results []result
}

type node struct {
	name      string
	witness   bool
	container string
	ip        string // on the lan network
	up        bool   // the test expects this node to answer DNS
	api       *client
	sess      *client // signed-in session, until the node restarts
	id        string  // cluster node ID
}

func newLab(t *testing.T) *lab {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if _, err := docker("info"); err != nil {
		t.Skipf("docker not running: %v", err)
	}
	l := &lab{t: t, image: image(t), nodes: map[string]*node{},
		prefix: fmt.Sprintf("dnslab-%s-%d", strings.ToLower(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(t.Name(), "")), time.Now().Unix()%100000)}
	if _, err := docker("network", "create", l.prefix+"-lan"); err != nil {
		t.Fatal(err)
	}
	if _, err := docker("network", "create", "--internal", l.prefix+"-raft"); err != nil {
		t.Fatal(err)
	}
	l.records = []map[string]string{{"name": strings.TrimSuffix(probeName, "."), "value": probeIP}}
	l.probe = newProber(l)
	t.Cleanup(l.cleanup)
	return l
}

func (l *lab) cleanup() {
	l.probe.stop()
	l.writeReport()
	if l.t.Failed() || os.Getenv("FAILOVER_LOGS") != "" {
		for _, n := range l.order {
			out, _ := docker("logs", "--tail", "80", l.nodes[n].container)
			l.t.Logf("---- last log lines of %s ----\n%s", n, out)
		}
	}
	if os.Getenv("FAILOVER_KEEP") != "" {
		l.t.Logf("keeping containers with prefix %s", l.prefix)
		return
	}
	for _, n := range l.order {
		docker("rm", "-f", "-v", l.nodes[n].container)
		docker("volume", "rm", "-f", l.nodes[n].container)
	}
	docker("network", "rm", l.prefix+"-lan")
	docker("network", "rm", l.prefix+"-raft")
}

func (l *lab) node(name string) *node {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.nodes[name]
	if n == nil {
		l.t.Fatalf("no node %s", name)
	}
	return n
}

// create makes and starts a node's container. env adds variables.
func (l *lab) create(name string, witness bool, env ...string) *node {
	l.t.Helper()
	l.mu.Lock()
	n := l.nodes[name]
	if n == nil {
		n = &node{name: name, witness: witness, container: l.prefix + "-" + name}
		l.nodes[name] = n
		l.order = append(l.order, name)
	}
	l.mu.Unlock()
	args := []string{"create", "--name", n.container, "--hostname", name,
		"--network", l.prefix + "-lan",
		"-v", n.container + ":/data",
		"-e", "DNSERVE_NODE_NAME=" + name,
		"-e", "DNSERVE_CLUSTER_ADVERTISE=" + name + "-raft:8081",
		// Nothing upstream is reachable from the lab; the probe uses a
		// local record. Lists would only slow start-up.
		"-e", "DNSERVE_LOG_LEVEL=debug",
	}
	if witness {
		args = append(args, "-e", "DNSERVE_ROLE=witness")
	}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, l.image)
	if _, err := docker(args...); err != nil {
		l.t.Fatal(err)
	}
	l.connectRaft(n)
	l.start(name)
	return n
}

func (l *lab) connectRaft(n *node) {
	l.t.Helper()
	if _, err := docker("network", "connect", "--alias", n.name+"-raft", l.prefix+"-raft", n.container); err != nil {
		l.t.Fatal(err)
	}
}

// start starts a stopped container and waits for its HTTP port.
func (l *lab) start(name string) {
	l.t.Helper()
	n := l.node(name)
	if _, err := docker("start", n.container); err != nil {
		l.t.Fatal(err)
	}
	ip, err := docker("inspect", "-f", `{{(index .NetworkSettings.Networks "`+l.prefix+`-lan").IPAddress}}`, n.container)
	if err != nil || ip == "" {
		l.t.Fatalf("no lan address for %s: %v", name, err)
	}
	l.mu.Lock()
	n.ip = ip
	n.api = newClient(l, n)
	n.sess = nil
	l.mu.Unlock()
	l.waitFor(name+" HTTP up", 30*time.Second, func() bool {
		resp, err := http.Get("http://" + ip + ":8080/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	if !n.witness {
		l.waitFor(name+" answers DNS", 30*time.Second, func() bool { return lookup(ip, probeName) == nil || l.setupPending(n) })
	}
	l.mu.Lock()
	n.up = !n.witness
	l.mu.Unlock()
}

// setupPending is true for a node that hasn't been set up yet (it has no
// probe record to answer).
func (l *lab) setupPending(n *node) bool {
	var s struct{ Needed bool }
	_, err := n.api.do("GET", "/api/v1/setup", nil, &s)
	return err == nil && s.Needed
}

// kill stops a node the hard way (power cut, kernel panic).
func (l *lab) kill(name string) {
	l.t.Helper()
	n := l.node(name)
	l.mu.Lock()
	n.up = false
	l.mu.Unlock()
	if _, err := docker("kill", n.container); err != nil {
		l.t.Fatal(err)
	}
}

// stop stops a node cleanly (docker stop, a host reboot).
func (l *lab) stop(name string) {
	l.t.Helper()
	n := l.node(name)
	l.mu.Lock()
	n.up = false
	l.mu.Unlock()
	if _, err := docker("stop", "-t", "10", n.container); err != nil {
		l.t.Fatal(err)
	}
}

// recreate replaces a node's container with a new one on the same data
// volume, as `docker compose pull && docker compose up -d` does for an
// upgrade.
func (l *lab) recreate(name string) {
	l.t.Helper()
	n := l.node(name)
	l.mu.Lock()
	n.up = false
	l.mu.Unlock()
	if _, err := docker("stop", "-t", "10", n.container); err != nil {
		l.t.Fatal(err)
	}
	if _, err := docker("rm", n.container); err != nil {
		l.t.Fatal(err)
	}
	l.create(name, n.witness)
}

// isolate cuts a node off from the other servers; devices can still reach
// it.
func (l *lab) isolate(name string) {
	l.t.Helper()
	if _, err := docker("network", "disconnect", l.prefix+"-raft", l.node(name).container); err != nil {
		l.t.Fatal(err)
	}
}

func (l *lab) heal(name string) { l.t.Helper(); l.connectRaft(l.node(name)) }

func (l *lab) waitFor(what string, timeout time.Duration, fn func() bool) time.Duration {
	l.t.Helper()
	start := time.Now()
	for time.Since(start) < timeout {
		if fn() {
			return time.Since(start)
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("timed out after %s waiting for: %s", timeout, what)
	return 0
}

// setupCode reads the one-time setup code from a node's log.
func (l *lab) setupCode(name string) string {
	l.t.Helper()
	var code string
	l.waitFor(name+" setup code in log", 20*time.Second, func() bool {
		out, _ := docker("logs", l.node(name).container)
		m := regexp.MustCompile(`setup_code=([A-Z0-9-]+)`).FindAllStringSubmatch(out, -1)
		if len(m) == 0 {
			return false
		}
		code = m[len(m)-1][1]
		return true
	})
	return code
}

// totp returns an authenticator code for a step never used before. Each
// sign-in uses up a step, so a burst of sign-ins may wait for the clock.
func (l *lab) totp() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		cur := time.Now().Unix() / 30
		step := max(l.steps+1, cur-1)
		if step <= cur+1 {
			l.steps = step
			code, err := auth.TOTPCode(l.secret, time.Unix(step*30, 0))
			if err != nil {
				l.t.Fatal(err)
			}
			return code
		}
		l.mu.Unlock()
		time.Sleep(time.Second)
		l.mu.Lock()
	}
}

// --- cluster set-up ---

// bootstrap makes the first node and sets up its admin with an
// authenticator, as the setup wizard does.
func (l *lab) bootstrap(name string) *node {
	l.t.Helper()
	n := l.create(name, false)
	code := l.setupCode(name)
	var s struct{ CSRF string }
	if _, err := n.api.do("POST", "/api/v1/setup", map[string]string{"code": code, "username": adminUser, "password": adminPass}, &s); err != nil {
		l.t.Fatal(err)
	}
	n.api.csrf = s.CSRF
	var b struct{ Secret string }
	if _, err := n.api.do("POST", "/api/v1/auth/totp/begin", map[string]string{}, &b); err != nil {
		l.t.Fatal(err)
	}
	l.secret = b.Secret
	if _, err := n.api.do("POST", "/api/v1/auth/totp/confirm", map[string]string{"code": l.totp()}, &s); err != nil {
		l.t.Fatal(err)
	}
	n.api.csrf = s.CSRF
	n.api.signedIn = true
	var tok struct{ Token string }
	perms := []string{"dashboard.view", "querylog.view", "data.export", "domains.allowblock", "rules.edit", "lists.manage",
		"devices.manage", "upstream.manage", "network.manage", "users.manage", "cluster.manage", "backups.manage", "audit.view"}
	if _, err := n.api.do("POST", "/api/v1/tokens", map[string]any{"name": "failover lab", "perms": perms}, &tok); err != nil {
		l.t.Fatal(err)
	}
	l.token = tok.Token
	n.api = newClient(l, n)
	l.pushRecords(name)
	l.waitDNS(name, probeName, probeIP)
	n.id = l.status(name).Self
	return n
}

// joinCode makes a join code on node via.
func (l *lab) joinCode(via string) string {
	l.t.Helper()
	var out struct{ Code string }
	if _, err := l.api(via).do("POST", "/api/v1/cluster/join-codes", map[string]string{"host": ""}, &out); err != nil {
		l.t.Fatal(err)
	}
	return out.Code
}

// addNode starts a fresh node and joins it through the setup wizard's
// "add this server to my DNServe" path.
func (l *lab) addNode(name, via string) *node {
	l.t.Helper()
	code := l.joinCode(via)
	n := l.create(name, false)
	setup := l.setupCode(name)
	if _, err := n.api.do("POST", "/api/v1/setup/join", map[string]string{"code": setup, "join_code": code, "host": ""}, nil); err != nil {
		l.t.Fatal(err)
	}
	l.waitDNS(name, probeName, probeIP)
	n.id = l.status(name).Self
	return n
}

// addWitness starts a witness with a join code in DNSERVE_JOIN, as the
// witness compose file does.
func (l *lab) addWitness(name, via string) *node {
	l.t.Helper()
	code := l.joinCode(via)
	n := l.create(name, true, "DNSERVE_JOIN="+code)
	l.waitFor(name+" in the cluster", 60*time.Second, func() bool {
		for _, m := range l.status(via).Nodes {
			if m.Name == name && m.Voter && m.Reachable {
				n.id = m.ID
				return true
			}
		}
		return false
	})
	return n
}

// --- API ---

type client struct {
	l        *lab
	n        *node
	base     string
	hc       *http.Client
	csrf     string
	signedIn bool
	token    string
}

// newClient makes a client for a node, using the lab's API token once
// there is one.
func newClient(l *lab, n *node) *client {
	jar, _ := cookiejar.New(nil)
	return &client{l: l, n: n, base: "http://" + n.ip + ":8080", hc: &http.Client{Jar: jar, Timeout: 40 * time.Second}, token: l.token}
}

type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg) }

func (c *client) do(method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, body)
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = string(raw)
		}
		return resp.StatusCode, &apiError{resp.StatusCode, e.Error}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode, nil
}

// signIn signs in with password and authenticator code.
func (c *client) signIn() error {
	var s struct{ CSRF, Stage string }
	c.csrf = ""
	if _, err := c.do("POST", "/api/v1/auth/login", map[string]string{"username": adminUser, "password": adminPass}, &s); err != nil {
		return err
	}
	c.csrf = s.CSRF
	if _, err := c.do("POST", "/api/v1/auth/mfa", map[string]string{"code": c.l.totp()}, &s); err != nil {
		return err
	}
	c.csrf = s.CSRF
	c.signedIn = true
	return nil
}

// api returns a client for a node that uses the lab's API token.
func (l *lab) api(name string) *client {
	l.t.Helper()
	return l.node(name).api
}

// session signs in on a node with password and authenticator code, for
// the few actions that need a person (recovery, joining another cluster).
func (l *lab) session(name string) *client {
	l.t.Helper()
	l.mu.Lock()
	n := l.nodes[name]
	if n.sess != nil {
		l.mu.Unlock()
		return n.sess
	}
	c := newClient(l, n)
	l.mu.Unlock()
	c.token = ""
	if err := c.signIn(); err != nil {
		l.t.Fatalf("sign in on %s: %v", name, err)
	}
	l.mu.Lock()
	n.sess = c
	l.mu.Unlock()
	return c
}

type memberStatus struct {
	ID        string
	Name      string
	Leader    bool
	Voter     bool
	Witness   bool
	Role      string
	Reachable bool
	Behind    uint64
}

type clusterStatus struct {
	Self      string
	LeaderID  string `json:"leader_id"`
	Healthy   bool
	Voters    int
	Tolerates int
	LeftOut   bool `json:"left_out"`
	Nodes     []memberStatus
}

func (l *lab) status(name string) clusterStatus {
	l.t.Helper()
	var out struct{ Cluster clusterStatus }
	if _, err := l.api(name).do("GET", "/api/v1/cluster", nil, &out); err != nil {
		l.t.Fatalf("cluster status on %s: %v", name, err)
	}
	return out.Cluster
}

// tryStatus is status without failing the test.
func (l *lab) tryStatus(name string) (clusterStatus, error) {
	var out struct{ Cluster clusterStatus }
	_, err := l.api(name).do("GET", "/api/v1/cluster", nil, &out)
	return out.Cluster, err
}

func (l *lab) leaderName(name string) string {
	st, err := l.tryStatus(name)
	if err != nil {
		return ""
	}
	for _, m := range st.Nodes {
		if m.ID == st.LeaderID {
			return m.Name
		}
	}
	return ""
}

// pushRecords saves the lab's local records through node via.
func (l *lab) pushRecords(via string) error {
	_, err := l.api(via).do("PATCH", "/api/v1/settings", map[string]any{"records": l.records}, nil)
	return err
}

// change adds a local record through node via and returns its name. It
// is the lab's stand-in for any settings change.
func (l *lab) change(via string) (string, error) {
	name := fmt.Sprintf("change-%d.lab.home.arpa", time.Now().UnixNano())
	l.records = append(l.records, map[string]string{"name": name, "value": "10.53.1.1"})
	if err := l.pushRecords(via); err != nil {
		l.records = l.records[:len(l.records)-1]
		return "", err
	}
	return name + ".", nil
}

// mustChange makes a change and waits until every node that is up
// answers it.
func (l *lab) mustChange(via string) string {
	l.t.Helper()
	name, err := l.change(via)
	if err != nil {
		l.t.Fatalf("change via %s: %v", via, err)
	}
	for _, n := range l.upNodes() {
		l.waitDNS(n, name, "10.53.1.1")
	}
	return name
}

func (l *lab) upNodes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, n := range l.order {
		if l.nodes[n].up {
			out = append(out, n)
		}
	}
	return out
}

// waitDNS waits until node answers qname with ip.
func (l *lab) waitDNS(name, qname, ip string) time.Duration {
	l.t.Helper()
	n := l.node(name)
	return l.waitFor(fmt.Sprintf("%s answers %s", name, qname), 30*time.Second, func() bool {
		a, err := query(n.ip, qname)
		return err == nil && slices.Contains(a, ip)
	})
}

// --- DNS ---

func query(ip, qname string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	c := &dns.Client{Timeout: probeTimeout}
	r, _, err := c.Exchange(m, net.JoinHostPort(ip, "53"))
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	var out []string
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out, nil
}

func lookup(ip, qname string) error {
	a, err := query(ip, qname)
	if err == nil && len(a) == 0 {
		err = fmt.Errorf("no answer")
	}
	return err
}

// prober queries every node that is up, nonstop, and keeps every result.
type prober struct {
	l    *lab
	mu   sync.Mutex
	runs map[string]bool
	obs  []observation
	quit chan struct{}
	wg   sync.WaitGroup
}

type observation struct {
	node    string
	at      time.Time
	ok      bool
	latency time.Duration
	err     string
}

func newProber(l *lab) *prober {
	return &prober{l: l, runs: map[string]bool{}, quit: make(chan struct{})}
}

// watch starts probing a node; it is probed whenever the test expects it
// to be up.
func (p *prober) watch(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runs[name] {
		return
	}
	p.runs[name] = true
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		tk := time.NewTicker(probeEvery)
		defer tk.Stop()
		for {
			select {
			case <-p.quit:
				return
			case <-tk.C:
			}
			p.l.mu.Lock()
			n := p.l.nodes[name]
			ip, up := n.ip, n.up
			p.l.mu.Unlock()
			if !up {
				continue
			}
			start := time.Now()
			a, err := query(ip, probeName)
			o := observation{node: name, at: start, latency: time.Since(start), ok: err == nil && slices.Contains(a, probeIP)}
			if err != nil {
				o.err = err.Error()
			} else if !o.ok {
				o.err = fmt.Sprintf("wrong answer %v", a)
			}
			// A node marked down while this query ran doesn't count.
			p.l.mu.Lock()
			still := p.l.nodes[name].up
			p.l.mu.Unlock()
			if !still {
				continue
			}
			p.mu.Lock()
			p.obs = append(p.obs, o)
			p.mu.Unlock()
		}
	}()
}

func (p *prober) stop() {
	select {
	case <-p.quit:
	default:
		close(p.quit)
	}
	p.wg.Wait()
}

type dnsStats struct {
	Sent, Failed int
	P50, P99     time.Duration
	Max          time.Duration
	Errors       []string
}

func (p *prober) stats(from, to time.Time) dnsStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	var s dnsStats
	var lat []time.Duration
	for _, o := range p.obs {
		if o.at.Before(from) || o.at.After(to) {
			continue
		}
		s.Sent++
		if !o.ok {
			s.Failed++
			if len(s.Errors) < 5 {
				s.Errors = append(s.Errors, o.node+": "+o.err)
			}
			continue
		}
		lat = append(lat, o.latency)
	}
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		s.P50 = lat[len(lat)/2]
		s.P99 = lat[len(lat)*99/100]
		s.Max = lat[len(lat)-1]
	}
	return s
}

// --- scenarios and the report ---

type result struct {
	Test, Scenario string
	DNS            dnsStats
	Notes          []string
}

// scenario runs fn as a subtest and records the DNS seen by devices while
// it ran, failing it if any query to a node that should be up went
// unanswered.
func (l *lab) scenario(name string, fn func(r *result)) {
	l.t.Helper()
	l.t.Run(name, func(t *testing.T) {
		outer := l.t
		l.t = t
		defer func() { l.t = outer }()
		r := result{Test: outer.Name(), Scenario: name}
		start := time.Now()
		fn(&r)
		// Let the probe see the end state for a moment.
		time.Sleep(500 * time.Millisecond)
		r.DNS = l.probe.stats(start, time.Now())
		l.results = append(l.results, r)
		t.Logf("DNS while this ran: %d queries, %d unanswered, p50 %s, p99 %s, max %s; %s",
			r.DNS.Sent, r.DNS.Failed, r.DNS.P50.Round(10*time.Microsecond), r.DNS.P99.Round(10*time.Microsecond), r.DNS.Max.Round(10*time.Microsecond), strings.Join(r.Notes, "; "))
		if r.DNS.Failed > 0 {
			t.Errorf("%d DNS queries to nodes that were up went unanswered: %v", r.DNS.Failed, r.DNS.Errors)
		}
	})
}

func (r *result) note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

func (l *lab) writeReport() {
	path := os.Getenv("FAILOVER_REPORT")
	if path == "" || len(l.results) == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		l.t.Logf("report: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n### %s\n\n| Scenario | DNS queries | Unanswered | p50 | p99 | Slowest | What happened |\n|---|---:|---:|---:|---:|---:|---|\n", l.results[0].Test)
	ms := func(d time.Duration) string { return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond)) }
	for _, r := range l.results {
		fmt.Fprintf(f, "| %s | %d | %d | %s | %s | %s | %s |\n", r.Scenario, r.DNS.Sent, r.DNS.Failed, ms(r.DNS.P50), ms(r.DNS.P99), ms(r.DNS.Max), strings.Join(r.Notes, "; "))
	}
}
