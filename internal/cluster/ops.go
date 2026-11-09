package cluster

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/store"
)

// JoinCodeTTL is how long a join code works.
const JoinCodeTTL = time.Hour

const joinPrefix = "DNSJ1-"

type joinCode struct {
	Addrs  []string `json:"a"`
	CAFP   string   `json:"f"`
	ID     string   `json:"i"`
	Secret string   `json:"s"`
}

func (j joinCode) String() string {
	b, _ := json.Marshal(j)
	return joinPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func parseJoinCode(s string) (joinCode, error) {
	var j joinCode
	s = strings.Join(strings.Fields(s), "") // tolerate line breaks from copy and paste
	raw, ok := strings.CutPrefix(s, joinPrefix)
	if !ok {
		return j, errors.New("that isn't a DNServe join code (it starts with " + joinPrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &j) != nil || len(j.Addrs) == 0 || j.CAFP == "" || j.ID == "" || j.Secret == "" {
		return j, errors.New("that join code is damaged; copy it again")
	}
	return j, nil
}

// CreateJoinCode makes a one-time code that lets one new node join within
// JoinCodeTTL. The code holds this cluster's addresses, its CA fingerprint
// and a secret; only the secret's hash is stored.
func (c *Cluster) CreateJoinCode(actor string) (string, time.Time, error) {
	secret := auth.RandomID(16)
	id := auth.RandomID(6)
	exp := time.Now().Add(JoinCodeTTL).UTC().Truncate(time.Second)
	if _, err := c.st.Apply(store.NewCommand(store.OpJoinCodeCreate, actor, store.JoinCode{ID: id, Hash: auth.HashToken(secret), ExpiresAt: exp})); err != nil {
		return "", time.Time{}, err
	}
	addrs := []string{c.advertise()}
	for _, n := range c.st.State().Cluster.Nodes {
		if n.Addr != "" && n.Addr != addrs[0] {
			addrs = append(addrs, n.Addr)
		}
	}
	return joinCode{Addrs: addrs, CAFP: c.creds.Load().caFP, ID: id, Secret: secret}.String(), exp, nil
}

// CanJoin says whether this node may join another cluster, which replaces
// its state. It may when it is alone, or cut off from its cluster.
func (c *Cluster) CanJoin() error {
	st := c.st.State()
	others := 0
	for id := range st.Cluster.Nodes {
		if id != c.ID() {
			others++
		}
	}
	if others == 0 {
		return nil
	}
	if c.leaderID() != "" {
		return errors.New("this node is already in a working cluster; remove it from that cluster first")
	}
	return nil
}

// Join makes this node a member of the cluster that issued code. Its own
// state is replaced by the cluster's. host is the address this node's
// dashboard was opened at, used as its cluster address unless the config
// sets one.
func (c *Cluster) Join(ctx context.Context, code, host string) (string, error) {
	jc, err := parseJoinCode(code)
	if err != nil {
		return "", err
	}
	if err := c.CanJoin(); err != nil {
		return "", err
	}
	c.LearnHost(host)
	key, err := newKey()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	node := store.Node{ID: c.id.ID, Name: c.id.Name, Addr: c.advertiseLocked()}
	c.mu.Unlock()
	req := joinReq{CodeID: jc.ID, Secret: jc.Secret, Node: node, PublicKey: publicPEM(key)}

	pinned := pinnedConfig(jc.CAFP)
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: pinned}
			return d.DialContext(ctx, network, addr)
		},
	}}
	var rep joinReply
	var lastErr error
	for _, addr := range jc.Addrs {
		lastErr = postJSON(ctx, cl, "https://"+addr+"/rpc/join", req, &rep)
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		var ne net.Error
		if errors.As(lastErr, &ne) || errors.Is(lastErr, errRetry) {
			return "", fmt.Errorf("couldn't reach the other node at %s (is port %s open between the servers?): %v", strings.Join(jc.Addrs, ", "), portOf(jc.Addrs[0]), lastErr)
		}
		return "", lastErr
	}
	cr, err := loadCreds(rep.Cert, keyPEM(key), rep.CA)
	if err != nil {
		return "", err
	}

	// Swap identities: stop Raft, drop the old log and state, and start
	// again as a member waiting for the leader to send the state.
	c.mu.Lock()
	if err := c.stopRaftLocked(); err != nil {
		c.log.Warn("stopping raft", "err", err)
	}
	c.mu.Unlock()
	if err := os.RemoveAll(c.raftDir()); err != nil {
		return "", err
	}
	if err := c.st.Replace(store.NewState()); err != nil {
		return "", err
	}
	c.mu.Lock()
	c.id.CertPEM, c.id.KeyPEM, c.id.CAPEM = rep.Cert, keyPEM(key), rep.CA
	c.id.ClusterID, c.id.Joined, c.id.PendingCAKey = rep.ClusterID, true, ""
	if rep.Name != "" {
		c.id.Name = rep.Name
	}
	name := c.id.Name
	err = c.saveIdentityLocked()
	c.mu.Unlock()
	if err != nil {
		return "", err
	}
	c.creds.Store(cr)
	c.client.Store(c.newClient(cr))
	if err := c.startRaft(nil); err != nil {
		return "", err
	}
	c.log.Info("joined the cluster; waiting for its settings", "cluster", rep.ClusterID, "name", name)
	return name, nil
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

func postJSON(ctx context.Context, cl *http.Client, url string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var rep rpcReply
		if json.NewDecoder(resp.Body).Decode(&rep) == nil && rep.Error != "" {
			return codeErr(rep.Code, rep.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// --- leadership ---

// TransferLeadership hands leadership to node to, or to any caught-up
// voter when to is empty.
func (c *Cluster) TransferLeadership(to string) error {
	if p := c.st.State().Cluster.Preferred; p != "" && p != to {
		return fmt.Errorf("%q is the preferred leader, so leadership would move back to it; change the preferred leader instead", c.st.State().Cluster.NodeName(p))
	}
	lid := c.leaderID()
	if lid == "" {
		return store.ErrUnavailable
	}
	if lid == c.ID() {
		return c.transferLocal(to)
	}
	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()
	return c.call(ctx, c.addrOf(lid), "/rpc/transfer", transferReq{To: to}, nil)
}

func (c *Cluster) transferLocal(to string) error {
	r := c.raft()
	if r == nil || r.State() != raft.Leader {
		return errors.New("this node isn't the leader any more; try again")
	}
	if to == c.ID() {
		return nil
	}
	var f raft.Future
	if to == "" {
		f = r.LeadershipTransfer()
	} else {
		n := c.st.State().Cluster.Nodes[to]
		if n == nil {
			return store.ErrNotFound
		}
		if n.NeverLeader {
			return fmt.Errorf("%q is set to never lead", n.Name)
		}
		f = r.LeadershipTransferToServer(raft.ServerID(to), raft.ServerAddress(c.addrOf(to)))
	}
	c.lastTransfer.Store(time.Now().UnixNano())
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrLeadershipTransferInProgress) {
			return nil
		}
		return fmt.Errorf("leadership transfer failed: %v (the other node must be up and caught up)", err)
	}
	return nil
}

// --- forced recovery ---

// RiskError says forced recovery could leave two clusters running: the
// nodes left out could still have a majority between them.
type RiskError struct{ Nodes []string }

func (e *RiskError) Error() string {
	return fmt.Sprintf("%s could still be running the cluster without this node. Only continue if they are switched off or broken for good", strings.Join(e.Nodes, " and "))
}

// ForceRecover makes this node a cluster of one, keeping its copy of the
// state, when the others are lost. It refuses while another member answers
// and, unless acceptRisk, when the members left out could still form a
// majority among themselves (two clusters must never run at once). Nodes
// left behind are cut off: this node refuses their connections, so they
// can't rejoin without a new join code.
func (c *Cluster) ForceRecover(ctx context.Context, actor string, acceptRisk bool) error {
	r := c.raft()
	if r == nil {
		return errors.New("raft isn't running")
	}
	f := r.GetConfiguration()
	if err := f.Error(); err != nil {
		return err
	}
	self := c.ID()
	st := c.st.State()
	var others []raft.Server
	voters, otherVoters := 0, 0
	for _, s := range f.Configuration().Servers {
		if s.Suffrage == raft.Voter {
			voters++
		}
		if string(s.ID) == self {
			continue
		}
		others = append(others, s)
		if s.Suffrage == raft.Voter {
			otherVoters++
		}
	}
	if len(others) == 0 && voters == 1 {
		return errors.New("this node is already the only member")
	}
	if c.leaderID() != "" {
		return errors.New("the cluster has a leader, so nothing needs recovering; remove the lost node instead")
	}
	// Anyone answering means the cluster isn't lost: refuse.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var up []string
	for _, s := range others {
		wg.Add(1)
		go func(s raft.Server) {
			defer wg.Done()
			if _, err := c.peerStatus(ctx, string(s.ID), 2*time.Second); err == nil {
				mu.Lock()
				up = append(up, st.Cluster.NodeName(string(s.ID)))
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	if len(up) > 0 {
		sort.Strings(up)
		return fmt.Errorf("%s still answers, so the cluster isn't lost; check the network between the nodes instead", strings.Join(up, " and "))
	}
	if otherVoters >= voters/2+1 && !acceptRisk {
		var names []string
		for _, s := range others {
			if s.Suffrage == raft.Voter {
				names = append(names, st.Cluster.NodeName(string(s.ID)))
			}
		}
		sort.Strings(names)
		return &RiskError{Nodes: names}
	}

	conf := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: raft.ServerID(self), Address: raft.ServerAddress(c.advertise())}}}
	c.log.Warn("forced recovery: this node becomes a cluster of one", "actor", actor)
	c.mu.Lock()
	err := c.stopRaftLocked()
	c.mu.Unlock()
	if err != nil {
		c.log.Warn("stopping raft", "err", err)
	}
	if err := c.startRaft(&conf); err != nil {
		// Try to come back as before so the node isn't left without Raft.
		if err2 := c.startRaft(nil); err2 != nil {
			c.log.Error("restarting raft after a failed recovery", "err", err2)
		}
		return err
	}
	// Wait to lead, then record what happened.
	deadline := time.Now().Add(15 * time.Second)
	for c.leaderID() != self {
		if time.Now().After(deadline) {
			return errors.New("recovered, but this node hasn't become leader yet; check the log")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var removed []string
	for _, s := range others {
		removed = append(removed, string(s.ID))
	}
	_, err = c.st.Apply(store.NewCommand(store.OpClusterRecovered, actor, store.ClusterRecovered{NodeID: self, Removed: removed}))
	c.poke()
	return err
}

// --- the whole cluster, for the dashboard ---

// MemberStatus is one node as the dashboard shows it.
type MemberStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	Self        bool   `json:"self"`
	Leader      bool   `json:"leader"`
	Voter       bool   `json:"voter"`
	NeverLeader bool   `json:"never_leader"`
	Preferred   bool   `json:"preferred"`
	// Role: leader, follower, joining (catching up before it votes),
	// standby (never leads), or adding (not in Raft yet).
	Role      string    `json:"role"`
	Reachable bool      `json:"reachable"`
	Version   string    `json:"version,omitempty"`
	Behind    uint64    `json:"behind"` // log entries behind this node
	JoinedAt  time.Time `json:"joined_at"`
}

// Status is the cluster as seen from this node.
type Status struct {
	ClusterID        string         `json:"cluster_id"`
	Self             string         `json:"self"`
	LeaderID         string         `json:"leader_id"`
	Healthy          bool           `json:"healthy"` // has a leader; changes work
	Voters           int            `json:"voters"`
	Nodes            []MemberStatus `json:"nodes"`
	Advertise        string         `json:"advertise"`
	AdvertiseLearned bool           `json:"advertise_learned"`
	// LeftOut means this node isn't in its own cluster's membership any
	// more (it was removed, or recovered around).
	LeftOut bool `json:"left_out"`
}

// Status gathers every node's view, asking peers in parallel.
func (c *Cluster) Status(ctx context.Context) Status {
	self := c.LocalStatus()
	st := c.st.State()
	out := Status{ClusterID: st.Cluster.ID, Self: self.ID, LeaderID: self.LeaderID, Healthy: self.LeaderID != "",
		Advertise: c.advertise(), AdvertiseLearned: c.AdvertiseLearned()}
	raftServers := map[string]raft.Server{}
	if r := c.raft(); r != nil {
		if f := r.GetConfiguration(); f.Error() == nil {
			for _, s := range f.Configuration().Servers {
				raftServers[string(s.ID)] = s
			}
		}
	}
	c.mu.Lock()
	joined, ownCluster := c.id.Joined, c.id.ClusterID
	c.mu.Unlock()
	out.LeftOut = len(raftServers) > 0 && !self.Member && joined
	if out.ClusterID == "" {
		out.ClusterID = ownCluster
	}
	ids := map[string]bool{}
	for id := range st.Cluster.Nodes {
		ids[id] = true
	}
	for id := range raftServers {
		ids[id] = true
	}
	ids[self.ID] = true

	var wg sync.WaitGroup
	var mu sync.Mutex
	for id := range ids {
		m := MemberStatus{ID: id, Name: st.Cluster.NodeName(id), Self: id == self.ID, Leader: id == self.LeaderID, Preferred: id == st.Cluster.Preferred}
		if n := st.Cluster.Nodes[id]; n != nil {
			m.Addr, m.NeverLeader, m.JoinedAt = n.Addr, n.NeverLeader, n.JoinedAt
		}
		if id == self.ID {
			m.Name = self.Name
		}
		s, inRaft := raftServers[id]
		if m.Addr == "" {
			m.Addr = string(s.Address)
		}
		m.Voter = inRaft && s.Suffrage == raft.Voter
		if m.Voter {
			out.Voters++
		}
		switch {
		case m.Leader:
			m.Role = "leader"
		case !inRaft:
			m.Role = "adding"
		case m.NeverLeader && !m.Voter:
			m.Role = "standby"
		case !m.Voter:
			m.Role = "joining"
		default:
			m.Role = "follower"
		}
		if m.Self {
			m.Reachable, m.Version = true, self.Version
			mu.Lock()
			out.Nodes = append(out.Nodes, m)
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(m MemberStatus) {
			defer wg.Done()
			if ps, err := c.peerStatus(ctx, m.ID, 1500*time.Millisecond); err == nil {
				m.Reachable, m.Version = true, ps.Version
				if self.AppliedIndex > ps.AppliedIndex {
					m.Behind = self.AppliedIndex - ps.AppliedIndex
				}
			}
			mu.Lock()
			out.Nodes = append(out.Nodes, m)
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	sort.Slice(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].JoinedAt.Equal(out.Nodes[j].JoinedAt) {
			return out.Nodes[i].Name < out.Nodes[j].Name
		}
		return out.Nodes[i].JoinedAt.Before(out.Nodes[j].JoinedAt)
	})
	return out
}
