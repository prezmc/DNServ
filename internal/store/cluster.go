package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ClusterState is the replicated part of the cluster's own setup. Raft's
// configuration says who votes right now; this says who should be in the
// cluster and how the owner wants it run, and the leader moves Raft
// towards it.
type ClusterState struct {
	ID string `json:"id,omitempty"`
	// CACert and CAKey (PEM) sign node certificates. Every node holds the
	// key, so any node can let a new one join.
	CACert string           `json:"ca_cert,omitempty"`
	CAKey  string           `json:"ca_key,omitempty"`
	Nodes  map[string]*Node `json:"nodes"`
	// Preferred is the node that should lead whenever it is healthy.
	Preferred string               `json:"preferred,omitempty"`
	JoinCodes map[string]*JoinCode `json:"join_codes,omitempty"`
}

// Node is a member of the cluster.
type Node struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Addr is the host:port of the node's cluster listener.
	Addr string `json:"addr"`
	// NeverLeader keeps a full copy of the settings but never votes or
	// leads (a Raft non-voter).
	NeverLeader bool      `json:"never_leader,omitempty"`
	JoinedAt    time.Time `json:"joined_at"`
}

// JoinCode lets one new node join. Only a hash of its secret is kept.
type JoinCode struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
}

// Cluster command ops and their data.
const (
	OpClusterInit      = "cluster.init"      // ClusterInit
	OpClusterNode      = "cluster.node"      // Node (adds or updates)
	OpClusterRemove    = "cluster.remove"    // IDOnly
	OpClusterPreferred = "cluster.preferred" // IDOnly ("" clears)
	OpJoinCodeCreate   = "cluster.join_code" // JoinCode
	OpClusterJoin      = "cluster.join"      // ClusterJoin
	OpClusterRecovered = "cluster.recovered" // ClusterRecovered
	opClusterPrefix    = "cluster."
)

// ClusterInit starts the cluster on its first node. Import carries the
// node's state from before clustering, so nodes that join later get it
// through the log.
type ClusterInit struct {
	ID     string `json:"id"`
	CACert string `json:"ca_cert"`
	CAKey  string `json:"ca_key"`
	Node   Node   `json:"node"`
	Import *State `json:"import,omitempty"`
}

// ClusterJoin uses a join code to add a node.
type ClusterJoin struct {
	CodeID string `json:"code_id"`
	Hash   string `json:"hash"`
	Node   Node   `json:"node"`
}

// ClusterRecovered records a forced single-node recovery and drops the
// nodes that were left behind.
type ClusterRecovered struct {
	NodeID  string   `json:"node_id"`
	Removed []string `json:"removed"`
}

// ErrBadJoinCode is returned for an unknown, used or expired join code.
var ErrBadJoinCode = errors.New("that join code isn't valid any more; make a new one on the other node")

// NodeName returns a node's display name, or its ID.
func (cs *ClusterState) NodeName(id string) string {
	if n := cs.Nodes[id]; n != nil && n.Name != "" {
		return n.Name
	}
	return id
}

func validNode(n *Node) error {
	n.Name = strings.TrimSpace(n.Name)
	if n.ID == "" {
		return errors.New("node id required")
	}
	if l := utf8.RuneCountInString(n.Name); l < 1 || l > 64 {
		return errors.New("a node needs a name of 1 to 64 characters")
	}
	if n.Addr == "" {
		return errors.New("node address required")
	}
	return nil
}

func applyCluster(st *State, c Command, dec func(any) error) (any, *AuditEntry, error) {
	cs := &st.Cluster
	switch c.Op {
	case OpClusterInit:
		var d ClusterInit
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if cs.ID != "" {
			return nil, nil, errors.New("the cluster is already set up")
		}
		if err := validNode(&d.Node); err != nil {
			return nil, nil, err
		}
		if d.Import != nil {
			imp := d.Import.clone()
			*st = *imp
			st.Version, st.RaftIndex = 0, 0
			cs = &st.Cluster
		}
		d.Node.JoinedAt = c.Time
		*cs = ClusterState{ID: d.ID, CACert: d.CACert, CAKey: d.CAKey,
			Nodes: map[string]*Node{d.Node.ID: &d.Node}, JoinCodes: map[string]*JoinCode{}}
		return nil, audit(fmt.Sprintf("started the cluster on %q", d.Node.Name), nil, nil), nil

	case OpClusterNode:
		var d Node
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if err := validNode(&d); err != nil {
			return nil, nil, err
		}
		old := cs.Nodes[d.ID]
		if old == nil {
			return nil, nil, ErrNotFound
		}
		for _, o := range cs.Nodes {
			if o.ID != d.ID && strings.EqualFold(o.Name, d.Name) {
				return nil, nil, fmt.Errorf("there is already a node called %q", o.Name)
			}
		}
		if d.NeverLeader && cs.Preferred == d.ID {
			return nil, nil, errors.New("this is the preferred leader; pick another preferred leader first")
		}
		if d.NeverLeader && !old.NeverLeader && voters(cs) <= 1 {
			return nil, nil, errors.New("at least one node must be able to lead")
		}
		d.JoinedAt = old.JoinedAt
		before := *old
		cs.Nodes[d.ID] = &d
		if before.Addr != d.Addr && before.Name == d.Name && before.NeverLeader == d.NeverLeader {
			return nil, nil, nil // address learned automatically: not worth an audit line
		}
		return nil, audit(fmt.Sprintf("updated node %q", d.Name), before, d), nil

	case OpClusterRemove:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		old := cs.Nodes[d.ID]
		if old == nil {
			return nil, nil, ErrNotFound
		}
		if len(cs.Nodes) == 1 {
			return nil, nil, errors.New("the last node can't be removed")
		}
		delete(cs.Nodes, d.ID)
		if voters(cs) == 0 {
			return nil, nil, errors.New("at least one remaining node must be able to lead")
		}
		if cs.Preferred == d.ID {
			cs.Preferred = ""
		}
		return nil, audit(fmt.Sprintf("removed node %q", old.Name), old, nil), nil

	case OpClusterPreferred:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if d.ID == "" {
			cs.Preferred = ""
			return nil, audit("cleared the preferred leader", nil, nil), nil
		}
		n := cs.Nodes[d.ID]
		if n == nil {
			return nil, nil, ErrNotFound
		}
		if n.NeverLeader {
			return nil, nil, fmt.Errorf("%q is set to never lead", n.Name)
		}
		cs.Preferred = d.ID
		return nil, audit(fmt.Sprintf("made %q the preferred leader", n.Name), nil, nil), nil

	case OpJoinCodeCreate:
		var d JoinCode
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if d.ID == "" || d.Hash == "" || !d.ExpiresAt.After(c.Time) {
			return nil, nil, errors.New("bad join code")
		}
		for id, jc := range cs.JoinCodes {
			if !jc.ExpiresAt.After(c.Time) {
				delete(cs.JoinCodes, id)
			}
		}
		d.CreatedBy = c.Actor
		cs.JoinCodes[d.ID] = &d
		return d.ID, audit("made a join code for a new node", nil, nil), nil

	case OpClusterJoin:
		var d ClusterJoin
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		jc := cs.JoinCodes[d.CodeID]
		if jc == nil || jc.Hash != d.Hash || !jc.ExpiresAt.After(c.Time) {
			return nil, nil, ErrBadJoinCode
		}
		if err := validNode(&d.Node); err != nil {
			return nil, nil, err
		}
		if cs.Nodes[d.Node.ID] != nil {
			return nil, nil, errors.New("a node with this id is already in the cluster")
		}
		base, name := d.Node.Name, d.Node.Name
		for i := 2; ; i++ {
			taken := false
			for _, o := range cs.Nodes {
				if strings.EqualFold(o.Name, name) {
					taken = true
				}
			}
			if !taken {
				break
			}
			name = fmt.Sprintf("%s-%d", base, i)
		}
		d.Node.Name, d.Node.JoinedAt = name, c.Time
		delete(cs.JoinCodes, d.CodeID)
		cs.Nodes[d.Node.ID] = &d.Node
		return name, audit(fmt.Sprintf("node %q joined the cluster", name), nil, d.Node), nil

	case OpClusterRecovered:
		var d ClusterRecovered
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		n := cs.Nodes[d.NodeID]
		if n == nil {
			return nil, nil, ErrNotFound
		}
		var names []string
		for _, id := range d.Removed {
			if id == d.NodeID || cs.Nodes[id] == nil {
				continue
			}
			names = append(names, fmt.Sprintf("%q", cs.Nodes[id].Name))
			delete(cs.Nodes, id)
		}
		if cs.Nodes[cs.Preferred] == nil {
			cs.Preferred = ""
		}
		n.NeverLeader = false
		return nil, audit(fmt.Sprintf("forced recovery on %q; removed %s", n.Name, strings.Join(names, ", ")), nil, nil), nil
	}
	return nil, nil, fmt.Errorf("unknown command %q", c.Op)
}

func voters(cs *ClusterState) int {
	n := 0
	for _, x := range cs.Nodes {
		if !x.NeverLeader {
			n++
		}
	}
	return n
}
