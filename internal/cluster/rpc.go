package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/raft"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/store"
)

// errRetry means the leader moved or couldn't be reached; try again.
var errRetry = errors.New("retry")

// Error codes carried over RPC so callers can tell errors apart.
const (
	codeNotFound    = "not_found"
	codeLastAdmin   = "last_admin"
	codeBadJoin     = "bad_join_code"
	codeNotLeader   = "not_leader"
	codeUnavailable = "unavailable"
)

func errCode(err error) string {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return codeNotFound
	case errors.Is(err, store.ErrLastAdmin):
		return codeLastAdmin
	case errors.Is(err, store.ErrBadJoinCode):
		return codeBadJoin
	case errors.Is(err, store.ErrUnavailable):
		return codeUnavailable
	}
	return ""
}

func codeErr(code, msg string) error {
	switch code {
	case codeNotFound:
		return store.ErrNotFound
	case codeLastAdmin:
		return store.ErrLastAdmin
	case codeBadJoin:
		return store.ErrBadJoinCode
	case codeUnavailable:
		return store.ErrUnavailable
	case codeNotLeader:
		return errRetry
	}
	return errors.New(msg)
}

type rpcReply struct {
	Result any    `json:"result,omitempty"`
	Index  uint64 `json:"index,omitempty"`
	Error  string `json:"error,omitempty"`
	Code   string `json:"code,omitempty"`
}

func (c *Cluster) newClient(cr *creds) *http.Client {
	conf := cr.clientConfig(alpnRPC)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: conf}
				return d.DialContext(ctx, network, addr)
			},
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     time.Minute,
		},
	}
}

// call posts to a peer's RPC endpoint.
func (c *Cluster) call(ctx context.Context, addr, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Load().Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errRetry, err)
	}
	defer resp.Body.Close()
	var rep rpcReply
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		if json.Unmarshal(body, &rep) == nil && (rep.Error != "" || rep.Code != "") {
			return codeErr(rep.Code, rep.Error)
		}
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func (c *Cluster) forwardApply(leader string, data []byte) (any, uint64, error) {
	addr := c.addrOf(leader)
	if addr == "" {
		return nil, 0, errRetry
	}
	var rep rpcReply
	ctx, cancel := context.WithTimeout(c.ctx, 8*time.Second)
	defer cancel()
	if err := c.call(ctx, addr, "/rpc/apply", json.RawMessage(data), &rep); err != nil {
		return nil, 0, err
	}
	if rep.Error != "" || rep.Code != "" {
		return nil, rep.Index, codeErr(rep.Code, rep.Error)
	}
	return rep.Result, rep.Index, nil
}

// NodeStatus is one node's own view, for the dashboard.
type NodeStatus struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	State         string `json:"state"` // Leader, Follower, Candidate, Shutdown
	LeaderID      string `json:"leader_id"`
	AppliedIndex  uint64 `json:"applied_index"`
	LastIndex     uint64 `json:"last_index"`
	Term          uint64 `json:"term"`
	LastContactMS int64  `json:"last_contact_ms"` // follower: since the leader was last heard
	ClusterID     string `json:"cluster_id"`
	Member        bool   `json:"member"` // this node is in its own Raft configuration
}

// LocalStatus is this node's Raft view.
func (c *Cluster) LocalStatus() NodeStatus {
	c.mu.Lock()
	id, r := c.id, c.r
	c.mu.Unlock()
	ns := NodeStatus{ID: id.ID, Name: id.Name, Version: c.opt.Version, State: "Shutdown", ClusterID: c.st.State().Cluster.ID}
	if r == nil {
		return ns
	}
	ns.State = r.State().String()
	_, lid := r.LeaderWithID()
	ns.LeaderID = string(lid)
	ns.AppliedIndex = r.AppliedIndex()
	ns.LastIndex = r.LastIndex()
	if lc := r.LastContact(); !lc.IsZero() {
		ns.LastContactMS = time.Since(lc).Milliseconds()
	} else {
		ns.LastContactMS = -1
	}
	if f := r.GetConfiguration(); f.Error() == nil {
		for _, s := range f.Configuration().Servers {
			if string(s.ID) == id.ID {
				ns.Member = true
			}
		}
	}
	var term uint64
	fmt.Sscan(r.Stats()["term"], &term)
	ns.Term = term
	return ns
}

func (c *Cluster) peerStatus(ctx context.Context, id string, timeout time.Duration) (NodeStatus, error) {
	var ns NodeStatus
	addr := c.addrOf(id)
	if addr == "" {
		return ns, errors.New("no address")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := c.call(ctx, addr, "/rpc/status", struct{}{}, &ns)
	return ns, err
}

// --- server side ---

func (c *Cluster) rpcHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /rpc/apply", c.member(c.rpcApply))
	m.HandleFunc("POST /rpc/status", c.member(func(w http.ResponseWriter, r *http.Request) { reply(w, http.StatusOK, c.LocalStatus()) }))
	m.HandleFunc("POST /rpc/transfer", c.member(c.rpcTransfer))
	m.HandleFunc("POST /rpc/join", c.rpcJoin)
	return m
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func replyErr(w http.ResponseWriter, err error) {
	reply(w, http.StatusConflict, rpcReply{Error: err.Error(), Code: errCode(err)})
}

// member requires a client certificate from the cluster CA belonging to a
// current member.
func (c *Cluster) member(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id := peerID(r); id == "" || !c.isMember(id) {
			reply(w, http.StatusForbidden, rpcReply{Error: "not a member of this cluster"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		h(w, r)
	}
}

func (c *Cluster) rpcApply(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		replyErr(w, err)
		return
	}
	rf := c.raft()
	if rf == nil || rf.State() != raft.Leader {
		reply(w, http.StatusConflict, rpcReply{Code: codeNotLeader, Error: "not the leader"})
		return
	}
	f := rf.Apply(data, 5*time.Second)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			reply(w, http.StatusConflict, rpcReply{Code: codeNotLeader, Error: "not the leader"})
			return
		}
		replyErr(w, fmt.Errorf("%w (%v)", store.ErrUnavailable, err))
		return
	}
	ar, _ := f.Response().(applyResult)
	rep := rpcReply{Result: ar.res, Index: f.Index()}
	if ar.err != nil {
		rep.Error, rep.Code = ar.err.Error(), errCode(ar.err)
	}
	reply(w, http.StatusOK, rep)
}

type transferReq struct {
	To string `json:"to"`
}

func (c *Cluster) rpcTransfer(w http.ResponseWriter, r *http.Request) {
	var req transferReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		replyErr(w, err)
		return
	}
	if err := c.transferLocal(req.To); err != nil {
		replyErr(w, err)
		return
	}
	reply(w, http.StatusOK, rpcReply{})
}

// --- joining ---

type joinReq struct {
	CodeID    string     `json:"code_id"`
	Secret    string     `json:"secret"`
	Node      store.Node `json:"node"`
	PublicKey string     `json:"public_key"`
}

type joinReply struct {
	Cert      string `json:"cert"`
	CA        string `json:"ca"`
	ClusterID string `json:"cluster_id"`
	Name      string `json:"name"`
}

// rpcJoin admits a new node that holds a valid join code. It needs no
// client certificate: the code is the credential, and it is used up.
func (c *Cluster) rpcJoin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req joinReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		replyErr(w, err)
		return
	}
	pub, err := parsePublicKey(req.PublicKey)
	if err != nil {
		replyErr(w, err)
		return
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		replyErr(w, errors.New("unsupported key"))
		return
	}
	st := c.st.State()
	if st.Cluster.CAKey == "" {
		replyErr(w, store.ErrUnavailable)
		return
	}
	res, err := c.st.Apply(store.NewCommand(store.OpClusterJoin, "system", store.ClusterJoin{
		CodeID: req.CodeID, Hash: auth.HashToken(req.Secret), Node: req.Node,
	}))
	if err != nil {
		replyErr(w, err)
		return
	}
	cs := c.st.State().Cluster
	cert, err := issue(cs.CACert, cs.CAKey, req.Node.ID, pub)
	if err != nil {
		replyErr(w, err)
		return
	}
	name, _ := res.(string)
	c.poke()
	reply(w, http.StatusOK, joinReply{Cert: cert, CA: cs.CACert, ClusterID: cs.ID, Name: name})
}

func keyPEM(k *ecdsa.PrivateKey) string {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pemString("PRIVATE KEY", b)
}

func publicPEM(k *ecdsa.PrivateKey) string {
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return pemString("PUBLIC KEY", b)
}
