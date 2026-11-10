package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"
)

// ErrNoFullLeader means there is no leader to ask, or it is this node or
// a witness (which keeps no files): the caller should do the work itself.
var ErrNoFullLeader = errors.New("no other full node is leading")

// FileSource finds a file this node serves to the others, by name (a
// SHA-256 for blocklists).
type FileSource func(name string) (path string, ok bool)

var fileName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ServeFiles makes files from src available to other members.
func (c *Cluster) ServeFiles(src FileSource) { c.files.Store(&src) }

func (c *Cluster) rpcFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	src := c.files.Load()
	if src == nil || !fileName.MatchString(name) {
		reply(w, http.StatusNotFound, rpcReply{Error: "no such file"})
		return
	}
	path, ok := (*src)(name)
	if !ok {
		reply(w, http.StatusNotFound, rpcReply{Error: "no such file"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		reply(w, http.StatusNotFound, rpcReply{Error: "no such file"})
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// fullLeader returns the leader's ID when it is another node that isn't a
// witness.
func (c *Cluster) fullLeader() (string, error) {
	id := c.leaderID()
	if id == "" || id == c.ID() {
		return "", ErrNoFullLeader
	}
	if n := c.st.State().Cluster.Nodes[id]; n == nil || n.Witness {
		return "", ErrNoFullLeader
	}
	return id, nil
}

// AskLeader calls a member-only RPC (see Handle) on the leader. It
// returns ErrNoFullLeader when this node leads, or the leader is a
// witness or unknown.
func (c *Cluster) AskLeader(ctx context.Context, name string, in any) (json.RawMessage, error) {
	id, err := c.fullLeader()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return c.askPeer(ctx, id, name, b)
}

// FetchFromLeader copies a file the leader serves (see ServeFiles) to w.
func (c *Cluster) FetchFromLeader(ctx context.Context, name string, w io.Writer) error {
	id, err := c.fullLeader()
	if err != nil {
		return err
	}
	addr := c.addrOf(id)
	if addr == "" {
		return errors.New("no address known for the leader")
	}
	conf := c.creds.Load().clientConfig(alpnRPC)
	// No overall timeout: a big list over a slow link takes a while. ctx
	// bounds it.
	cl := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: conf}
			return d.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/rpc/file/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var rep rpcReply
		if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rep) == nil && rep.Error != "" {
			return errors.New(rep.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}
