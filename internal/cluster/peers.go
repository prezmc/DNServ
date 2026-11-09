package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// PeerHandler answers a request from another member of the cluster. The
// caller has already checked the user's permissions; the peer trusts it
// because it holds a member certificate.
type PeerHandler func(ctx context.Context, body json.RawMessage) (any, error)

// Handle adds a member-only RPC that peers reach with AskPeers.
func (c *Cluster) Handle(name string, h PeerHandler) { c.handlers.Store(name, h) }

func (c *Cluster) rpcExtra(w http.ResponseWriter, r *http.Request) {
	v, ok := c.handlers.Load(r.PathValue("name"))
	if !ok {
		reply(w, http.StatusNotFound, rpcReply{Error: "this node doesn't support " + r.PathValue("name") + " (update it)"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		replyErr(w, err)
		return
	}
	out, err := v.(PeerHandler)(r.Context(), body)
	if err != nil {
		replyErr(w, err)
		return
	}
	reply(w, http.StatusOK, out)
}

// PeerReply is one peer's answer to AskPeers.
type PeerReply struct {
	ID   string
	Name string
	Body json.RawMessage
	Err  error
}

// maxPeerReply bounds a peer's answer (a long query-log export).
const maxPeerReply = 64 << 20

// AskPeers sends in to the named RPC on every other full node (witnesses
// keep no data) at once and returns their answers, by name. A peer that
// is down or slower than ctx allows has Err set.
func (c *Cluster) AskPeers(ctx context.Context, name string, in any) []PeerReply {
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	self := c.ID()
	var out []PeerReply
	for id, n := range c.st.State().Cluster.Nodes {
		if id != self && !n.Witness {
			out = append(out, PeerReply{ID: id, Name: n.Name})
		}
	}
	slices.SortFunc(out, func(a, b PeerReply) int { return strings.Compare(a.Name, b.Name) })
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].Body, out[i].Err = c.askPeer(ctx, out[i].ID, name, b)
		}()
	}
	wg.Wait()
	return out
}

func (c *Cluster) askPeer(ctx context.Context, id, name string, body []byte) (json.RawMessage, error) {
	addr := c.addrOf(id)
	if addr == "" {
		return nil, errors.New("no address known")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/rpc/x/"+name, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Load().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("didn't answer in time")
		}
		return nil, errors.New("can't be reached")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerReply))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var rep rpcReply
		if json.Unmarshal(data, &rep) == nil && rep.Error != "" {
			return nil, errors.New(rep.Error)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return data, nil
}
