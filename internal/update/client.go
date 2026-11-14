package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Client is DNServ's side of the updater socket.
type Client struct {
	Path string
	hc   *http.Client
}

// ErrNoUpdater means no updater is set up next to this container.
var ErrNoUpdater = errors.New("no updater is set up on this server")

// NewClient talks to the updater at path.
func NewClient(path string) *Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &Client{Path: path, hc: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	if c == nil {
		return ErrNoUpdater
	}
	if _, err := os.Stat(c.Path); err != nil {
		return ErrNoUpdater
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://updater"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("the updater isn't answering: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("the updater answered HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

// Status asks the updater about this container.
func (c *Client) Status(ctx context.Context) (*SidecarStatus, error) {
	var st SidecarStatus
	if err := c.call(ctx, http.MethodGet, "/v1/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Start asks the updater to update this container (to rev, an earlier
// published version, when set). When it works, this process is stopped
// shortly after.
func (c *Client) Start(ctx context.Context, rev string) (*Job, error) {
	var j Job
	if err := c.call(ctx, http.MethodPost, "/v1/update", map[string]string{"revision": rev}, &j); err != nil {
		return nil, err
	}
	return &j, nil
}
