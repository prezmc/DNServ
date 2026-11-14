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
	"net/url"
	"strings"
	"time"
)

// Docker is the small part of the Docker Engine API the updater uses,
// over the Unix socket, without the Docker SDK.
type Docker struct {
	hc *http.Client
}

// ErrNoSuchContainer is a 404 from the engine.
var ErrNoSuchContainer = errors.New("no such container")

// NewDocker talks to the engine at socket (usually
// /var/run/docker.sock).
func NewDocker(socket string) *Docker {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	return &Docker{hc: &http.Client{Transport: tr}}
}

func (d *Docker) do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNoSuchContainer
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil // already started / stopped
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return fmt.Errorf("docker: %s", e.Message)
		}
		return fmt.Errorf("docker: HTTP %d on %s %s", resp.StatusCode, method, path)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Container is the part of an inspect we read. Raw keeps the whole
// answer so a replacement copies every setting, including ones newer
// than this code.
type Container struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"` // image ID
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Restarting bool   `json:"Restarting"`
		ExitCode   int    `json:"ExitCode"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image       string            `json:"Image"` // the reference it was created from
		Labels      map[string]string `json:"Labels"`
		StopTimeout *int              `json:"StopTimeout"`
	} `json:"Config"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`

	Raw map[string]json.RawMessage `json:"-"`
}

// Inspect reads a container by ID, ID prefix or name.
func (d *Docker) Inspect(ctx context.Context, id string) (*Container, error) {
	var raw []byte
	if err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &raw); err != nil {
		return nil, err
	}
	var c Container
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c.Raw); err != nil {
		return nil, err
	}
	c.Name = strings.TrimPrefix(c.Name, "/")
	return &c, nil
}

// ContainersWithVolume lists the IDs of containers that mount a named
// volume.
func (d *Docker) ContainersWithVolume(ctx context.Context, volume string) ([]string, error) {
	f, _ := json.Marshal(map[string][]string{"volume": {volume}})
	var list []struct {
		ID string `json:"Id"`
	}
	if err := d.do(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(f)}}, nil, &list); err != nil {
		return nil, err
	}
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.ID
	}
	return out, nil
}

// Image is the part of an image inspect we read.
type Image struct {
	ID     string                     `json:"Id"`
	Config map[string]json.RawMessage `json:"Config"`
}

// Labels returns the image's labels.
func (im *Image) Labels() map[string]string {
	var l map[string]string
	_ = json.Unmarshal(im.Config["Labels"], &l)
	return l
}

// InspectImage reads an image by ID or reference.
func (d *Docker) InspectImage(ctx context.Context, ref string) (*Image, error) {
	var im Image
	if err := d.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, &im); err != nil {
		return nil, err
	}
	return &im, nil
}

// Pull fetches the newest image for ref's tag.
func (d *Docker) Pull(ctx context.Context, ref string) error {
	r, err := ParseRef(ref)
	if err != nil {
		return err
	}
	from := ref
	if i := strings.LastIndex(from, ":"); i > strings.LastIndex(from, "/") {
		from = from[:i]
	}
	u := "http://docker/images/create?" + url.Values{"fromImage": {from}, "tag": {r.Tag}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("docker pull: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// The pull streams progress as JSON objects; a failure partway is
	// one of them.
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("docker pull: %w", err)
		}
		if msg.Error != "" {
			return fmt.Errorf("docker pull: %s", msg.Error)
		}
	}
}

// Create makes a container and returns its ID.
func (d *Docker) Create(ctx context.Context, name string, body map[string]any) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	if err := d.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// Start starts a container.
func (d *Docker) Start(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil)
}

// Stop stops a container, giving it timeout to shut down cleanly.
func (d *Docker) Stop(ctx context.Context, id string, timeout time.Duration) error {
	return d.do(ctx, http.MethodPost, "/containers/"+id+"/stop", url.Values{"t": {fmt.Sprint(int(timeout.Seconds()))}}, nil, nil)
}

// Rename renames a container.
func (d *Docker) Rename(ctx context.Context, id, name string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+id+"/rename", url.Values{"name": {name}}, nil, nil)
}

// Remove deletes a container (it must be stopped).
func (d *Docker) Remove(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodDelete, "/containers/"+id, nil, nil, nil)
}

// RemoveImage deletes an image if nothing uses it (errors are ignored by
// callers: another container may still use it).
func (d *Docker) RemoveImage(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodDelete, "/images/"+id, nil, nil, nil)
}
