// Package virustotal looks up a domain's VirusTotal report with the
// owner's own API key. It runs only when someone asks about a domain:
// nothing is sent from the DNS path, and results are cached for a day.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultBase is VirusTotal's API.
const DefaultBase = "https://www.virustotal.com/api/v3"

// The free VirusTotal API allows 4 lookups a minute.
const (
	perMinute = 4
	cacheFor  = 24 * time.Hour
	maxCache  = 2000
)

var (
	// ErrNoKey means no API key is set.
	ErrNoKey = errors.New("no VirusTotal API key is set")
	// ErrBusy means the per-minute limit was reached.
	ErrBusy = errors.New("VirusTotal allows 4 lookups a minute; try again shortly")
	// ErrBadKey means VirusTotal refused the key.
	ErrBadKey = errors.New("VirusTotal refused the API key")
)

// Report is the part of a domain report the dashboard shows.
type Report struct {
	Name       string            `json:"name"`
	Malicious  int               `json:"malicious"`
	Suspicious int               `json:"suspicious"`
	Harmless   int               `json:"harmless"`
	Undetected int               `json:"undetected"`
	Reputation int               `json:"reputation"`
	Categories map[string]string `json:"categories,omitempty"`
	Analyzed   time.Time         `json:"analyzed,omitzero"`
	Found      bool              `json:"found"` // VirusTotal knows the domain
	Link       string            `json:"link"`
	Checked    time.Time         `json:"checked"`
}

// Client looks up reports. It is safe for concurrent use.
type Client struct {
	Base string
	HTTP *http.Client
	Key  func() string
	Now  func() time.Time

	mu    sync.Mutex
	cache map[string]Report
	calls []time.Time
}

// New returns a client that reads the key from key.
func New(key func() string) *Client {
	return &Client{Base: DefaultBase, HTTP: &http.Client{Timeout: 15 * time.Second}, Key: key, Now: time.Now}
}

// Configured reports whether a key is set.
func (c *Client) Configured() bool { return c.Key() != "" }

// Lookup returns name's report, from the cache when it is under a day old.
func (c *Client) Lookup(ctx context.Context, name string) (Report, bool, error) {
	key := c.Key()
	if key == "" {
		return Report{}, false, ErrNoKey
	}
	now := c.Now()
	c.mu.Lock()
	if r, ok := c.cache[name]; ok && now.Sub(r.Checked) < cacheFor {
		c.mu.Unlock()
		return r, true, nil
	}
	recent := c.calls[:0]
	for _, t := range c.calls {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	c.calls = recent
	if len(c.calls) >= perMinute {
		c.mu.Unlock()
		return Report{}, false, ErrBusy
	}
	c.calls = append(c.calls, now)
	c.mu.Unlock()

	r, err := c.fetch(ctx, key, name)
	if err != nil {
		return Report{}, false, err
	}
	r.Checked = now
	c.mu.Lock()
	if c.cache == nil || len(c.cache) >= maxCache {
		c.cache = map[string]Report{}
	}
	c.cache[name] = r
	c.mu.Unlock()
	return r, false, nil
}

// Forget drops cached reports (after the key changes).
func (c *Client) Forget() {
	c.mu.Lock()
	c.cache = nil
	c.mu.Unlock()
}

func (c *Client) fetch(ctx context.Context, key, name string) (Report, error) {
	r := Report{Name: name, Link: "https://www.virustotal.com/gui/domain/" + url.PathEscape(name)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/domains/"+url.PathEscape(name), nil)
	if err != nil {
		return r, err
	}
	req.Header.Set("x-apikey", key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return r, fmt.Errorf("couldn't reach VirusTotal: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return r, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return r, ErrBadKey
	case http.StatusTooManyRequests:
		return r, errors.New("VirusTotal says this key is over its quota; try again later")
	default:
		return r, fmt.Errorf("VirusTotal answered HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Reputation   int               `json:"reputation"`
				Categories   map[string]string `json:"categories"`
				LastAnalysis int64             `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return r, fmt.Errorf("unexpected answer from VirusTotal: %w", err)
	}
	a := doc.Data.Attributes
	r.Found = true
	r.Malicious, r.Suspicious, r.Harmless, r.Undetected = a.Stats.Malicious, a.Stats.Suspicious, a.Stats.Harmless, a.Stats.Undetected
	r.Reputation, r.Categories = a.Reputation, a.Categories
	if a.LastAnalysis > 0 {
		r.Analyzed = time.Unix(a.LastAnalysis, 0).UTC()
	}
	return r, nil
}
