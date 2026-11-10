// Package adguard reads a running AdGuard Home's settings through its HTTP
// API and works out how they map onto DNServe, so people can move across
// without retyping their lists, rules, local names and devices.
//
// Nothing here touches DNS answers: it runs only when an admin asks for an
// import.
package adguard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Snapshot is what DNServe read from AdGuard Home.
type Snapshot struct {
	Source  string `json:"source"` // base URL
	Version string `json:"version"`

	FilteringEnabled bool     `json:"filtering_enabled"`
	Filters          []Filter `json:"filters"`
	Whitelist        []Filter `json:"whitelist_filters"`
	UserRules        []string `json:"user_rules"`

	Rewrites []Rewrite `json:"rewrites"`
	DNS      DNSInfo   `json:"dns"`
	Clients  []Client  `json:"clients"`
	// AutoClients counts devices AdGuard Home named by itself (rDNS, ARP,
	// hosts files).
	AutoClients int    `json:"auto_clients"`
	Access      Access `json:"access"`

	// BlockedServices are the services blocked for everyone.
	BlockedServices []string `json:"blocked_services"`
	// ServicesSchedule is true when the global blocked services have a
	// schedule.
	ServicesSchedule bool `json:"services_schedule"`
	// Services describes every service AdGuard Home knows, by id.
	Services map[string]Service `json:"services"`

	DHCPEnabled  bool    `json:"dhcp_enabled"`
	StaticLeases []Lease `json:"static_leases"`

	SafeBrowsing bool `json:"safe_browsing"`
	Parental     bool `json:"parental"`
	SafeSearch   bool `json:"safe_search"`

	// Missing lists parts AdGuard Home didn't answer (older versions lack
	// some endpoints).
	Missing []string `json:"missing,omitempty"`
}

// Filter is one blocklist or allowlist.
type Filter struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// Rewrite is a DNS rewrite.
type Rewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"` // newer versions only
}

// DNSInfo is the part of /control/dns_info DNServe can use.
type DNSInfo struct {
	Upstreams         []string `json:"upstream_dns"`
	UpstreamsFile     string   `json:"upstream_dns_file"`
	LocalPTR          []string `json:"local_ptr_upstreams"`
	UsePrivatePTR     bool     `json:"use_private_ptr_resolvers"`
	BlockingMode      string   `json:"blocking_mode"`
	ProtectionEnabled bool     `json:"protection_enabled"`
	RateLimit         int      `json:"ratelimit"`
	DNSSEC            bool     `json:"dnssec_enabled"`
}

// Client is a persistent client (a named device).
type Client struct {
	Name              string   `json:"name"`
	IDs               []string `json:"ids"`
	UseGlobalSettings bool     `json:"use_global_settings"`
	FilteringEnabled  bool     `json:"filtering_enabled"`
	ParentalEnabled   bool     `json:"parental_enabled"`
	SafeBrowsing      bool     `json:"safebrowsing_enabled"`
	SafeSearchOld     bool     `json:"safesearch_enabled"`
	SafeSearch        *struct {
		Enabled bool `json:"enabled"`
	} `json:"safe_search,omitempty"`
	UseGlobalServices bool            `json:"use_global_blocked_services"`
	BlockedServices   []string        `json:"blocked_services"`
	Schedule          json.RawMessage `json:"blocked_services_schedule,omitempty"`
	Upstreams         []string        `json:"upstreams"`
}

// Service is a blockable service such as YouTube.
type Service struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

// Access is the access settings.
type Access struct {
	Allowed      []string `json:"allowed_clients"`
	Disallowed   []string `json:"disallowed_clients"`
	BlockedHosts []string `json:"blocked_hosts"`
}

// Lease is a DHCP static lease.
type Lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Conn says how to reach AdGuard Home.
type Conn struct {
	URL      string
	Username string
	Password string
	// Insecure accepts a self-signed HTTPS certificate.
	Insecure bool
}

// ErrAuth means AdGuard Home refused the username or password.
var ErrAuth = errors.New("AdGuard Home didn't accept that username and password")

// maxBody bounds each response (the service list carries icons).
const maxBody = 16 << 20

// NormalizeURL turns "192.168.1.2:3000" into "http://192.168.1.2:3000".
func NormalizeURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("enter AdGuard Home's address, like http://192.168.1.2:3000")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%q isn't a web address like http://192.168.1.2:3000", s)
	}
	if u.User != nil {
		return "", errors.New("put the username and password in their own boxes, not in the address")
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/control")
	return u.String(), nil
}

// Fetch reads everything DNServe can import from AdGuard Home. Only the
// status call must work; parts that older versions lack are listed in
// Snapshot.Missing.
func Fetch(ctx context.Context, c Conn) (*Snapshot, error) {
	base, err := NormalizeURL(c.URL)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // AdGuard Home is on the local network
	if c.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		// AdGuard Home redirects to its sign-in page when credentials
		// are missing; treat that as an auth failure, never follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	f := &fetcher{ctx: ctx, hc: hc, base: base, conn: c}
	s := &Snapshot{Source: base, Services: map[string]Service{}}

	var status struct {
		Version           string `json:"version"`
		ProtectionEnabled bool   `json:"protection_enabled"`
	}
	if err := f.get("/control/status", &status); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("%s doesn't look like AdGuard Home (no /control/status)", base)
		}
		return nil, err
	}
	s.Version = status.Version

	var fs struct {
		Enabled   bool     `json:"enabled"`
		Filters   []Filter `json:"filters"`
		Whitelist []Filter `json:"whitelist_filters"`
		UserRules []string `json:"user_rules"`
	}
	opt := func(name, path string, v any) bool {
		if err := f.get(path, v); err != nil {
			if errors.Is(err, ErrAuth) {
				f.authErr = err
			}
			s.Missing = append(s.Missing, name)
			return false
		}
		return true
	}
	if opt("blocklists and custom rules", "/control/filtering/status", &fs) {
		s.FilteringEnabled, s.Filters, s.Whitelist, s.UserRules = fs.Enabled, fs.Filters, fs.Whitelist, fs.UserRules
	}
	opt("DNS rewrites", "/control/rewrite/list", &s.Rewrites)
	opt("DNS settings", "/control/dns_info", &s.DNS)

	var cl struct {
		Clients     []Client          `json:"clients"`
		AutoClients []json.RawMessage `json:"auto_clients"`
	}
	if opt("clients", "/control/clients", &cl) {
		s.Clients, s.AutoClients = cl.Clients, len(cl.AutoClients)
	}
	opt("access settings", "/control/access/list", &s.Access)

	// Blocked services moved from /list (ids) to /get (ids + schedule).
	var bs struct {
		IDs      []string                   `json:"ids"`
		Schedule map[string]json.RawMessage `json:"schedule"`
	}
	if err := f.get("/control/blocked_services/get", &bs); err == nil {
		s.BlockedServices = bs.IDs
		for k := range bs.Schedule {
			if k != "time_zone" {
				s.ServicesSchedule = true
			}
		}
	} else {
		opt("blocked services", "/control/blocked_services/list", &s.BlockedServices)
	}
	var all struct {
		Services []struct {
			ID    string   `json:"id"`
			Name  string   `json:"name"`
			Rules []string `json:"rules"`
		} `json:"blocked_services"`
	}
	if opt("blocked service definitions", "/control/blocked_services/all", &all) {
		for _, sv := range all.Services {
			s.Services[sv.ID] = Service{Name: sv.Name, Rules: sv.Rules}
		}
	}

	var dhcp struct {
		Enabled      bool    `json:"enabled"`
		StaticLeases []Lease `json:"static_leases"`
	}
	if opt("DHCP", "/control/dhcp/status", &dhcp) {
		s.DHCPEnabled, s.StaticLeases = dhcp.Enabled, dhcp.StaticLeases
	}
	var on struct {
		Enabled bool `json:"enabled"`
	}
	if opt("safe browsing", "/control/safebrowsing/status", &on) {
		s.SafeBrowsing = on.Enabled
	}
	on.Enabled = false
	if opt("parental control", "/control/parental/status", &on) {
		s.Parental = on.Enabled
	}
	on.Enabled = false
	if opt("safe search", "/control/safesearch/status", &on) {
		s.SafeSearch = on.Enabled
	}
	if f.authErr != nil && len(s.Filters) == 0 && len(s.UserRules) == 0 {
		return nil, f.authErr
	}
	return s, nil
}

var errNotFound = errors.New("not found")

type fetcher struct {
	ctx     context.Context
	hc      *http.Client
	base    string
	conn    Conn
	authErr error
}

func (f *fetcher) get(path string, v any) error {
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		return err
	}
	if f.conn.Username != "" || f.conn.Password != "" {
		req.SetBasicAuth(f.conn.Username, f.conn.Password)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			return fmt.Errorf("AdGuard Home at %s didn't answer in time", f.base)
		}
		return fmt.Errorf("couldn't reach AdGuard Home at %s: %v", f.base, unwrapURL(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode >= 300 && resp.StatusCode < 400:
		return ErrAuth
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("AdGuard Home answered %s for %s", resp.Status, path)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if len(b) > maxBody {
		return fmt.Errorf("AdGuard Home's answer for %s is too large", path)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s doesn't look like AdGuard Home (%s isn't JSON)", f.base, path)
	}
	return nil
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
