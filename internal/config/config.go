// Package config defines the node configuration and loads it from YAML.
//
// In later steps the same structure is replicated across the cluster with
// Raft; for now a node reads it from a local file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full node configuration.
type Config struct {
	DNS       DNSConfig       `yaml:"dns"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Cache     CacheConfig     `yaml:"cache"`
	Filtering FilteringConfig `yaml:"filtering"`
	HTTP      HTTPConfig      `yaml:"http"`
	Cluster   ClusterConfig   `yaml:"cluster"`
	DataDir   string          `yaml:"data_dir"`
	// TimeZone is an IANA name such as "Europe/London" used for group
	// schedules. Empty means the container's TZ, or UTC.
	TimeZone string `yaml:"time_zone"`
}

// DNSConfig controls the listeners that serve clients.
type DNSConfig struct {
	// Listen addresses, served on both UDP and TCP.
	Listen []string `yaml:"listen"`
	// AllowedNets restricts which client networks may query. Empty means
	// private ranges only (RFC 1918, RFC 4193, loopback, link-local).
	AllowedNets []string `yaml:"allowed_nets"`
	// UDPSize is the EDNS0 buffer size advertised to clients.
	UDPSize uint16 `yaml:"udp_size"`
	// RateLimit is the maximum queries per second per client IP (0 = off).
	RateLimit int `yaml:"rate_limit"`
	// TLS configures encrypted DNS for clients: DNS over TLS and DNS over
	// HTTPS.
	TLS TLSConfig `yaml:"tls"`
	// LocalDNS is the LAN router's DNS (for example "192.168.1.1"). When
	// set, local names (.lan, .home.arpa, single labels) and reverse
	// lookups of private addresses are forwarded to it, so device names
	// work. Empty answers them as not found.
	LocalDNS string `yaml:"local_dns"`
	// Records are local DNS records, answered before filtering and
	// before the router or upstream.
	Records []Record `yaml:"records"`
}

// TLSConfig serves DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484)
// to clients.
type TLSConfig struct {
	// DoTListen addresses for DNS over TLS (usually ":853"). Empty disables.
	DoTListen []string `yaml:"dot_listen"`
	// DoHListen addresses for DNS over HTTPS (usually ":443"). Empty disables.
	DoHListen []string `yaml:"doh_listen"`
	// DoHPath is the URL path for DoH queries.
	DoHPath string `yaml:"doh_path"`
	// CertFile and KeyFile are a PEM certificate and key. When both are
	// empty a self-signed certificate is generated in data_dir/tls.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Hostnames for the generated certificate.
	Hostnames []string `yaml:"hostnames"`
}

// UpstreamConfig selects how queries the node can't answer are resolved.
type UpstreamConfig struct {
	// Mode:
	//   "forward"   encrypted (or plain) forwarding to Servers.
	//   "recursive" resolve from the root servers with the bundled Unbound.
	//   "tunnel"    recursive, with outbound traffic over a VPN tunnel.
	Mode string `yaml:"mode"`
	// Servers, tried in order of measured latency, failing over on error.
	// Schemes: https:// (DoH), tls:// (DoT), udp://, tcp://.
	Servers []string `yaml:"servers"`
	// Bootstrap resolvers used only to look up the hostnames of DoH/DoT
	// servers. Must be IP addresses.
	Bootstrap []string      `yaml:"bootstrap"`
	Timeout   time.Duration `yaml:"timeout"`
	// Recursive configures the bundled Unbound (recursive and tunnel modes).
	Recursive RecursiveConfig `yaml:"recursive"`
	// Tunnel configures tunnel mode.
	Tunnel TunnelConfig `yaml:"tunnel"`
}

// RecursiveConfig tunes the bundled Unbound resolver.
type RecursiveConfig struct {
	// Binary is the path to the unbound executable.
	Binary string `yaml:"binary"`
	// Port is the loopback port Unbound listens on.
	Port int `yaml:"port"`
	// Threads is the number of Unbound worker threads (0 = 1).
	Threads int `yaml:"threads"`
	// CacheMB is Unbound's total cache size in megabytes (split between the
	// RRset and message caches).
	CacheMB int `yaml:"cache_mb"`
}

// TunnelConfig controls tunnel mode. The tunnel itself (WireGuard) is set up
// by a VPN container sharing DNServe's network, or by the host; DNServe
// checks it is up and refuses to leak queries when it is not.
type TunnelConfig struct {
	// Interface that must exist and be up, e.g. "wg0" or "tun0".
	Interface string `yaml:"interface"`
	// ExpectedEgress optionally lists the IPs or CIDRs your VPN exits from.
	// When set, the node checks the address authoritative servers see.
	ExpectedEgress []string `yaml:"expected_egress"`
	// CheckInterval is how often the tunnel is checked.
	CheckInterval time.Duration `yaml:"check_interval"`
	// OnDown: "forward" falls back to encrypted forwarding to Servers (the
	// ISP still sees nothing); "block" answers SERVFAIL until the tunnel is
	// back.
	OnDown string `yaml:"on_down"`
}

// CacheConfig tunes the in-memory answer cache.
type CacheConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxEntries bounds memory use.
	MaxEntries int `yaml:"max_entries"`
	// MinTTL and MaxTTL clamp record TTLs stored in the cache.
	MinTTL time.Duration `yaml:"min_ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`
	// NegativeTTL caps how long NXDOMAIN/NODATA answers are cached.
	NegativeTTL time.Duration `yaml:"negative_ttl"`
	// Prefetch refreshes popular entries shortly before they expire.
	Prefetch bool `yaml:"prefetch"`
	// ServeStale answers from expired entries for up to this long when
	// upstream is slow or failing (RFC 8767). 0 disables.
	ServeStale time.Duration `yaml:"serve_stale"`
	// Persist saves the cache to data_dir on shutdown and reloads it on start.
	Persist bool `yaml:"persist"`
}

// FilteringConfig controls blocking.
type FilteringConfig struct {
	Enabled bool `yaml:"enabled"`
	// BlockMode: "null_ip" (0.0.0.0 / ::), "nxdomain" or "refused".
	BlockMode string `yaml:"block_mode"`
	// BlockTTL is the TTL on blocked answers.
	BlockTTL time.Duration `yaml:"block_ttl"`
	// Lists are blocklists by URL or local file path.
	Lists []ListConfig `yaml:"lists"`
	// Allowlists are lists whose entries are never blocked.
	Allowlists []ListConfig `yaml:"allowlists"`
	// Rules are custom rules in AdBlock syntax, e.g. "||ads.example^",
	// "@@||good.example^", "*.tracker.example", or a plain domain.
	Rules []string `yaml:"rules"`
	// RefreshInterval is how often remote lists are re-downloaded.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// BlockBypass blocks well-known public DNS-over-HTTPS resolvers and
	// Apple's iCloud Private Relay, so devices can't quietly skip filtering.
	BlockBypass bool `yaml:"block_bypass"`
}

// ListConfig is one blocklist or allowlist.
type ListConfig struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

// HTTPConfig serves health checks and metrics.
type HTTPConfig struct {
	Listen string `yaml:"listen"`
}

// ClusterConfig is how nodes reach each other. Every node runs the cluster
// listener, even alone, so another node can join it at any time.
type ClusterConfig struct {
	// Listen is the address for node-to-node traffic (mutual TLS).
	Listen string `yaml:"listen"`
	// Advertise is the host:port other nodes use to reach this one. Empty
	// means learn it from the address the dashboard was opened at.
	Advertise string `yaml:"advertise"`
}

// Default returns a configuration that works out of the box: encrypted
// forwarding to Cloudflare over DNS over HTTPS, caching on, filtering on.
func Default() Config {
	return Config{
		DNS: DNSConfig{
			Listen:    []string{":53"},
			UDPSize:   1232,
			RateLimit: 0,
			TLS: TLSConfig{
				DoTListen: []string{":853"},
				DoHListen: []string{":443"},
				DoHPath:   "/dns-query",
				Hostnames: []string{"dnserve.local"},
			},
		},
		Upstream: UpstreamConfig{
			Mode:      "forward",
			Servers:   []string{"https://cloudflare-dns.com/dns-query", "tls://one.one.one.one"},
			Bootstrap: []string{"1.1.1.1:53", "1.0.0.1:53"},
			Timeout:   3 * time.Second,
			Recursive: RecursiveConfig{
				Binary:  "unbound",
				Port:    5335,
				Threads: 1,
				CacheMB: 128,
			},
			Tunnel: TunnelConfig{
				Interface:     "wg0",
				CheckInterval: 30 * time.Second,
				OnDown:        "forward",
			},
		},
		Cache: CacheConfig{
			Enabled:     true,
			MaxEntries:  100_000,
			MinTTL:      0,
			MaxTTL:      24 * time.Hour,
			NegativeTTL: 5 * time.Minute,
			Prefetch:    true,
			ServeStale:  time.Hour,
			Persist:     true,
		},
		Filtering: FilteringConfig{
			Enabled:         true,
			BlockMode:       "null_ip",
			BlockTTL:        10 * time.Second,
			RefreshInterval: 24 * time.Hour,
		},
		HTTP:    HTTPConfig{Listen: ":8080"},
		Cluster: ClusterConfig{Listen: ":8081"},
		DataDir: "/data",
	}
}

// Load reads a YAML file on top of the defaults. A missing file yields the
// defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, cfg.Validate()
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, cfg.Validate()
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// ApplyEnv overrides settings from DNSERVE_* environment variables, so a
// node can be configured from docker run or compose without any file. It
// is applied after the file (if any), so the environment wins.
func (c *Config) ApplyEnv(getenv func(string) string) error {
	list := func(v string) []string {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var errs []error
	set := func(key string, fn func(string) error) {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			if err := fn(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
			}
		}
	}
	set("DNSERVE_UPSTREAM_MODE", func(v string) error { c.Upstream.Mode = v; return nil })
	set("DNSERVE_UPSTREAM_SERVERS", func(v string) error { c.Upstream.Servers = list(v); return nil })
	set("DNSERVE_TUNNEL_INTERFACE", func(v string) error { c.Upstream.Tunnel.Interface = v; return nil })
	set("DNSERVE_TUNNEL_EXPECTED_EGRESS", func(v string) error { c.Upstream.Tunnel.ExpectedEgress = list(v); return nil })
	set("DNSERVE_TUNNEL_ON_DOWN", func(v string) error { c.Upstream.Tunnel.OnDown = v; return nil })
	set("DNSERVE_ALLOWED_NETS", func(v string) error { c.DNS.AllowedNets = list(v); return nil })
	set("DNSERVE_LOCAL_DNS", func(v string) error { c.DNS.LocalDNS = v; return nil })
	set("DNSERVE_TIME_ZONE", func(v string) error { c.TimeZone = v; return nil })
	set("DNSERVE_BLOCK_BYPASS", func(v string) error {
		b, err := strconv.ParseBool(v)
		c.Filtering.BlockBypass = b
		return err
	})
	set("DNSERVE_CLUSTER_LISTEN", func(v string) error { c.Cluster.Listen = v; return nil })
	set("DNSERVE_CLUSTER_ADVERTISE", func(v string) error { c.Cluster.Advertise = v; return nil })
	set("DNSERVE_BLOCK_MODE", func(v string) error { c.Filtering.BlockMode = v; return nil })
	return errors.Join(errs...)
}

// Validate checks the configuration for mistakes that would stop the node.
func (c Config) Validate() error {
	var errs []error
	if len(c.DNS.Listen) == 0 {
		errs = append(errs, errors.New("dns.listen: at least one address is required"))
	}
	switch c.Upstream.Mode {
	case "forward":
		if len(c.Upstream.Servers) == 0 {
			errs = append(errs, errors.New("upstream.servers: at least one server is required in forward mode"))
		}
		for _, s := range c.Upstream.Servers {
			if err := validateUpstream(s); err != nil {
				errs = append(errs, fmt.Errorf("upstream.servers: %q: %w", s, err))
			}
		}
	case "recursive", "tunnel":
		r := c.Upstream.Recursive
		if r.Binary == "" {
			errs = append(errs, errors.New("upstream.recursive.binary is required"))
		}
		if r.Port <= 0 || r.Port > 65535 {
			errs = append(errs, errors.New("upstream.recursive.port must be 1-65535"))
		}
		if c.Upstream.Mode == "tunnel" {
			t := c.Upstream.Tunnel
			if t.Interface == "" && len(t.ExpectedEgress) == 0 {
				errs = append(errs, errors.New("upstream.tunnel: set interface and/or expected_egress so the node can tell the tunnel is up"))
			}
			if t.CheckInterval <= 0 {
				errs = append(errs, errors.New("upstream.tunnel.check_interval must be positive"))
			}
			switch t.OnDown {
			case "forward":
				if len(c.Upstream.Servers) == 0 {
					errs = append(errs, errors.New("upstream.tunnel.on_down forward needs upstream.servers"))
				}
			case "block":
			default:
				errs = append(errs, fmt.Errorf("upstream.tunnel.on_down: unknown value %q (use forward or block)", t.OnDown))
			}
			for _, e := range t.ExpectedEgress {
				if _, err := netip.ParsePrefix(e); err != nil {
					if _, err := netip.ParseAddr(e); err != nil {
						errs = append(errs, fmt.Errorf("upstream.tunnel.expected_egress: %q is not an IP or CIDR", e))
					}
				}
			}
		}
	default:
		errs = append(errs, fmt.Errorf("upstream.mode: unknown mode %q", c.Upstream.Mode))
	}
	if len(c.DNS.TLS.DoHListen) > 0 && !strings.HasPrefix(c.DNS.TLS.DoHPath, "/") {
		errs = append(errs, errors.New("dns.tls.doh_path must start with /"))
	}
	if (c.DNS.TLS.CertFile == "") != (c.DNS.TLS.KeyFile == "") {
		errs = append(errs, errors.New("dns.tls: set both cert_file and key_file, or neither"))
	}
	if c.Upstream.Timeout <= 0 {
		errs = append(errs, errors.New("upstream.timeout must be positive"))
	}
	if _, _, err := net.SplitHostPort(c.Cluster.Listen); err != nil {
		errs = append(errs, fmt.Errorf("cluster.listen: %q is not host:port (for example :8081)", c.Cluster.Listen))
	}
	if a := c.Cluster.Advertise; a != "" {
		if h, p, err := net.SplitHostPort(a); err != nil || h == "" || p == "" {
			errs = append(errs, fmt.Errorf("cluster.advertise: %q is not host:port (for example 192.168.1.10:8081)", a))
		}
	}
	switch c.Filtering.BlockMode {
	case "null_ip", "nxdomain", "refused":
	default:
		errs = append(errs, fmt.Errorf("filtering.block_mode: unknown mode %q", c.Filtering.BlockMode))
	}
	for _, n := range c.DNS.AllowedNets {
		if _, err := netip.ParsePrefix(n); err != nil {
			if _, err := netip.ParseAddr(n); err != nil {
				errs = append(errs, fmt.Errorf("dns.allowed_nets: %q is not an IP or CIDR", n))
			}
		}
	}
	if _, err := c.Location(); err != nil {
		errs = append(errs, fmt.Errorf("time_zone: %q is not a known time zone (use a name like Europe/London)", c.TimeZone))
	}
	if _, err := NormalizeRecords(c.DNS.Records); err != nil {
		errs = append(errs, fmt.Errorf("dns.records: %w", err))
	}
	if c.DNS.LocalDNS != "" {
		if _, err := LocalDNSAddr(c.DNS.LocalDNS); err != nil {
			errs = append(errs, fmt.Errorf("dns.local_dns: %w", err))
		}
	}
	for _, l := range append(append([]ListConfig(nil), c.Filtering.Lists...), c.Filtering.Allowlists...) {
		if strings.TrimSpace(l.URL) == "" {
			errs = append(errs, fmt.Errorf("filtering: list %q has no url", l.Name))
		}
	}
	if c.Cache.Enabled && c.Cache.MaxEntries <= 0 {
		errs = append(errs, errors.New("cache.max_entries must be positive"))
	}
	return errors.Join(errs...)
}

// LocalDNSAddr turns "192.168.1.1" or "192.168.1.1:5353" into host:port.
func LocalDNSAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address", s)
	}
	return netip.AddrPortFrom(a, 53).String(), nil
}

func validateUpstream(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https", "tls", "udp", "tcp":
	default:
		return fmt.Errorf("unsupported scheme %q (use https, tls, udp or tcp)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	return nil
}

// Location is the time zone for schedules.
func (c Config) Location() (*time.Location, error) {
	if c.TimeZone == "" {
		return time.Local, nil
	}
	return time.LoadLocation(c.TimeZone)
}
