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
	"net/url"
	"os"
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
	DataDir   string          `yaml:"data_dir"`
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
}

// UpstreamConfig selects how queries the node can't answer are resolved.
type UpstreamConfig struct {
	// Mode: "forward" (encrypted or plain forwarding). "recursive" and
	// "tunnel" arrive in step 1b.
	Mode string `yaml:"mode"`
	// Servers, tried in order of measured latency, failing over on error.
	// Schemes: https:// (DoH), tls:// (DoT), udp://, tcp://.
	Servers []string `yaml:"servers"`
	// Bootstrap resolvers used only to look up the hostnames of DoH/DoT
	// servers. Must be IP addresses.
	Bootstrap []string      `yaml:"bootstrap"`
	Timeout   time.Duration `yaml:"timeout"`
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
}

// ListConfig is one blocklist or allowlist.
type ListConfig struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Enabled bool   `yaml:"enabled"`
}

// HTTPConfig serves health checks and metrics.
type HTTPConfig struct {
	Listen string `yaml:"listen"`
}

// Default returns a configuration that works out of the box: encrypted
// forwarding to Cloudflare over DNS over HTTPS, caching on, filtering on.
func Default() Config {
	return Config{
		DNS: DNSConfig{
			Listen:    []string{":53"},
			UDPSize:   1232,
			RateLimit: 0,
		},
		Upstream: UpstreamConfig{
			Mode:      "forward",
			Servers:   []string{"https://cloudflare-dns.com/dns-query", "tls://one.one.one.one"},
			Bootstrap: []string{"1.1.1.1:53", "1.0.0.1:53"},
			Timeout:   3 * time.Second,
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
		errs = append(errs, fmt.Errorf("upstream.mode %q is not available yet", c.Upstream.Mode))
	default:
		errs = append(errs, fmt.Errorf("upstream.mode: unknown mode %q", c.Upstream.Mode))
	}
	if c.Upstream.Timeout <= 0 {
		errs = append(errs, errors.New("upstream.timeout must be positive"))
	}
	switch c.Filtering.BlockMode {
	case "null_ip", "nxdomain", "refused":
	default:
		errs = append(errs, fmt.Errorf("filtering.block_mode: unknown mode %q", c.Filtering.BlockMode))
	}
	if c.Cache.Enabled && c.Cache.MaxEntries <= 0 {
		errs = append(errs, errors.New("cache.max_entries must be positive"))
	}
	return errors.Join(errs...)
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
