package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil || cfg.Upstream.Servers[0] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("missing file should give defaults: %v", err)
	}
}

func TestLoadOverridesAndRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	os.WriteFile(p, []byte("upstream:\n  servers: [\"tls://dns.quad9.net\"]\nfiltering:\n  block_mode: nxdomain\n"), 0o600)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.Servers[0] != "tls://dns.quad9.net" || cfg.Filtering.BlockMode != "nxdomain" || !cfg.Cache.Enabled {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	os.WriteFile(p, []byte("upstrem:\n  mode: forward\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "upstrem") {
		t.Fatalf("typo should be rejected, got %v", err)
	}

	os.WriteFile(p, []byte("upstream:\n  servers: [\"ftp://x\"]\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("bad scheme should be rejected")
	}

	os.WriteFile(p, []byte(""), 0o600)
	if _, err := Load(p); err != nil {
		t.Fatalf("empty file should give defaults: %v", err)
	}
}

func TestTunnelValidation(t *testing.T) {
	c := Default()
	c.Upstream.Mode = "tunnel"
	if err := c.Validate(); err != nil {
		t.Fatalf("default tunnel settings should validate: %v", err)
	}
	c.Upstream.Tunnel.Interface = ""
	if err := c.Validate(); err == nil {
		t.Fatal("tunnel with no interface and no expected_egress must be rejected")
	}
	c.Upstream.Tunnel.ExpectedEgress = []string{"185.65.0.0/16", "not-an-ip"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("bad egress should be named, got %v", err)
	}
	c.Upstream.Tunnel.ExpectedEgress = []string{"185.65.0.0/16"}
	c.Upstream.Tunnel.OnDown = "panic"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown on_down must be rejected")
	}
	c = Default()
	c.DNS.TLS.CertFile = "/x.crt"
	if err := c.Validate(); err == nil {
		t.Fatal("cert without key must be rejected")
	}
}

func TestApplyEnv(t *testing.T) {
	c := Default()
	env := map[string]string{
		"DNSERV_UPSTREAM_MODE":          "tunnel",
		"DNSERV_TUNNEL_EXPECTED_EGRESS": "185.65.0.0/16, 193.32.0.1",
		"DNSERV_BLOCK_BYPASS":           "true",
		"DNSERV_UPSTREAM_SERVERS":       "tls://dns.quad9.net",
	}
	if err := c.ApplyEnv(func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	if c.Upstream.Mode != "tunnel" || len(c.Upstream.Tunnel.ExpectedEgress) != 2 || !c.Filtering.BlockBypass || c.Upstream.Servers[0] != "tls://dns.quad9.net" {
		t.Fatalf("env not applied: %+v", c.Upstream)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	env["DNSERV_BLOCK_BYPASS"] = "maybe"
	if err := c.ApplyEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("bad boolean must be rejected")
	}
}
