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
