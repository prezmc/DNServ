package server

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/config"
)

func startEncrypted(t *testing.T, up *fakeResolver) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	s, _ := newTestServer(t, func(c *config.Config) {
		c.DNS.TLS.DoTListen = []string{"127.0.0.1:0"}
		c.DNS.TLS.DoHListen = []string{"127.0.0.1:0"}
		c.DataDir = dir
	}, up)
	cert, fp, self, err := LoadOrCreateCert(s.cfg.DNS.TLS, dir)
	if err != nil || !self || len(fp) != 64 {
		t.Fatalf("cert: self=%v fp=%q err=%v", self, fp, err)
	}
	// A second load reuses the saved certificate.
	if _, fp2, _, _ := LoadOrCreateCert(s.cfg.DNS.TLS, dir); fp2 != fp {
		t.Fatal("self-signed certificate should be reused across restarts")
	}
	if err := s.StartEncrypted(cert, nil); err != nil {
		t.Fatal(err)
	}
	return s, filepath.Join(dir, "tls")
}

func TestDoHGetAndPost(t *testing.T) {
	up := &fakeResolver{}
	s, _ := startEncrypted(t, up)
	url := "https://" + s.DoHAddrs()[0] + "/dns-query"
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	q := new(dns.Msg)
	q.SetQuestion("doh.example.", dns.TypeA)
	q.Id = 0
	raw, _ := q.Pack()

	resp, err := client.Post(url, "application/dns-message", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil || len(m.Answer) != 1 || resp.Header.Get("Cache-Control") != "max-age=300" {
		t.Fatalf("POST: %v %v cache-control=%q", m, err, resp.Header.Get("Cache-Control"))
	}

	resp, err = client.Get(url + "?dns=" + base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := m.Unpack(body); err != nil || len(m.Answer) != 1 {
		t.Fatalf("GET: %v %v", m, err)
	}

	resp, _ = client.Get(url)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET without dns param = %d, want 400", resp.StatusCode)
	}
}

func TestDoT(t *testing.T) {
	up := &fakeResolver{}
	s, _ := startEncrypted(t, up)
	_, tcp := s.Addrs()
	dotAddr := tcp[len(tcp)-1] // listeners: plain TCP first, then DoT
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	q := new(dns.Msg)
	q.SetQuestion("dot.example.", dns.TypeA)
	r, _, err := c.Exchange(q, dotAddr)
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("DoT: %v %v", r, err)
	}
}

func TestFirefoxCanary(t *testing.T) {
	up := &fakeResolver{}
	_, addr := newTestServer(t, nil, up)
	if r := query(t, addr, "use-application-dns.net", dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("canary should be NXDOMAIN, got %v", r)
	}
	if up.calls.Load() != 0 {
		t.Fatal("canary must not reach upstream")
	}
}
