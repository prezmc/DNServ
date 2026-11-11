package certs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

func TestSelfSigned(t *testing.T) {
	dir := t.TempDir()
	c, err := SelfSigned(dir, []string{"dns1.example.com", "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	in := Describe(c)
	if !in.SelfSigned || in.Subject != "dns1.example.com" {
		t.Fatalf("info %+v", in)
	}
	again, _ := SelfSigned(dir, []string{"192.168.1.10"})
	if Describe(again).Fingerprint != in.Fingerprint {
		t.Fatal("made a new certificate though the old one covers the names")
	}
	more, _ := SelfSigned(dir, []string{"10.0.0.5"})
	mi := Describe(more)
	if mi.Fingerprint == in.Fingerprint {
		t.Fatal("kept a certificate that doesn't cover a new address")
	}
	for _, want := range []string{"dns1.example.com", "192.168.1.10", "10.0.0.5"} {
		if !strings.Contains(strings.Join(mi.Names, " "), want) {
			t.Fatalf("new certificate lost %s: %v", want, mi.Names)
		}
	}
}

// testCert makes a CA-signed (not self-signed) certificate for name.
func testCert(t *testing.T, name string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	ca, err := SelfSigned(t.TempDir(), []string{"Test CA"})
	if err != nil {
		t.Fatal(err)
	}
	return signed(t, ca, name, notAfter)
}

func TestParse(t *testing.T) {
	c, k := testCert(t, "a.example.com", time.Now().Add(time.Hour))
	if _, err := Parse(c, k, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(c, k, time.Now().Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	_, k2 := testCert(t, "b.example.com", time.Now().Add(time.Hour))
	if _, err := Parse(c, k2, time.Now()); err == nil {
		t.Fatal("accepted a key that doesn't match")
	}
}

func TestListenerServesBoth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var h Holder
	ss, _ := SelfSigned(t.TempDir(), []string{"localhost", "127.0.0.1"})
	h.Set(ss)
	l := NewListener(ln, &tls.Config{GetCertificate: h.GetCertificate, MinVersion: tls.VersionTLS12})
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, map[bool]string{true: "tls", false: "plain"}[r.TLS != nil])
	})}
	go hs.Serve(l)
	defer hs.Close()
	addr := ln.Addr().String()
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	get := func(url string) (string, error) {
		resp, err := insecure.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if b, err := get("http://" + addr); err != nil || b != "plain" {
		t.Fatalf("plain with TLS off: %q %v", b, err)
	}
	if _, err := get("https://" + addr); err == nil {
		t.Fatal("TLS worked while off")
	}
	l.SetTLS(true)
	if b, err := get("https://" + addr); err != nil || b != "tls" {
		t.Fatalf("tls: %q %v", b, err)
	}
	if b, err := get("http://" + addr); err != nil || b != "plain" {
		t.Fatalf("plain with TLS on: %q %v", b, err)
	}
	// A client that connects and says nothing doesn't block others.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	if b, err := get("https://" + addr); err != nil || b != "tls" {
		t.Fatalf("tls behind an idle client: %q %v", b, err)
	}
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, b := range files {
		w, _ := zw.Create(n)
		w.Write(b)
	}
	zw.Close()
	return buf.Bytes()
}

func TestFromZip(t *testing.T) {
	c, k := testCert(t, "a.example.com", time.Now().Add(time.Hour))
	gc, gk, err := FromZip(zipOf(t, map[string][]byte{"npm-3/fullchain1.pem": c, "npm-3/privkey1.pem": k, "npm-3/cert1.pem": c, "npm-3/chain1.pem": []byte("x")}))
	if err != nil || !bytes.Equal(gc, c) || !bytes.Equal(gk, k) {
		t.Fatalf("letsencrypt zip: %v", err)
	}
	if _, _, err := FromZip(zipOf(t, map[string][]byte{"cert.pem": c})); err == nil {
		t.Fatal("accepted a zip with no key")
	}
}

// fakeNPM is enough of Nginx Proxy Manager's API for the tests.
type fakeNPM struct {
	mu        sync.Mutex
	cert, key []byte
	downloads int
}

func (f *fakeNPM) handler(t *testing.T) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["identity"] != "dns@example.com" || in["secret"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"message":"Invalid password"}}`)
			return
		}
		io.WriteString(w, `{"token":"tok","expires":"2030-01-01T00:00:00Z"}`)
	})
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer tok" }
	m.HandleFunc("GET /api/nginx/certificates", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `[{"id":3,"nice_name":"dns.example.com","domain_names":["dns.example.com"],"provider":"letsencrypt","expires_on":"2027-02-01 10:00:00"}]`)
	})
	m.HandleFunc("GET /api/nginx/certificates/3/download", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.downloads++
		w.Write(zipOf(t, map[string][]byte{"fullchain1.pem": f.cert, "privkey1.pem": f.key}))
	})
	return m
}

func TestNPM(t *testing.T) {
	f := &fakeNPM{}
	f.cert, f.key = testCert(t, "dns.example.com", time.Now().Add(time.Hour))
	hs := httptest.NewServer(f.handler(t))
	defer hs.Close()
	n := &NPM{URL: hs.URL + "/", Email: "dns@example.com", Password: "pw"}
	list, err := n.List(context.Background())
	if err != nil || len(list) != 1 || list[0].ID != 3 || list[0].Name != "dns.example.com" || list[0].Expires.Year() != 2027 {
		t.Fatalf("list %+v %v", list, err)
	}
	c, _, err := n.Download(context.Background(), 3)
	if err != nil || !bytes.Equal(c, f.cert) {
		t.Fatalf("download %v", err)
	}
	if _, _, err := n.Download(context.Background(), 9); err == nil || !strings.Contains(err.Error(), "2.10") {
		t.Fatalf("missing cert: %v", err)
	}
	n.Password = "nope"
	if _, err := n.List(context.Background()); err != ErrNPMLogin {
		t.Fatalf("bad login: %v", err)
	}
}

func TestManagerFilesRenewal(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	c1, k1 := testCert(t, "dns.example.com", time.Now().Add(24*time.Hour))
	os.WriteFile(cf, c1, 0o600)
	os.WriteFile(kf, k1, 0o600)

	var mu sync.Mutex
	cfg := store.HTTPSConfig{Mode: store.HTTPSFiles, CertFile: cf, KeyFile: kf, CertPEM: string(c1), KeyPEM: string(k1), Redirect: true}
	m := &Manager{DataDir: t.TempDir(), IsLeader: func() bool { return true }}
	m.Propose = func(c store.HTTPSCert) error {
		mu.Lock()
		defer mu.Unlock()
		if c.Error == "" {
			cfg.CertPEM, cfg.KeyPEM = c.CertPEM, c.KeyPEM
		}
		cfg.FetchError = c.Error
		return nil
	}
	m.Apply(cfg)
	if s := m.Status(); !s.On || s.Cert == nil || s.Cert.SelfSigned || !m.Redirect() {
		t.Fatalf("status %+v", s)
	}
	m.checkFiles(m.current())

	c2, k2 := testCert(t, "dns.example.com", time.Now().Add(48*time.Hour))
	os.WriteFile(cf, c2, 0o600)
	os.WriteFile(kf, k2, 0o600)
	m.checkFiles(m.current())
	mu.Lock()
	got := cfg
	mu.Unlock()
	if got.CertPEM != string(c2) {
		t.Fatal("renewed files weren't shared")
	}
	// An older file on some node doesn't undo the renewal.
	m.Apply(got)
	os.WriteFile(cf, c1, 0o600)
	os.WriteFile(kf, k1, 0o600)
	m.checkFiles(m.current())
	mu.Lock()
	defer mu.Unlock()
	if cfg.CertPEM != string(c2) {
		t.Fatal("an older certificate replaced a newer one")
	}
}

func TestManagerFallsBackToSelfSigned(t *testing.T) {
	m := &Manager{DataDir: t.TempDir()}
	m.Apply(store.HTTPSConfig{Mode: store.HTTPSFiles, CertFile: "/nope/c.pem", KeyFile: "/nope/k.pem"})
	s := m.Status()
	if !s.On || s.Cert == nil || !s.Cert.SelfSigned || !strings.Contains(s.Error, "certificate file") {
		t.Fatalf("status %+v", s)
	}
	fb := &tls.Certificate{}
	if c, _ := m.DNSCertificate(fb)(nil); c != fb {
		t.Fatal("DNS over TLS used a self-signed dashboard certificate")
	}
	m.Off = true
	m.Apply(store.HTTPSConfig{Mode: store.HTTPSSelfSigned})
	if s := m.Status(); s.On || !s.Forced {
		t.Fatalf("forced off: %+v", s)
	}
}

func TestRedirect(t *testing.T) {
	m := &Manager{DataDir: t.TempDir()}
	m.Apply(store.HTTPSConfig{Mode: store.HTTPSSelfSigned, Redirect: true})
	h := m.RedirectHTTPS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	for path, want := range map[string]int{"/": 307, "/app.js?x=1": 307, "/api/v1/status": 299, "/healthz": 299, "/metrics": 299} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://dns.lan:8080"+path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
		if want == 307 && w.Header().Get("Location") != "https://dns.lan:8080"+path {
			t.Errorf("%s: location %s", path, w.Header().Get("Location"))
		}
	}
	r := httptest.NewRequest("GET", "http://dns.lan:8080/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 299 {
		t.Error("redirected a request a proxy sent")
	}
}
