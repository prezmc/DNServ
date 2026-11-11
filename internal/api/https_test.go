package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prezmc/dnserv/internal/certs"
	"github.com/prezmc/dnserv/internal/store"
)

func testPEM(t *testing.T, name string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if _, err := certs.SelfSigned(dir, []string{name}); err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(filepath.Join(dir, "https.crt"))
	k, _ := os.ReadFile(filepath.Join(dir, "https.key"))
	return string(c), string(k)
}

func TestHTTPSSettings(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var got struct {
		Settings struct {
			Mode    string   `json:"mode"`
			Names   []string `json:"names"`
			HasCert bool     `json:"has_cert"`
			NPM     *struct {
				HasPassword bool   `json:"has_password"`
				CertName    string `json:"cert_name"`
			} `json:"npm"`
		} `json:"settings"`
	}
	admin.want(200, "GET", "/api/v1/https", nil, &got)
	if got.Settings.Mode != "" {
		t.Fatalf("HTTPS is on by default: %+v", got)
	}

	c, k := testPEM(t, "dns.example.com")
	_, k2 := testPEM(t, "other.example.com")
	admin.want(400, "PUT", "/api/v1/https", map[string]any{"mode": "upload", "cert_pem": c, "key_pem": k2}, nil)
	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": "upload", "cert_pem": c, "key_pem": k, "redirect": true}, &got)
	if !got.Settings.HasCert || e.api.Store.State().HTTPS.KeyPEM == "" {
		t.Fatalf("upload not saved: %+v", got)
	}
	// Saving again without pasting keeps the certificate.
	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": "upload", "redirect": false}, nil)
	if e.api.Store.State().HTTPS.CertPEM != strings.TrimSpace(c)+"\n" {
		t.Fatal("re-saving lost the certificate")
	}
	raw := admin.raw("GET", "/api/v1/https")
	if strings.Contains(raw, "PRIVATE KEY") || strings.Contains(raw, "BEGIN CERTIFICATE") {
		t.Fatal("the API returned the certificate or key")
	}

	admin.want(400, "PUT", "/api/v1/https", map[string]any{"mode": "files", "cert_file": "/nope/c.pem", "key_file": "/nope/k.pem"}, nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.pem"), []byte(c), 0o600)
	os.WriteFile(filepath.Join(dir, "k.pem"), []byte(k), 0o600)
	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": "files", "cert_file": filepath.Join(dir, "c.pem"), "key_file": filepath.Join(dir, "k.pem")}, nil)

	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": "self_signed", "names": []string{"DNS1.example.com"}}, &got)
	if strings.Join(got.Settings.Names, ",") != "dns1.example.com,127.0.0.1" {
		t.Fatalf("names %v (want the typed name and the page's host)", got.Settings.Names)
	}
	admin.want(400, "PUT", "/api/v1/https", map[string]any{"mode": "self_signed", "names": []string{"bad name!"}}, nil)

	// Nginx Proxy Manager: list, then pick.
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	w, _ := zw.Create("fullchain1.pem")
	io.WriteString(w, c)
	w, _ = zw.Create("privkey1.pem")
	io.WriteString(w, k)
	zw.Close()
	npm := http.NewServeMux()
	npm.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["secret"] != "pw" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"token":"t"}`)
	})
	npm.HandleFunc("GET /api/nginx/certificates", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"id":7,"nice_name":"dns.example.com","domain_names":["dns.example.com"],"provider":"letsencrypt","expires_on":"2027-01-01 00:00:00"}]`)
	})
	npm.HandleFunc("GET /api/nginx/certificates/7/download", func(w http.ResponseWriter, r *http.Request) { w.Write(zipped.Bytes()) })
	hs := httptest.NewServer(npm)
	defer hs.Close()
	var list struct{ Certificates []certs.NPMCert }
	admin.want(502, "POST", "/api/v1/https/npm/certificates", map[string]any{"url": hs.URL, "email": "a@b.c", "password": "wrong"}, nil)
	admin.want(200, "POST", "/api/v1/https/npm/certificates", map[string]any{"url": hs.URL, "email": "a@b.c", "password": "pw"}, &list)
	if len(list.Certificates) != 1 || list.Certificates[0].ID != 7 {
		t.Fatalf("list %+v", list)
	}
	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": "npm", "npm": map[string]any{"url": hs.URL, "email": "a@b.c", "password": "pw", "cert_id": 7}}, &got)
	if got.Settings.NPM == nil || !got.Settings.NPM.HasPassword || got.Settings.NPM.CertName != "dns.example.com" {
		t.Fatalf("npm %+v", got.Settings.NPM)
	}
	// The saved password is used when none is sent.
	admin.want(200, "POST", "/api/v1/https/npm/certificates", map[string]any{"url": hs.URL, "email": "a@b.c"}, &list)
	if strings.Contains(admin.raw("GET", "/api/v1/https"), `"pw"`) {
		t.Fatal("the API returned the NPM password")
	}

	admin.want(200, "PUT", "/api/v1/https", map[string]any{"mode": ""}, nil)
	h := e.api.Store.State().HTTPS
	if h.Mode != "" || h.CertPEM != "" || h.NPM != nil {
		t.Fatalf("turning off kept secrets: %+v", h)
	}
	var audited int
	for _, a := range e.api.Store.State().Audit {
		if a.Op == store.OpHTTPSConfig {
			audited++
			if strings.Contains(string(a.After)+string(a.Before), "PRIVATE") {
				t.Fatal("audit log has the key")
			}
		}
	}
	if audited < 5 {
		t.Fatalf("audited %d changes", audited)
	}
}

// raw returns a response body as text.
func (c *client) raw(method, path string) string {
	var m json.RawMessage
	c.do(method, path, nil, &m)
	return string(m)
}
