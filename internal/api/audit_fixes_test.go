package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prezmc/dnserv/internal/store"
)

// A saved SMB password is used only for the server and account it was
// saved for.
func TestSMBPasswordNotSentElsewhere(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	if _, err := e.api.Store.Apply(store.NewCommand(store.OpBackupSMB, "t", store.SMBTarget{Server: "nas.lan", Share: "backups", User: "u", Password: "p"})); err != nil {
		t.Fatal(err)
	}
	var dialled []string
	e.api.smbDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		return nil, errors.New("connection refused")
	}
	for _, other := range []map[string]any{
		{"server": "evil.example", "share": "backups", "user": "u"},
		{"server": "nas.lan", "share": "backups", "user": "someone"},
		{"server": "nas.lan", "share": "backups", "user": "u", "domain": "EVIL"},
	} {
		admin.want(400, "PUT", "/api/v1/backups/smb", other, nil)
	}
	if len(dialled) != 0 {
		t.Fatalf("signed in to %v with the saved password", dialled)
	}
	// The same share (written another way) still reuses it.
	admin.want(400, "PUT", "/api/v1/backups/smb", map[string]any{"server": `\\NAS.lan\backups\sub`, "user": "u"}, nil)
	if len(dialled) != 1 || dialled[0] != "NAS.lan:445" && dialled[0] != "nas.lan:445" {
		t.Fatalf("dialled %v", dialled)
	}
}

func TestSameS3(t *testing.T) {
	old := store.S3Target{Endpoint: "https://minio.lan:9000", Region: "us-east-1", Bucket: "b", AccessKey: "AK", SecretKey: "s"}
	if !sameS3(store.S3Target{Endpoint: "https://minio.lan:9000/", Region: "us-east-1", Bucket: "other", AccessKey: "AK"}, old) {
		t.Fatal("same service refused")
	}
	for _, t2 := range []store.S3Target{
		{Endpoint: "https://evil.example", Region: "us-east-1", Bucket: "b", AccessKey: "AK"},
		{Endpoint: "https://minio.lan:9000", Region: "us-east-1", Bucket: "b", AccessKey: "AK2"},
	} {
		if sameS3(t2, old) {
			t.Fatalf("%+v counted as the same", t2)
		}
	}
}

// Changing a DNS host's address means typing its login again.
func TestACMETokenNotSentToNewAddress(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var seen []map[string]string
	oldTest := testDNSHost
	defer func() { testDNSHost = oldTest }()
	testDNSHost = func(_ context.Context, host string, settings map[string]string, names []string) error {
		seen = append(seen, settings)
		if settings["CF_DNS_API_TOKEN"] == "" {
			return errors.New("no token")
		}
		return nil
	}
	body := func(settings map[string]string) map[string]any {
		return map[string]any{"mode": "acme", "acme": map[string]any{"method": "dns_api", "email": "me@example.com", "names": []string{"dns1.example.com"},
			"staging": true, "dns_host": "cloudflare", "dns_settings": settings}}
	}
	admin.want(200, "PUT", "/api/v1/https", body(map[string]string{"CF_DNS_API_TOKEN": "secret-token"}), nil)
	admin.want(200, "PUT", "/api/v1/https", body(map[string]string{"CLOUDFLARE_TTL": "300"}), nil) // not an address: kept
	before := len(seen)
	admin.want(400, "PUT", "/api/v1/https", body(map[string]string{"CLOUDFLARE_BASE_URL": "https://attacker.example"}), nil)
	if len(seen) != before {
		t.Fatalf("DNS host contacted with a new address and the saved token: %v", seen[len(seen)-1])
	}
	admin.want(200, "PUT", "/api/v1/https", body(map[string]string{"CLOUDFLARE_BASE_URL": "https://api.example", "CF_DNS_API_TOKEN": "typed-again"}), nil)
}

type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// Once a node is set up, a first-run restore is refused before the
// upload is read.
func TestSetupRestoreRefusedBeforeReading(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin()
	body := &countingReader{r: io.MultiReader(strings.NewReader("--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b\"\r\n\r\n"), io.LimitReader(zeros{}, 60<<20))}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/setup/restore", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("HTTP %d", resp.StatusCode)
		}
	}
	if n := body.n.Load(); n > 8<<20 {
		t.Fatalf("server read %d MB of the upload", n>>20)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// One address can't use up the passkey sign-in pool.
func TestPasskeyBeginsCappedPerAddress(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin()
	e.api.AllowedOrigins = []string{"dns1.example.com"}
	begin := func() int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/auth/passkey/begin", bytes.NewReader(nil))
		req.Header.Set("Origin", "https://dns1.example.com")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < maxPerOwner; i++ {
		if code := begin(); code != 200 {
			t.Fatalf("begin %d: HTTP %d", i, code)
		}
	}
	if code := begin(); code != http.StatusServiceUnavailable {
		t.Fatalf("begin over the cap: HTTP %d", code)
	}
	if len(e.api.passkeyCer.m) != maxPerOwner {
		t.Fatalf("%d ceremonies held", len(e.api.passkeyCer.m))
	}
}

func TestAddrBlock(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.5":            "192.168.1.5",
		"::ffff:192.168.1.5":     "192.168.1.5",
		"2001:db8:1:2:3:4:5:6":   "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::abc": "2001:db8:1:2::/64",
	} {
		if got := addrBlock(in); got != want {
			t.Errorf("addrBlock(%q) = %q, want %q", in, got, want)
		}
	}
}
