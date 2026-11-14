package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/store"
)

func TestDNSHostsList(t *testing.T) {
	hosts := DNSHosts()
	if len(hosts) < 150 {
		t.Fatalf("only %d DNS hosts", len(hosts))
	}
	cf, ok := DNSHost("cloudflare")
	if !ok || len(cf.Credentials) == 0 {
		t.Fatalf("cloudflare: %+v", cf)
	}
	if _, ok := DNSHost("exec"); ok {
		t.Fatal("exec runs programs and must not be offered")
	}
	got, err := CleanDNSSettings("cloudflare", map[string]string{"CF_DNS_API_TOKEN": " abc ", "CF_ZONE_API_TOKEN": ""})
	if err != nil || len(got) != 1 || got["CF_DNS_API_TOKEN"] != "abc" {
		t.Fatalf("clean: %v %v", got, err)
	}
	if _, err := CleanDNSSettings("cloudflare", map[string]string{"CF_DNS_API_TOKEN_FILE": "/etc/shadow"}); err == nil {
		t.Fatal("a setting the host doesn't list was accepted")
	}
}

func TestNewDNSProviderRestoresEnv(t *testing.T) {
	os.Unsetenv("CF_DNS_API_TOKEN")
	if _, err := newDNSProvider("cloudflare", map[string]string{"CF_DNS_API_TOKEN": "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("CF_DNS_API_TOKEN"); ok {
		t.Fatal("setting left in the environment")
	}
	if _, err := newDNSProvider("cloudflare", nil); err == nil {
		t.Fatal("no error without a login")
	}
}

func TestNeedsCertificate(t *testing.T) {
	now := time.Now()
	c, k := testCert(t, "dns1.example.com", now.Add(60*24*time.Hour))
	if NeedsCertificate(string(c), string(k), []string{"dns1.example.com"}, now) {
		t.Fatal("good certificate needs renewing")
	}
	if !NeedsCertificate(string(c), string(k), []string{"dns1.example.com", "dns2.example.com"}, now) {
		t.Fatal("name added but no renewal")
	}
	if !NeedsCertificate(string(c), string(k), []string{"dns1.example.com"}, now.Add(40*24*time.Hour)) {
		t.Fatal("20 days left but no renewal")
	}
	if !NeedsCertificate("", "", []string{"a.example.com"}, now) {
		t.Fatal("no certificate but no request")
	}
}

func TestHelperDNS(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			fmt.Fprint(w, `{"username":"u1","password":"p1","fulldomain":"abc.auth.example.org","subdomain":"abc"}`)
		case "/update":
			if r.Header.Get("X-Api-User") != "u1" || r.Header.Get("X-Api-Key") != "p1" {
				http.Error(w, "forbidden", http.StatusUnauthorized)
				return
			}
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			got[b["subdomain"]] = b["txt"]
			mu.Unlock()
			fmt.Fprintf(w, `{"txt":%q}`, b["txt"])
		}
	}))
	defer srv.Close()
	acc, err := RegisterHelper(context.Background(), srv.URL)
	if err != nil || acc.FullDomain != "abc.auth.example.org" {
		t.Fatalf("register: %+v %v", acc, err)
	}
	src := &store.ACMESource{Names: []string{"dns1.example.com"}, HelperAccounts: map[string]store.HelperAccount{"dns1.example.com": acc}}
	if c := HelperCNAMEs(src); len(c) != 1 || c[0].Name != "_acme-challenge.dns1.example.com" || c[0].Value != "abc.auth.example.org" {
		t.Fatalf("cnames: %+v", c)
	}
	p := &helperDNS{server: srv.URL, accounts: src.HelperAccounts}
	if err := p.Present("dns1.example.com", "tok", "tok.key"); err != nil {
		t.Fatal(err)
	}
	if got["abc"] == "" || len(got["abc"]) != 43 {
		t.Fatalf("txt sent: %q", got["abc"])
	}
	if err := p.Present("other.example.com", "tok", "tok.key"); err == nil {
		t.Fatal("no error for a name without an account")
	}
}

// TestObtainWithPebble asks Pebble, Let's Encrypt's test server, for a
// real certificate. Set PEBBLE_BIN (go install
// github.com/letsencrypt/pebble/v2/cmd/pebble@latest) or put pebble on
// PATH to run it.
func TestObtainWithPebble(t *testing.T) {
	bin := os.Getenv("PEBBLE_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("pebble")
	}
	if bin == "" {
		t.Skip("pebble not installed")
	}
	dir := t.TempDir()

	// A DNS server Pebble asks for the TXT records.
	var mu sync.Mutex
	txt := map[string]string{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		mu.Lock()
		if v, ok := txt[strings.ToLower(q.Question[0].Name)]; ok && q.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v}})
		}
		mu.Unlock()
		w.WriteMsg(m)
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: tl, Handler: handler}} {
		go srv.ActivateAndServe()
		defer srv.Shutdown()
	}

	// Pebble with a certificate of our own for its API.
	c, k := testCert(t, "localhost", time.Now().Add(24*time.Hour))
	os.WriteFile(filepath.Join(dir, "cert.pem"), c, 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), k, 0o600)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	mgmt := ln2.Addr().String()
	ln2.Close()
	cfg := fmt.Sprintf(`{"pebble":{"listenAddress":%q,"managementListenAddress":%q,"certificate":%q,"privateKey":%q,"httpPort":5002,"tlsPort":5001}}`,
		addr, mgmt, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	os.WriteFile(filepath.Join(dir, "pebble.json"), []byte(cfg), 0o600)
	cmd := exec.Command(bin, "-config", filepath.Join(dir, "pebble.json"), "-dnsserver", pc.LocalAddr().String())
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	if testing.Verbose() {
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	dirURL := "https://" + addr + "/dir"
	for i := 0; ; i++ {
		resp, err := hc.Get(dirURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		if i > 50 {
			t.Fatal("pebble didn't start: ", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	defer func(old time.Duration) { waitInterval = old }(waitInterval)
	waitInterval = 50 * time.Millisecond
	key, _ := NewAccountKey()
	names := []string{"dns1.example.com", "dns2.example.com"}
	// By hand: the records are handed out, then "added" to DNS.
	var shown []store.DNSRecord
	req := ACMERequest{
		ACMESource: store.ACMESource{Method: store.ACMEManual, Directory: dirURL, Email: "owner@example.com", AccountKey: key, Names: names},
		Publish: func(r []store.DNSRecord) {
			mu.Lock()
			shown = r
			for _, rec := range r {
				txt[strings.ToLower(dns.Fqdn(rec.Name))] = rec.Value
			}
			mu.Unlock()
		},
		HTTPClient:      hc,
		SkipPropagation: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	certPEM, keyPEM, err := Obtain(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(shown) != 2 || shown[0].Type != "TXT" || !strings.HasPrefix(shown[0].Name, "_acme-challenge.dns") {
		t.Fatalf("records shown: %+v", shown)
	}
	cert, err := Parse(certPEM, keyPEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if NeedsCertificate(string(certPEM), string(keyPEM), names, time.Now()) {
		t.Fatalf("new certificate isn't good enough: %v", cert.Leaf.DNSNames)
	}

	// The manager, as the leader, asks for one and shares it.
	got := make(chan store.HTTPSCert, 4)
	m := &Manager{DataDir: dir, IsLeader: func() bool { return true }, Holder: Holder{},
		Propose:     func(c store.HTTPSCert) error { got <- c; return nil },
		ProposeWait: func(w store.HTTPSWait) error { req.Publish(w.Records); return nil }}
	old := acmeObtain
	acmeObtain = func(ctx context.Context, r ACMERequest) ([]byte, []byte, error) {
		r.HTTPClient, r.SkipPropagation = hc, true
		return old(ctx, r)
	}
	defer func() { acmeObtain = old }()
	src := req.ACMESource
	m.Apply(store.HTTPSConfig{Mode: store.HTTPSACME, ACME: &src})
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	go m.Run(rctx)
	m.poke()
	select {
	case c := <-got:
		if c.Error != "" || c.CertPEM == "" {
			t.Fatalf("manager: %+v", c)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("manager didn't get a certificate")
	}
}
