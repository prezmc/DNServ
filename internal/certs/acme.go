package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/prezmc/dnserv/internal/store"
)

// DNSHostInfo describes one DNS host (from lego's provider list) and the
// settings it takes. Settings are the environment variable names lego
// documents, such as CF_DNS_API_TOKEN.
type DNSHostInfo struct {
	Code        string      `json:"code"`
	Name        string      `json:"name"`
	URL         string      `json:"url,omitempty"`
	Credentials [][2]string `json:"credentials"` // name, description
	Additional  [][2]string `json:"additional"`
	// Main is the recommended way to sign in, with plain labels, for
	// popular hosts (empty for the rest); Help says where to get it.
	Main []SimpleField `json:"main,omitempty"`
	Help string        `json:"help,omitempty"`
}

// dnshosts.json is made by scripts/gen-dnshosts.py.
//
//go:embed dnshosts.json
var dnsHostsJSON []byte

// Hosts that would run programs or need someone at the keyboard.
var unsupportedHosts = map[string]bool{"exec": true, "manual": true}

var dnsHosts = sync.OnceValue(func() []DNSHostInfo {
	var all, out []DNSHostInfo
	if err := json.Unmarshal(dnsHostsJSON, &all); err != nil {
		panic(err)
	}
	for _, h := range all {
		if !unsupportedHosts[h.Code] {
			if sh, ok := simpleHosts[h.Code]; ok {
				h.Main, h.Help = sh.fields, sh.help
			}
			out = append(out, h)
		}
	}
	return out
})

// DNSHosts lists the DNS hosts Let's Encrypt certificates can use.
func DNSHosts() []DNSHostInfo { return dnsHosts() }

// DNSHost returns the host with this code.
func DNSHost(code string) (DNSHostInfo, bool) {
	for _, h := range dnsHosts() {
		if h.Code == code {
			return h, true
		}
	}
	return DNSHostInfo{}, false
}

// CleanDNSSettings keeps the settings host takes, trimmed and non-empty.
func CleanDNSSettings(host string, in map[string]string) (map[string]string, error) {
	h, ok := DNSHost(host)
	if !ok {
		return nil, fmt.Errorf("unknown DNS host %q", host)
	}
	known := map[string]bool{}
	for _, kv := range append(append([][2]string{}, h.Credentials...), h.Additional...) {
		known[kv[0]] = true
	}
	out := map[string]string{}
	for k, v := range in {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		if !known[k] {
			return nil, fmt.Errorf("%s doesn't take a setting called %s", h.Name, k)
		}
		out[k] = v
	}
	return out, nil
}

// lego's DNS hosts read their settings from environment variables when
// they are made, so they are made one at a time with the settings set
// only for that moment.
var envMu sync.Mutex

func newDNSProvider(host string, settings map[string]string) (challenge.Provider, error) {
	if _, ok := DNSHost(host); !ok {
		return nil, fmt.Errorf("unknown DNS host %q", host)
	}
	envMu.Lock()
	defer envMu.Unlock()
	type old struct {
		v  string
		ok bool
	}
	saved := map[string]old{}
	for k, v := range settings {
		ov, ok := os.LookupEnv(k)
		saved[k] = old{ov, ok}
		os.Setenv(k, v)
	}
	defer func() {
		for k, o := range saved {
			if o.ok {
				os.Setenv(k, o.v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()
	p, err := dns.NewDNSChallengeProviderByName(host)
	if err != nil {
		return nil, errors.New(strings.TrimPrefix(err.Error(), host+": "))
	}
	return p, nil
}

// TestDNSHost adds and removes a TXT record for each name, to make sure
// the DNS host login works before it is saved.
func TestDNSHost(ctx context.Context, host string, settings map[string]string, names []string) error {
	p, err := newDNSProvider(host, settings)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		for _, n := range names {
			const token, keyAuth = "dnserv-test", "dnserv-test.check"
			if err := p.Present(n, token, keyAuth); err != nil {
				done <- fmt.Errorf("couldn't add a TXT record for %s: %w", n, err)
				return
			}
			if err := p.CleanUp(n, token, keyAuth); err != nil {
				done <- fmt.Errorf("added a TXT record for %s but couldn't remove it: %w", n, err)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errors.New("the DNS host didn't answer in time")
	}
}

// ACMERequest is one certificate request.
type ACMERequest struct {
	store.ACMESource
	// Publish shows the TXT records a by-hand request waits for.
	Publish func([]store.DNSRecord)
	// HTTPClient talks to the ACME service (nil: lego's default).
	HTTPClient *http.Client
	// Provider replaces the DNS host (tests).
	Provider challenge.Provider
	// SkipPropagation skips waiting for the TXT records to show (tests).
	SkipPropagation bool
	Log             *slog.Logger
}

// NewAccountKey makes an ACME account key (PEM).
func NewAccountKey() (string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

var legoLogOnce sync.Once

// Obtain asks the ACME service for one certificate listing every name,
// proving each with a DNS TXT record, and returns the chain and its new
// private key as PEM. It can take a few minutes.
func Obtain(ctx context.Context, r ACMERequest) (certPEM, keyPEM []byte, err error) {
	logger := r.Log
	if logger == nil {
		logger = slog.Default()
	}
	legoLogOnce.Do(func() {
		legolog.Logger = log.New(&slogWriter{logger.With("part", "acme")}, "", 0)
	})
	b, _ := pem.Decode([]byte(r.AccountKey))
	if b == nil {
		return nil, nil, errors.New("the ACME account key is damaged")
	}
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, nil, errors.New("the ACME account key is damaged")
	}
	p := r.Provider
	if p == nil {
		switch r.Method {
		case store.ACMEManual:
			p = &manualDNS{publish: r.Publish}
		case store.ACMEDNSHelper:
			p = &helperDNS{server: r.Helper, accounts: r.HelperAccounts}
		default:
			if p, err = newDNSProvider(r.DNSHost, r.DNSSettings); err != nil {
				return nil, nil, err
			}
		}
	}
	u := &acmeUser{email: r.Email, key: key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = r.Directory
	cfg.UserAgent = "dnserv"
	cfg.Certificate.KeyType = certcrypto.EC256
	if r.HTTPClient != nil {
		cfg.HTTPClient = r.HTTPClient
	}
	type result struct {
		res *certificate.Resource
		err error
	}
	done := make(chan result, 1)
	go func() {
		cl, err := lego.NewClient(cfg)
		if err != nil {
			done <- result{nil, fmt.Errorf("reaching the certificate service: %w", err)}
			return
		}
		reg, err := cl.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			done <- result{nil, fmt.Errorf("signing up with the certificate service: %w", err)}
			return
		}
		u.reg = reg
		// Stop waiting for records once the request is called off.
		opts := []dns01.ChallengeOption{dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			if ctx.Err() != nil {
				return true, ctx.Err() // true stops lego waiting
			}
			return check(fqdn, value)
		})}
		if r.SkipPropagation {
			opts = append(opts, dns01.PropagationWait(0, true))
		}
		if err := cl.Challenge.SetDNS01Provider(p, opts...); err != nil {
			done <- result{nil, err}
			return
		}
		res, err := cl.Certificate.Obtain(certificate.ObtainRequest{Domains: r.Names, Bundle: true})
		done <- result{res, err}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, errors.New("gave up waiting for the certificate service")
	case res := <-done:
		if res.err != nil {
			return nil, nil, shortACMEError(res.err)
		}
		return res.res.Certificate, res.res.PrivateKey, nil
	}
}

// shortACMEError trims lego's long wrapped errors to their last line.
func shortACMEError(err error) error {
	s := strings.TrimSpace(err.Error())
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return errors.New(s)
}

type slogWriter struct{ l *slog.Logger }

func (w *slogWriter) Write(b []byte) (int, error) {
	w.l.Info(strings.TrimSpace(string(b)))
	return len(b), nil
}

// RenewBefore is how long before expiry a Let's Encrypt certificate is
// renewed.
const RenewBefore = 30 * 24 * time.Hour

// NeedsCertificate reports whether certPEM is missing, close to expiry or
// doesn't list exactly the wanted names.
func NeedsCertificate(certPEM, keyPEM string, names []string, now time.Time) bool {
	if certPEM == "" {
		return true
	}
	c, err := Parse([]byte(certPEM), []byte(keyPEM), now)
	if err != nil || c.Leaf.NotAfter.Sub(now) < RenewBefore {
		return true
	}
	have := map[string]bool{}
	for _, n := range c.Leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	if len(have) != len(names) {
		return true
	}
	for _, n := range names {
		if !have[strings.ToLower(n)] {
			return true
		}
	}
	return false
}
