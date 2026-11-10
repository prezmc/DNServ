package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// How often sources are checked for a renewed certificate.
var (
	filesEvery    = time.Minute
	npmEvery      = 12 * time.Hour
	npmRetryEvery = 15 * time.Minute
)

// Manager keeps the dashboard certificate in line with the replicated
// HTTPS settings: it turns HTTPS on and off, makes self-signed
// certificates, and watches files and Nginx Proxy Manager for renewals.
type Manager struct {
	Holder   Holder
	DataDir  string
	Names    func() []string // this node's own names, for self-signed certificates
	IsLeader func() bool
	// Propose sends a renewed certificate (or a fetch error) to the cluster.
	Propose func(store.HTTPSCert) error
	Log     *slog.Logger
	// Off forces HTTPS off whatever the settings say (DNSERV_HTTPS=off),
	// for getting back in after a bad certificate.
	Off bool

	mu       sync.Mutex
	cfg      store.HTTPSConfig
	listener *Listener
	status   Status
	redirect atomic.Bool
	kick     chan struct{}
	lastFile []byte // files mode: what the cert file held when last read
}

// Status is what the dashboard shows about HTTPS on this node.
type Status struct {
	Mode   string `json:"mode"`
	On     bool   `json:"on"`
	Cert   *Info  `json:"cert,omitempty"`
	Error  string `json:"error,omitempty"`  // why the configured certificate isn't in use
	Forced bool   `json:"forced,omitempty"` // turned off by DNSERV_HTTPS=off
}

// Attach gives the manager the dashboard's listener to switch.
func (m *Manager) Attach(l *Listener) {
	m.mu.Lock()
	m.listener = l
	m.mu.Unlock()
	m.Apply(m.current())
}

func (m *Manager) current() store.HTTPSConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Redirect reports whether plain HTTP page loads should go to HTTPS.
func (m *Manager) Redirect() bool { return m.redirect.Load() }

// Status returns this node's HTTPS status.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Apply puts cfg into effect. It is cheap when nothing changed.
func (m *Manager) Apply(cfg store.HTTPSConfig) {
	m.mu.Lock()
	changed := !sameSource(m.cfg, cfg)
	m.cfg = cfg
	if changed {
		m.lastFile = nil
	}
	m.mu.Unlock()

	st := Status{Mode: cfg.Mode}
	var cert *tls.Certificate
	var err error
	switch {
	case m.Off:
		st.Forced = true
	case cfg.Mode == store.HTTPSOff:
	case cfg.Mode == store.HTTPSSelfSigned:
		cert, err = m.selfSigned(cfg.Names)
	default:
		cert, err = m.fromState(cfg)
		if err != nil && cfg.FetchError != "" {
			err = errorString(cfg.FetchError)
		}
		if cert == nil {
			// Keep HTTPS working with a self-signed certificate while the
			// real one can't be had, so a redirect never leads nowhere.
			if ss, e := m.selfSigned(nil); e == nil {
				cert = ss
			}
		}
	}
	if err != nil {
		st.Error = err.Error()
		m.logger().Warn("dashboard https certificate", "mode", cfg.Mode, "err", err)
	} else if cfg.FetchError != "" {
		st.Error = cfg.FetchError
	}
	on := cert != nil
	if on {
		in := Describe(cert)
		st.Cert = &in
		m.Holder.Set(cert)
	}
	st.On = on
	m.redirect.Store(on && cfg.Redirect)
	m.mu.Lock()
	m.status = st
	l := m.listener
	m.mu.Unlock()
	if l != nil && l.TLS() != on {
		l.SetTLS(on)
		if on {
			m.logger().Info("dashboard https on", "mode", cfg.Mode, "sha256", st.Cert.Fingerprint)
		} else {
			m.logger().Info("dashboard https off")
		}
	}
	if changed {
		m.poke()
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func sameSource(a, b store.HTTPSConfig) bool {
	if a.Mode != b.Mode || a.CertFile != b.CertFile || a.KeyFile != b.KeyFile {
		return false
	}
	if (a.NPM == nil) != (b.NPM == nil) {
		return false
	}
	return a.NPM == nil || *a.NPM == *b.NPM
}

func (m *Manager) logger() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) selfSigned(extra []string) (*tls.Certificate, error) {
	var names []string
	if m.Names != nil {
		names = m.Names()
	}
	return SelfSigned(filepath.Join(m.DataDir, "tls"), append(names, extra...))
}

// fromState uses the replicated certificate, or in files mode this node's
// own copy of the files when they hold a newer one.
func (m *Manager) fromState(cfg store.HTTPSConfig) (*tls.Certificate, error) {
	var best *tls.Certificate
	var err error
	if cfg.CertPEM != "" {
		best, err = Parse([]byte(cfg.CertPEM), []byte(cfg.KeyPEM), time.Now())
	} else {
		err = errorString("no certificate yet")
	}
	if cfg.Mode == store.HTTPSFiles {
		if local, lerr := readFiles(cfg); lerr == nil && newer(local, best) {
			return local, nil
		} else if best == nil && lerr != nil {
			err = lerr
		}
	}
	return best, err
}

func newer(a, b *tls.Certificate) bool {
	return b == nil || a.Leaf.NotAfter.After(b.Leaf.NotAfter)
}

func readFiles(cfg store.HTTPSConfig) (*tls.Certificate, error) {
	c, k, err := ReadFiles(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return Parse(c, k, time.Now())
}

// ReadFiles reads a certificate and key from disk.
func ReadFiles(certFile, keyFile string) (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		return nil, nil, errorString("can't read the certificate file: " + err.Error())
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, errorString("can't read the key file: " + err.Error())
	}
	return certPEM, keyPEM, nil
}

func (m *Manager) poke() {
	m.mu.Lock()
	k := m.kick
	m.mu.Unlock()
	if k != nil {
		select {
		case k <- struct{}{}:
		default:
		}
	}
}

// Run watches for renewed certificates until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.kick = make(chan struct{}, 1)
	kick := m.kick
	m.mu.Unlock()
	t := time.NewTicker(filesEvery)
	defer t.Stop()
	var nextNPM time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			nextNPM = time.Time{}
		case <-t.C:
		}
		cfg := m.current()
		switch cfg.Mode {
		case store.HTTPSFiles:
			m.checkFiles(cfg)
		case store.HTTPSNPM:
			if time.Now().After(nextNPM) && m.IsLeader != nil && m.IsLeader() {
				if m.checkNPM(ctx, cfg) {
					nextNPM = time.Now().Add(npmEvery)
				} else {
					nextNPM = time.Now().Add(npmRetryEvery)
				}
			}
		}
	}
}

// checkFiles re-reads the files when they changed and shares a renewed
// certificate with the cluster.
func (m *Manager) checkFiles(cfg store.HTTPSConfig) {
	c, k, err := ReadFiles(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		// Another node may have the files; only complain when nobody has
		// supplied a certificate.
		if cfg.CertPEM == "" && cfg.FetchError != err.Error() && m.IsLeader != nil && m.IsLeader() {
			m.propose(store.HTTPSCert{Mode: cfg.Mode, Error: err.Error()})
		}
		return
	}
	m.mu.Lock()
	same := bytes.Equal(c, m.lastFile)
	m.lastFile = c
	m.mu.Unlock()
	if same && cfg.FetchError == "" {
		return
	}
	cert, err := Parse(c, k, time.Now())
	if err != nil {
		if cfg.FetchError != err.Error() {
			m.propose(store.HTTPSCert{Mode: cfg.Mode, Error: err.Error()})
		}
		return
	}
	var cur *tls.Certificate
	if cfg.CertPEM != "" {
		cur, _ = Parse([]byte(cfg.CertPEM), []byte(cfg.KeyPEM), time.Now())
	}
	if string(c) == cfg.CertPEM && string(k) == cfg.KeyPEM {
		if cfg.FetchError != "" {
			m.propose(store.HTTPSCert{Mode: cfg.Mode, CertPEM: cfg.CertPEM, KeyPEM: cfg.KeyPEM})
		}
		return
	}
	if !newer(cert, cur) && cur != nil {
		return // older than what the cluster has; don't flip back and forth
	}
	m.logger().Info("dashboard certificate files changed", "sha256", Describe(cert).Fingerprint)
	m.propose(store.HTTPSCert{Mode: cfg.Mode, CertPEM: string(c), KeyPEM: string(k)})
}

// checkNPM downloads the certificate from Nginx Proxy Manager. It reports
// whether that worked.
func (m *Manager) checkNPM(ctx context.Context, cfg store.HTTPSConfig) bool {
	n := cfg.NPM
	if n == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c, k, err := (&NPM{URL: n.URL, Email: n.Email, Password: n.Password}).Download(ctx, n.CertID)
	if err == nil {
		_, err = Parse(c, k, time.Now())
	}
	if err != nil {
		m.logger().Warn("nginx proxy manager certificate", "err", err)
		if cfg.FetchError != err.Error() {
			m.propose(store.HTTPSCert{Mode: cfg.Mode, Error: err.Error()})
		}
		return false
	}
	if string(c) != cfg.CertPEM || string(k) != cfg.KeyPEM || cfg.FetchError != "" {
		m.propose(store.HTTPSCert{Mode: cfg.Mode, CertPEM: string(c), KeyPEM: string(k)})
	}
	return true
}

func (m *Manager) propose(c store.HTTPSCert) {
	if m.Propose == nil {
		return
	}
	if err := m.Propose(c); err != nil {
		m.logger().Warn("sharing dashboard certificate", "err", err)
	}
}

// DNSCertificate returns the dashboard certificate for DNS over TLS and
// HTTPS when it is a trusted (not self-signed) one, else fallback.
func (m *Manager) DNSCertificate(fallback *tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.mu.Lock()
		st := m.status
		m.mu.Unlock()
		if st.On && st.Cert != nil && !st.Cert.SelfSigned {
			if c := m.Holder.Get(); c != nil {
				return c, nil
			}
		}
		return fallback, nil
	}
}

// RedirectHTTPS sends plain-HTTP page loads to HTTPS on the same host and
// port while the manager says so. Requests a proxy already terminated TLS
// for, the API, health checks and metrics pass through.
func (m *Manager) RedirectHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil && m.redirect.Load() && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			r.Header.Get("X-Forwarded-Proto") == "" && r.Host != "" && !noRedirect(r.URL.Path) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func noRedirect(p string) bool {
	switch p {
	case "/healthz", "/readyz", "/metrics":
		return true
	}
	return strings.HasPrefix(p, "/api/")
}
