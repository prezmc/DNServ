package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
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
	acmeEvery     = 12 * time.Hour
	// After a failed Let's Encrypt request; kept well under its limit of
	// five failed checks per name per hour.
	acmeRetry = []time.Duration{30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour}
	// acmeObtain is replaced in tests.
	acmeObtain = Obtain
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
	// ProposeWait shares the records a by-hand request waits for.
	ProposeWait func(store.HTTPSWait) error
	Log         *slog.Logger
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
	// Requesting is set while this server asks Let's Encrypt for a
	// certificate.
	Requesting bool `json:"requesting,omitempty"`
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
	st.Requesting = m.status.Requesting
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
	if (a.NPM == nil) != (b.NPM == nil) || (a.ACME == nil) != (b.ACME == nil) {
		return false
	}
	if a.ACME != nil && !reflect.DeepEqual(*a.ACME, *b.ACME) {
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
	kick <- struct{}{} // check once straight away
	t := time.NewTicker(filesEvery)
	defer t.Stop()
	var nextNPM, nextACME time.Time
	acmeFails := 0
	var stopACME context.CancelFunc // a request in progress
	acmeDone := make(chan bool, 1)
	defer func() {
		if stopACME != nil {
			stopACME()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			nextNPM, nextACME, acmeFails = time.Time{}, time.Time{}, 0
			if stopACME != nil {
				stopACME() // the settings changed: start again with the new ones
				<-acmeDone
				stopACME = nil
			}
		case ok := <-acmeDone:
			stopACME()
			stopACME = nil
			if ok {
				acmeFails = 0
				nextACME = time.Now().Add(acmeEvery)
			} else {
				nextACME = time.Now().Add(acmeRetry[min(acmeFails, len(acmeRetry)-1)])
				acmeFails++
			}
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
		case store.HTTPSACME:
			if stopACME == nil && time.Now().After(nextACME) && m.IsLeader != nil && m.IsLeader() {
				stopACME = m.startACME(ctx, cfg, acmeDone)
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

// startACME runs checkACME in the background; done gets its result.
func (m *Manager) startACME(ctx context.Context, cfg store.HTTPSConfig, done chan<- bool) context.CancelFunc {
	actx, cancel := context.WithCancel(ctx)
	go func() { done <- m.checkACME(actx, cfg) }()
	return cancel
}

// checkACME asks Let's Encrypt for a certificate when there is none yet,
// it is within 30 days of expiry, or the names changed. It reports
// whether the cluster has a good certificate afterwards.
func (m *Manager) checkACME(ctx context.Context, cfg store.HTTPSConfig) bool {
	a := cfg.ACME
	if a == nil {
		return true
	}
	if !NeedsCertificate(cfg.CertPEM, cfg.KeyPEM, a.Names, time.Now()) {
		if cfg.FetchError != "" {
			m.propose(store.HTTPSCert{Mode: cfg.Mode, CertPEM: cfg.CertPEM, KeyPEM: cfg.KeyPEM})
		}
		return true
	}
	m.setRequesting(true)
	defer m.setRequesting(false)
	m.logger().Info("asking for a certificate", "names", strings.Join(a.Names, ","), "directory", a.Directory)
	limit := 10 * time.Minute
	if a.Method != store.ACMEDNSAPI {
		limit = waitForRecords + 10*time.Minute // waits for the owner's records
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req := ACMERequest{ACMESource: *a, Log: m.logger()}
	req.Publish = func(recs []store.DNSRecord) {
		if m.ProposeWait != nil {
			if err := m.ProposeWait(store.HTTPSWait{Mode: cfg.Mode, Records: recs}); err != nil {
				m.logger().Warn("sharing the records to add", "err", err)
			}
		}
	}
	c, k, err := acmeObtain(ctx, req)
	if ctx.Err() != nil && errors.Is(context.Cause(ctx), context.Canceled) {
		return false // called off: the settings changed
	}
	if err == nil {
		_, err = Parse(c, k, time.Now())
	}
	if err != nil {
		m.logger().Warn("let's encrypt certificate", "err", err)
		m.propose(store.HTTPSCert{Mode: cfg.Mode, Error: "Let's Encrypt: " + err.Error()})
		return false
	}
	m.logger().Info("got a certificate", "names", strings.Join(a.Names, ","))
	m.propose(store.HTTPSCert{Mode: cfg.Mode, CertPEM: string(c), KeyPEM: string(k)})
	return true
}

func (m *Manager) setRequesting(on bool) {
	m.mu.Lock()
	m.status.Requesting = on
	m.mu.Unlock()
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
