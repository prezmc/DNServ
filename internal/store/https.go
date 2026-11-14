package store

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// HTTPS modes for the dashboard.
const (
	HTTPSOff        = ""            // plain HTTP only (the default)
	HTTPSSelfSigned = "self_signed" // each node makes its own certificate
	HTTPSUpload     = "upload"      // a certificate and key pasted in
	HTTPSFiles      = "files"       // files in a mounted folder, re-read when they change
	HTTPSNPM        = "npm"         // downloaded from Nginx Proxy Manager
	HTTPSACME       = "acme"        // requested from Let's Encrypt by DNServ itself
)

// HTTPSConfig is how the dashboard does HTTPS. It is kept apart from
// Settings, so the private key and the proxy password are never in
// settings history, backups or the audit log, and the API never returns
// them.
type HTTPSConfig struct {
	Mode string `json:"mode,omitempty"`
	// Redirect sends browsers that open the dashboard over plain HTTP to
	// HTTPS. The API, /healthz and /metrics are never redirected.
	Redirect bool `json:"redirect,omitempty"`
	// Names are extra host names or addresses for self-signed
	// certificates, on top of each node's own.
	Names []string `json:"names,omitempty"`
	// CertPEM and KeyPEM are the certificate (with its chain) and key in
	// use for upload, files and npm modes. In files and npm modes they are
	// the latest copy a node fetched, so nodes that can't reach the source
	// still have it.
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
	// CertFile and KeyFile are paths inside the container (files mode).
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// NPM is the Nginx Proxy Manager to download from (npm mode).
	NPM *NPMSource `json:"npm,omitempty"`
	// ACME is the Let's Encrypt account and DNS login (acme mode).
	ACME *ACMESource `json:"acme,omitempty"`
	// Waiting lists TXT records a by-hand Let's Encrypt request is
	// waiting for, until they show up or the request ends.
	Waiting []DNSRecord `json:"waiting,omitempty"`
	// Fetched is when CertPEM last changed; FetchError is the last
	// failure to refresh it ("" when the last try worked).
	Fetched    time.Time `json:"fetched,omitzero"`
	FetchError string    `json:"fetch_error,omitempty"`
}

// NPMSource is an Nginx Proxy Manager login and the certificate to use.
type NPMSource struct {
	URL      string `json:"url"` // its admin address, such as http://192.168.1.10:81
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	CertID   int    `json:"cert_id"`
	CertName string `json:"cert_name,omitempty"`
}

// ACMESource is how DNServ gets its own certificate from Let's Encrypt
// (or another ACME service), proving it owns the names with DNS TXT
// records (the DNS-01 challenge) made through the DNS host's API. One
// certificate lists every name, and the leader requests and renews it for
// the whole cluster, so any server can take over.
type ACMESource struct {
	// Method is how the TXT records get made: ACMEDNSAPI (through the
	// DNS host's API), ACMEDNSHelper (a one-time CNAME to an acme-dns
	// server) or ACMEManual (the owner adds them by hand).
	Method    string   `json:"method"`
	Email     string   `json:"email"`
	Names     []string `json:"names"`     // exact names, such as dns1.example.com (no wildcards)
	Directory string   `json:"directory"` // ACME directory URL
	DNSHost   string   `json:"dns_host"`  // lego's code for the DNS host, such as "cloudflare"
	// DNSSettings are the DNS host's login and options, by lego's
	// environment variable names (such as CF_DNS_API_TOKEN). Secret.
	DNSSettings map[string]string `json:"dns_settings,omitempty"`
	// Helper is the acme-dns server and the account made there for each
	// name (helper method). Secret.
	Helper         string                   `json:"helper,omitempty"`
	HelperAccounts map[string]HelperAccount `json:"helper_accounts,omitempty"`
	// AccountKey is the ACME account's private key (PEM), made when the
	// mode is first saved and shared so any server can renew.
	AccountKey string `json:"account_key,omitempty"`
	// Saved changes on every save, so saving again asks for a certificate
	// straight away.
	Saved time.Time `json:"saved,omitzero"`
}

// HelperAccount is an acme-dns account for one name.
type HelperAccount struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"` // the CNAME target
}

// DNSRecord is a record the owner is asked to add.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACME methods.
const (
	ACMEDNSAPI    = "dns_api"
	ACMEDNSHelper = "helper"
	ACMEManual    = "manual"
)

// ACME directories and DNS hosts.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// HTTPS ops.
const (
	OpHTTPSConfig = "https.config" // HTTPSConfig (admin)
	OpHTTPSCert   = "https.cert"   // HTTPSCert (a node fetched a renewed certificate)
	OpHTTPSWait   = "https.wait"   // HTTPSWait (a by-hand request needs records)
)

// HTTPSWait sets the records a by-hand Let's Encrypt request waits for.
type HTTPSWait struct {
	Mode    string      `json:"mode"`
	Records []DNSRecord `json:"records"`
}

// HTTPSCert updates the certificate fetched for files or npm mode. Mode
// must match the current mode, so a late update can't undo a change.
type HTTPSCert struct {
	Mode    string `json:"mode"`
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
	Error   string `json:"error,omitempty"` // set instead of the PEMs when fetching failed
}

// Validate checks the parts each mode needs. It doesn't parse the
// certificate; the API does that before proposing.
func (h HTTPSConfig) Validate() error {
	switch h.Mode {
	case HTTPSOff, HTTPSSelfSigned:
	case HTTPSUpload:
		if h.CertPEM == "" || h.KeyPEM == "" {
			return fmt.Errorf("paste a certificate and its private key")
		}
	case HTTPSFiles:
		if !strings.HasPrefix(h.CertFile, "/") || !strings.HasPrefix(h.KeyFile, "/") {
			return fmt.Errorf("the certificate and key files need full paths inside the container, such as /certs/fullchain.pem")
		}
	case HTTPSNPM:
		n := h.NPM
		if n == nil || n.URL == "" || n.Email == "" || n.Password == "" || n.CertID <= 0 {
			return fmt.Errorf("Nginx Proxy Manager needs its address, a login and a certificate")
		}
		u, err := url.Parse(n.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("the Nginx Proxy Manager address should look like http://192.168.1.10:81")
		}
	case HTTPSACME:
		a := h.ACME
		if a == nil || len(a.Names) == 0 {
			return fmt.Errorf("Let's Encrypt needs at least one name, such as dns1.example.com")
		}
		if len(a.Names) > 20 {
			return fmt.Errorf("too many names (20 at most)")
		}
		for _, n := range a.Names {
			if strings.HasPrefix(n, "*") {
				return fmt.Errorf("list each name rather than a wildcard such as %s", n)
			}
		}
		if a.AccountKey == "" {
			return fmt.Errorf("the ACME account key is missing")
		}
		switch a.Method {
		case ACMEDNSAPI:
			if a.DNSHost == "" {
				return fmt.Errorf("choose your DNS host")
			}
		case ACMEDNSHelper:
			for _, n := range a.Names {
				if _, ok := a.HelperAccounts[n]; !ok {
					return fmt.Errorf("no acme-dns account for %s", n)
				}
			}
		case ACMEManual:
		default:
			return fmt.Errorf("unknown way to make the DNS records %q", a.Method)
		}
		if u, err := url.Parse(a.Directory); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("the ACME directory should be an https:// address")
		}
	default:
		return fmt.Errorf("unknown HTTPS mode %q", h.Mode)
	}
	return nil
}

// HTTPSModeName is how the audit log names each mode.
var HTTPSModeName = map[string]string{
	HTTPSOff:        "off",
	HTTPSSelfSigned: "self-signed",
	HTTPSUpload:     "an uploaded certificate",
	HTTPSFiles:      "certificate files",
	HTTPSNPM:        "Nginx Proxy Manager",
	HTTPSACME:       "Let's Encrypt",
}

func applyHTTPS(st *State, c Command, dec func(any) error) (any, *AuditEntry, error) {
	switch c.Op {
	case OpHTTPSConfig:
		var d HTTPSConfig
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if err := d.Validate(); err != nil {
			return nil, nil, err
		}
		if d.Mode != HTTPSNPM {
			d.NPM = nil
		}
		if d.Mode != HTTPSACME {
			d.ACME = nil
		}
		if d.Mode != HTTPSSelfSigned {
			d.Names = nil
		}
		if len(d.Names) > 20 {
			return nil, nil, fmt.Errorf("too many names")
		}
		if d.Mode != HTTPSFiles {
			d.CertFile, d.KeyFile = "", ""
		}
		if d.Mode == HTTPSOff || d.Mode == HTTPSSelfSigned {
			d.CertPEM, d.KeyPEM = "", ""
		}
		d.Waiting = nil
		if d.CertPEM != "" && d.CertPEM != st.HTTPS.CertPEM {
			d.Fetched = c.Time
		} else {
			d.Fetched = st.HTTPS.Fetched
		}
		st.HTTPS = d
		summary := "set dashboard HTTPS to " + HTTPSModeName[d.Mode]
		if d.Mode != HTTPSOff && d.Redirect {
			summary += ", sending HTTP to HTTPS"
		}
		return nil, audit(summary, nil, nil), nil

	case OpHTTPSCert:
		var d HTTPSCert
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if d.Mode != st.HTTPS.Mode || (d.Mode != HTTPSFiles && d.Mode != HTTPSNPM && d.Mode != HTTPSACME) {
			return nil, nil, nil // the mode changed since; ignore
		}
		st.HTTPS.Waiting = nil
		if d.Error != "" {
			st.HTTPS.FetchError = d.Error
			return nil, nil, nil
		}
		st.HTTPS.FetchError = ""
		if d.CertPEM == st.HTTPS.CertPEM && d.KeyPEM == st.HTTPS.KeyPEM {
			return nil, nil, nil
		}
		st.HTTPS.CertPEM, st.HTTPS.KeyPEM, st.HTTPS.Fetched = d.CertPEM, d.KeyPEM, c.Time
		return nil, audit("picked up a renewed dashboard certificate", nil, nil), nil

	case OpHTTPSWait:
		var d HTTPSWait
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if d.Mode != st.HTTPS.Mode || d.Mode != HTTPSACME {
			return nil, nil, nil
		}
		st.HTTPS.Waiting = d.Records
		return nil, nil, nil
	}
	return nil, nil, fmt.Errorf("unknown command %q", c.Op)
}
