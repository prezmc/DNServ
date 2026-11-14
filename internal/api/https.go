package api

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/certs"
	"github.com/prezmc/dnserv/internal/store"
)

// NodeHTTPS is one server's dashboard HTTPS status.
type NodeHTTPS struct {
	Server string `json:"server"`
	certs.Status
	Unreachable string `json:"unreachable,omitempty"`
}

func (a *API) routesHTTPS(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/https", a.authed(store.PermUsers, a.httpsGet))
	m.HandleFunc("PUT /api/v1/https", a.authed(store.PermUsers, a.httpsPut))
	m.HandleFunc("POST /api/v1/https/npm/certificates", a.authed(store.PermUsers, a.httpsNPMList))
	m.HandleFunc("GET /api/v1/https/dns-hosts", a.authed(store.PermUsers, a.httpsDNSHosts))
}

// httpsView is the HTTPS settings without the key or password.
type httpsView struct {
	Mode       string    `json:"mode"`
	Redirect   bool      `json:"redirect"`
	Names      []string  `json:"names"`
	CertFile   string    `json:"cert_file,omitempty"`
	KeyFile    string    `json:"key_file,omitempty"`
	HasCert    bool      `json:"has_cert"`
	NPM        *npmView  `json:"npm,omitempty"`
	ACME       *acmeView `json:"acme,omitempty"`
	Fetched    time.Time `json:"fetched,omitzero"`
	FetchError string    `json:"fetch_error,omitempty"`
}

type npmView struct {
	URL         string `json:"url"`
	Email       string `json:"email"`
	HasPassword bool   `json:"has_password"`
	CertID      int    `json:"cert_id"`
	CertName    string `json:"cert_name,omitempty"`
}

// acmeView leaves out the DNS host's setting values (they hold its
// login) and the account key.
type acmeView struct {
	Method    string   `json:"method"`
	Email     string   `json:"email"`
	Names     []string `json:"names"`
	Directory string   `json:"directory"`
	Staging   bool     `json:"staging"`
	DNSHost   string   `json:"dns_host"`
	Saved     []string `json:"saved_settings"` // names of settings with a saved value
	Helper    string   `json:"helper,omitempty"`
	// Records are the records the owner adds: the helper's one-time
	// CNAMEs, or the TXT records a by-hand request is waiting for.
	Records []store.DNSRecord `json:"records"`
}

func (a *API) httpsGet(w http.ResponseWriter, r *http.Request, p *Principal) {
	h := a.Store.State().HTTPS
	v := httpsView{Mode: h.Mode, Redirect: h.Redirect, Names: h.Names, CertFile: h.CertFile, KeyFile: h.KeyFile,
		HasCert: h.CertPEM != "", Fetched: h.Fetched, FetchError: h.FetchError}
	if v.Names == nil {
		v.Names = []string{}
	}
	if n := h.NPM; n != nil {
		v.NPM = &npmView{URL: n.URL, Email: n.Email, HasPassword: n.Password != "", CertID: n.CertID, CertName: n.CertName}
	}
	if ac := h.ACME; ac != nil {
		av := &acmeView{Method: ac.Method, Helper: ac.Helper, Records: h.Waiting, Email: ac.Email, Names: ac.Names, Directory: ac.Directory, Staging: ac.Directory == store.LetsEncryptStaging,
			DNSHost: ac.DNSHost, Saved: []string{}}
		for k := range ac.DNSSettings {
			av.Saved = append(av.Saved, k)
		}
		slices.Sort(av.Saved)
		if ac.Method == store.ACMEDNSHelper {
			av.Records = certs.HelperCNAMEs(ac)
		}
		if av.Records == nil {
			av.Records = []store.DNSRecord{}
		}
		v.ACME = av
	}
	var nodes []NodeHTTPS
	if a.HTTPSStatus != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		nodes = a.HTTPSStatus(ctx)
		cancel()
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": v, "servers": nodes, "this_server_tls": r.TLS != nil})
}

type httpsIn struct {
	Mode     string   `json:"mode"`
	Redirect bool     `json:"redirect"`
	Names    []string `json:"names"`
	CertPEM  string   `json:"cert_pem"`
	KeyPEM   string   `json:"key_pem"`
	CertFile string   `json:"cert_file"`
	KeyFile  string   `json:"key_file"`
	NPM      *struct {
		URL      string `json:"url"`
		Email    string `json:"email"`
		Password string `json:"password"` // "": keep the saved one
		CertID   int    `json:"cert_id"`
	} `json:"npm"`
	ACME *struct {
		Method    string   `json:"method"`
		Helper    string   `json:"helper"`
		Email     string   `json:"email"`
		Names     []string `json:"names"`
		Staging   bool     `json:"staging"`
		Directory string   `json:"directory"` // "": Let's Encrypt (or its staging service)
		DNSHost   string   `json:"dns_host"`
		// DNSSettings: an empty value keeps the saved one for the same host.
		DNSSettings map[string]string `json:"dns_settings"`
	} `json:"acme"`
}

// npmFrom builds the NPM login from the request, keeping the saved
// password when none was sent and the address and email are unchanged.
func (a *API) npmFrom(url, email, password string) *certs.NPM {
	url, email = strings.TrimRight(strings.TrimSpace(url), "/"), strings.TrimSpace(email)
	if password == "" {
		if s := a.Store.State().HTTPS.NPM; s != nil && s.URL == url && strings.EqualFold(s.Email, email) {
			password = s.Password
		}
	}
	return &certs.NPM{URL: url, Email: email, Password: password}
}

func (a *API) httpsPut(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in httpsIn
	if !readJSON(w, r, &in) {
		return
	}
	cfg := store.HTTPSConfig{Mode: in.Mode, Redirect: in.Redirect}
	cur := a.Store.State().HTTPS
	now := time.Now()
	fail := func(err error) { writeErr(w, http.StatusBadRequest, err.Error()) }
	switch in.Mode {
	case store.HTTPSOff:
		cfg.Redirect = false
	case store.HTTPSSelfSigned:
		for _, n := range in.Names {
			if n = strings.TrimSpace(n); n != "" {
				if !validHostOrIP(n) {
					fail(errors.New(n + " isn't a host name or address"))
					return
				}
				cfg.Names = append(cfg.Names, strings.ToLower(n))
			}
		}
		// The name this page was opened with, so the certificate matches it.
		if host := hostOnly(r.Host); host != "" && validHostOrIP(host) && !containsFold(cfg.Names, host) {
			cfg.Names = append(cfg.Names, strings.ToLower(host))
		}
	case store.HTTPSUpload:
		cfg.CertPEM, cfg.KeyPEM = strings.TrimSpace(in.CertPEM)+"\n", strings.TrimSpace(in.KeyPEM)+"\n"
		if strings.TrimSpace(in.CertPEM) == "" && strings.TrimSpace(in.KeyPEM) == "" && cur.Mode == store.HTTPSUpload {
			cfg.CertPEM, cfg.KeyPEM = cur.CertPEM, cur.KeyPEM // keep the saved one
		}
		if _, err := certs.Parse([]byte(cfg.CertPEM), []byte(cfg.KeyPEM), now); err != nil {
			fail(err)
			return
		}
	case store.HTTPSFiles:
		cfg.CertFile, cfg.KeyFile = strings.TrimSpace(in.CertFile), strings.TrimSpace(in.KeyFile)
		if err := cfg.Validate(); err != nil {
			fail(err)
			return
		}
		c, k, err := certs.ReadFiles(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			fail(errors.New("This server " + err.Error() + ". Mount the folder into the container on this server, then try again"))
			return
		}
		if _, err := certs.Parse(c, k, now); err != nil {
			fail(err)
			return
		}
		cfg.CertPEM, cfg.KeyPEM = string(c), string(k)
	case store.HTTPSNPM:
		if in.NPM == nil || in.NPM.CertID <= 0 {
			fail(errors.New("choose a certificate from Nginx Proxy Manager"))
			return
		}
		n := a.npmFrom(in.NPM.URL, in.NPM.Email, in.NPM.Password)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		list, err := n.List(ctx)
		if err != nil {
			fail(err)
			return
		}
		name := ""
		for _, c := range list {
			if c.ID == in.NPM.CertID {
				name = c.Name
			}
		}
		c, k, err := n.Download(ctx, in.NPM.CertID)
		if err == nil {
			_, err = certs.Parse(c, k, now)
		}
		if err != nil {
			fail(err)
			return
		}
		cfg.CertPEM, cfg.KeyPEM = string(c), string(k)
		cfg.NPM = &store.NPMSource{URL: n.URL, Email: n.Email, Password: n.Password, CertID: in.NPM.CertID, CertName: name}
	case store.HTTPSACME:
		ac, err := a.acmeFrom(r.Context(), in, cur, now)
		if err != nil {
			fail(err)
			return
		}
		cfg.ACME = ac
		if cur.Mode == store.HTTPSACME && cur.ACME != nil && cur.ACME.Directory == ac.Directory &&
			!certs.NeedsCertificate(cur.CertPEM, cur.KeyPEM, ac.Names, now) {
			// Still good for these names, from the same service (a test-run
			// certificate is never kept once Test run is off).
			cfg.CertPEM, cfg.KeyPEM = cur.CertPEM, cur.KeyPEM
		}
	}
	if err := cfg.Validate(); err != nil {
		fail(err)
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpHTTPSConfig, p.Actor(), cfg)); !ok {
		return
	}
	a.httpsGet(w, r, p)
}

// acmeFrom checks the Let's Encrypt settings from the request and tries
// the DNS host login by adding and removing a TXT record for each name.
func (a *API) acmeFrom(ctx context.Context, in httpsIn, cur store.HTTPSConfig, now time.Time) (*store.ACMESource, error) {
	if in.ACME == nil {
		return nil, errors.New("fill in the Let's Encrypt settings")
	}
	src := &store.ACMESource{Method: in.ACME.Method, Email: strings.TrimSpace(in.ACME.Email), Saved: now}
	if src.Email != "" && (!strings.Contains(src.Email, "@") || strings.ContainsAny(src.Email, " <>")) {
		return nil, errors.New(src.Email + " isn't an email address")
	}
	for _, n := range in.ACME.Names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" || slices.Contains(src.Names, n) {
			continue
		}
		if strings.HasPrefix(n, "*") {
			return nil, errors.New("list each name, such as dns1.example.com, rather than a wildcard")
		}
		if net.ParseIP(n) != nil || !validHostOrIP(n) || !strings.Contains(n, ".") {
			return nil, errors.New(n + " isn't a full host name such as dns1.example.com")
		}
		src.Names = append(src.Names, n)
	}
	if len(src.Names) == 0 {
		return nil, errors.New("add at least one name, such as dns1.example.com")
	}
	switch d := strings.TrimSpace(in.ACME.Directory); {
	case d != "":
		src.Directory = d
	case in.ACME.Staging:
		src.Directory = store.LetsEncryptStaging
	default:
		src.Directory = store.LetsEncrypt
	}
	var saved *store.ACMESource
	if cur.Mode == store.HTTPSACME && cur.ACME != nil {
		saved = cur.ACME
	}
	var err error
	if saved != nil && saved.AccountKey != "" && saved.Directory == src.Directory {
		src.AccountKey = saved.AccountKey
	} else if src.AccountKey, err = certs.NewAccountKey(); err != nil {
		return nil, err
	}
	tctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	switch src.Method {
	case store.ACMEDNSAPI:
		src.DNSHost = in.ACME.DNSHost
		settings := map[string]string{}
		if saved != nil && saved.Method == store.ACMEDNSAPI && saved.DNSHost == src.DNSHost {
			maps.Copy(settings, saved.DNSSettings)
		}
		for k, v := range in.ACME.DNSSettings {
			if strings.TrimSpace(v) != "" {
				settings[k] = v
			}
		}
		if src.DNSSettings, err = certs.CleanDNSSettings(src.DNSHost, settings); err != nil {
			return nil, err
		}
		if err := testDNSHost(tctx, src.DNSHost, src.DNSSettings, src.Names); err != nil {
			return nil, errors.New("Couldn't use your DNS host: " + err.Error())
		}
	case store.ACMEDNSHelper:
		src.Helper = strings.TrimRight(strings.TrimSpace(in.ACME.Helper), "/")
		if src.Helper == "" {
			src.Helper = certs.DefaultHelper
		}
		if u, err := url.Parse(src.Helper); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("the acme-dns server should be an https:// address")
		}
		// Keep accounts already made there, so CNAMEs added earlier
		// still work; make one for each new name.
		src.HelperAccounts = map[string]store.HelperAccount{}
		for _, n := range src.Names {
			if saved != nil && saved.Helper == src.Helper {
				if acc, ok := saved.HelperAccounts[n]; ok {
					src.HelperAccounts[n] = acc
					continue
				}
			}
			acc, err := registerHelper(tctx, src.Helper)
			if err != nil {
				return nil, err
			}
			src.HelperAccounts[n] = acc
		}
	case store.ACMEManual:
	default:
		return nil, errors.New("choose how DNServ proves you own the names")
	}
	return src, nil
}

// Replaced in tests.
var (
	testDNSHost    = certs.TestDNSHost
	registerHelper = certs.RegisterHelper
)

func (a *API) httpsDNSHosts(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"hosts": certs.DNSHosts()})
}

func (a *API) httpsNPMList(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		URL      string `json:"url"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n := a.npmFrom(in.URL, in.Email, in.Password)
	probe := store.HTTPSConfig{Mode: store.HTTPSNPM, NPM: &store.NPMSource{URL: n.URL, Email: n.Email, Password: n.Password, CertID: 1}}
	if err := probe.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	list, err := n.List(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": list})
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostport, "[]")
}

func validHostOrIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) > 253 || s == "" {
		return false
	}
	for _, label := range strings.Split(strings.TrimPrefix(s, "*."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	return true
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
