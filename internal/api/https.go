package api

import (
	"context"
	"errors"
	"net"
	"net/http"
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
