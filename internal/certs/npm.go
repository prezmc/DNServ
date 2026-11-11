package certs

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// NPM talks to an Nginx Proxy Manager admin API: sign in, list
// certificates, download one.
type NPM struct {
	URL      string // admin address, such as http://192.168.1.10:81
	Email    string
	Password string
	Client   *http.Client // nil: a client with a 20 s timeout
}

// NPMCert is a certificate as Nginx Proxy Manager lists it.
type NPMCert struct {
	ID       int       `json:"id"`
	Name     string    `json:"name"`
	Domains  []string  `json:"domains"`
	Provider string    `json:"provider"` // "letsencrypt" or "other"
	Expires  time.Time `json:"expires,omitzero"`
}

func (n *NPM) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (n *NPM) base() string { return strings.TrimRight(n.URL, "/") }

// ErrNPMLogin means Nginx Proxy Manager turned down the email and password.
var ErrNPMLogin = errors.New("Nginx Proxy Manager didn't accept that email and password")

func (n *NPM) token(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{"identity": n.Email, "secret": n.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base()+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("couldn't reach Nginx Proxy Manager: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadRequest {
		return "", ErrNPMLogin
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Nginx Proxy Manager sign-in: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token       string `json:"token"`
		Requires2FA bool   `json:"requires_2fa"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("Nginx Proxy Manager sign-in: %w (is this its admin address?)", err)
	}
	if out.Requires2FA {
		return "", errors.New("that Nginx Proxy Manager user has two-factor sign-in; make a separate user without it for DNServ")
	}
	if out.Token == "" {
		return "", ErrNPMLogin
	}
	return out.Token, nil
}

func (n *NPM) get(ctx context.Context, tok, p string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.base()+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := n.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return b, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, errors.New("that Nginx Proxy Manager user isn't allowed to see certificates")
	case http.StatusNotFound:
		return nil, errors.New("Nginx Proxy Manager doesn't have that certificate, or is too old to download certificates (update it to 2.10 or later)")
	}
	return nil, fmt.Errorf("Nginx Proxy Manager: HTTP %d", resp.StatusCode)
}

// List returns Nginx Proxy Manager's certificates.
func (n *NPM) List(ctx context.Context) ([]NPMCert, error) {
	tok, err := n.token(ctx)
	if err != nil {
		return nil, err
	}
	b, err := n.get(ctx, tok, "/api/nginx/certificates", 4<<20)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID          int      `json:"id"`
		NiceName    string   `json:"nice_name"`
		DomainNames []string `json:"domain_names"`
		Provider    string   `json:"provider"`
		ExpiresOn   string   `json:"expires_on"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("Nginx Proxy Manager certificates: %w", err)
	}
	out := make([]NPMCert, 0, len(raw))
	for _, r := range raw {
		c := NPMCert{ID: r.ID, Name: r.NiceName, Domains: r.DomainNames, Provider: r.Provider}
		for _, layout := range []string{time.DateTime, time.RFC3339} {
			if t, err := time.Parse(layout, r.ExpiresOn); err == nil {
				c.Expires = t
				break
			}
		}
		if c.Name == "" && len(c.Domains) > 0 {
			c.Name = c.Domains[0]
		}
		out = append(out, c)
	}
	return out, nil
}

// Download fetches certificate id and returns its chain and key as PEM.
func (n *NPM) Download(ctx context.Context, id int) (certPEM, keyPEM []byte, err error) {
	tok, err := n.token(ctx)
	if err != nil {
		return nil, nil, err
	}
	b, err := n.get(ctx, tok, fmt.Sprintf("/api/nginx/certificates/%d/download", id), 1<<20)
	if err != nil {
		return nil, nil, err
	}
	return FromZip(b)
}

// FromZip picks the certificate chain and private key out of a zip of PEM
// files, as Nginx Proxy Manager's download gives: fullchain*.pem (or
// cert*.pem plus chain*.pem) and privkey*.pem.
func FromZip(b []byte) (certPEM, keyPEM []byte, err error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, nil, fmt.Errorf("the download isn't a zip file: %w", err)
	}
	var full, cert, chain []byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > 256<<10 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, 256<<10))
		rc.Close()
		if err != nil {
			return nil, nil, err
		}
		name := strings.ToLower(path.Base(f.Name))
		switch {
		case bytes.Contains(data, []byte("PRIVATE KEY-----")):
			keyPEM = data
		case !bytes.Contains(data, []byte("BEGIN CERTIFICATE")):
		case strings.HasPrefix(name, "fullchain"):
			full = data
		case strings.HasPrefix(name, "chain"):
			chain = data
		default:
			cert = data
		}
	}
	switch {
	case full != nil:
		certPEM = full
	case cert != nil:
		certPEM = append(append(cert, '\n'), chain...)
	}
	if certPEM == nil || keyPEM == nil {
		return nil, nil, errors.New("the download didn't have both a certificate and a private key")
	}
	return certPEM, keyPEM, nil
}
