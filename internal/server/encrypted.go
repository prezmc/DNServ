package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/config"
)

// LoadOrCreateCert loads the configured certificate, or a self-signed one
// from dataDir/tls, creating it (valid two years) when missing or within
// 30 days of expiry. It returns the SHA-256 fingerprint of the leaf so the
// UI can show it for pinning.
func LoadOrCreateCert(c config.TLSConfig, dataDir string) (tls.Certificate, string, bool, error) {
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return cert, "", false, fmt.Errorf("load TLS certificate: %w", err)
		}
		return cert, fingerprint(cert), false, nil
	}
	dir := filepath.Join(dataDir, "tls")
	certPath, keyPath := filepath.Join(dir, "self-signed.crt"), filepath.Join(dir, "self-signed.key")
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
			return cert, fingerprint(cert), true, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", true, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", true, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstOr(c.Hostnames, "dnserv.local"), Organization: []string{"DNServ self-signed"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range c.Hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", true, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", true, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return tls.Certificate{}, "", true, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, "", true, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	return cert, fingerprint(cert), true, err
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}

func fingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// StartEncrypted serves DNS over TLS and DNS over HTTPS on the configured
// addresses.
// When pick is set, it chooses the certificate for each connection
// instead.
func (s *Server) StartEncrypted(cert tls.Certificate, pick func(*tls.ClientHelloInfo) (*tls.Certificate, error)) error {
	tc := s.cfg.DNS.TLS
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if pick != nil {
		base.Certificates, base.GetCertificate = nil, pick
	}

	for _, addr := range tc.DoTListen {
		ln, err := tls.Listen("tcp", addr, base.Clone())
		if err != nil {
			return fmt.Errorf("listen DoT %s: %w", addr, err)
		}
		srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: s, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: func() time.Duration { return 30 * time.Second }}
		go srv.ActivateAndServe()
		s.mu.Lock()
		s.servers = append(s.servers, srv)
		s.mu.Unlock()
		s.log.Info("dns over tls listening", "addr", ln.Addr())
	}

	for _, addr := range tc.DoHListen {
		hc := base.Clone()
		hc.NextProtos = []string{"h2", "http/1.1"}
		ln, err := tls.Listen("tcp", addr, hc)
		if err != nil {
			return fmt.Errorf("listen DoH %s: %w", addr, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc(tc.DoHPath, s.ServeDoH)
		hs := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
		go hs.Serve(ln)
		s.mu.Lock()
		s.https = append(s.https, hs)
		s.dohAddrs = append(s.dohAddrs, ln.Addr().String())
		s.mu.Unlock()
		s.log.Info("dns over https listening", "addr", ln.Addr(), "path", tc.DoHPath)
	}
	return nil
}

// DoHAddrs returns the bound DoH addresses.
func (s *Server) DoHAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dohAddrs...)
}

// ServeDoH answers RFC 8484 GET (?dns=base64url) and POST requests.
func (s *Server) ServeDoH(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err = base64.RawURLEncoding.DecodeString(q)
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(raw) == 0 || len(raw) > dns.MaxMsgSize {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	client := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		client = ap.Addr().Unmap()
	}
	resp := s.Handle(req, client, false)
	if resp == nil {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(minTTL(resp))))
	w.Write(out)
}

func minTTL(m *dns.Msg) uint32 {
	var ttl uint32 = 0
	found := false
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range rrs {
			if !found || rr.Header().Ttl < ttl {
				ttl, found = rr.Header().Ttl, true
			}
		}
	}
	return ttl
}
