// Package certs holds the dashboard's HTTPS certificate, makes a
// self-signed one when that is all there is, and lets one port carry both
// plain HTTP and HTTPS.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Info describes a certificate for the dashboard.
type Info struct {
	Subject     string    `json:"subject"`
	Names       []string  `json:"names"` // DNS names and IP addresses it is valid for
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"sha256"`
	SelfSigned  bool      `json:"self_signed"`
}

// Describe returns c's Info.
func Describe(c *tls.Certificate) Info {
	if c == nil || len(c.Certificate) == 0 {
		return Info{}
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return Info{}
		}
	}
	sum := sha256.Sum256(c.Certificate[0])
	in := Info{
		Subject:     leaf.Subject.CommonName,
		Names:       append([]string(nil), leaf.DNSNames...),
		Issuer:      leaf.Issuer.CommonName,
		NotAfter:    leaf.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]),
		SelfSigned:  leaf.Issuer.String() == leaf.Subject.String(),
	}
	for _, ip := range leaf.IPAddresses {
		in.Names = append(in.Names, ip.String())
	}
	if in.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		in.Issuer = leaf.Issuer.Organization[0]
	}
	return in
}

// Parse checks a PEM certificate chain and private key: they must match,
// and the certificate must be valid now.
func Parse(certPEM, keyPEM []byte, now time.Time) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate isn't valid until %s", leaf.NotBefore.Format(time.DateOnly))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format(time.DateOnly))
	}
	c.Leaf = leaf
	return &c, nil
}

// Holder serves whichever certificate was set last. It is safe for
// concurrent use; TLS handshakes read it through GetCertificate.
type Holder struct {
	cur atomic.Pointer[tls.Certificate]
}

// Set replaces the certificate.
func (h *Holder) Set(c *tls.Certificate) { h.cur.Store(c) }

// Get returns the current certificate (nil: none).
func (h *Holder) Get() *tls.Certificate { return h.cur.Load() }

// GetCertificate is for tls.Config.
func (h *Holder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := h.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate")
}

// SelfSigned loads the self-signed certificate in dir, or makes a new one
// (valid two years) when it is missing, within 30 days of expiry, or not
// valid for every name in names. Names may be host names or IP addresses.
func SelfSigned(dir string, names []string) (*tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "https.crt"), filepath.Join(dir, "https.key")
	names = cleanNames(names)
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			if time.Until(leaf.NotAfter) > 30*24*time.Hour && covers(leaf, names) {
				c.Leaf = leaf
				return &c, nil
			}
			// Keep the old names too, so an address that comes and goes
			// (a container's) doesn't make a new certificate each time.
			if len(leaf.DNSNames)+len(leaf.IPAddresses) < 40 {
				old := append([]string(nil), leaf.DNSNames...)
				for _, ip := range leaf.IPAddresses {
					old = append(old, ip.String())
				}
				names = cleanNames(append(names, old...))
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	cn := "DNServ"
	for _, n := range names {
		if net.ParseIP(n) == nil {
			cn = n
			break
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"DNServ self-signed"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	return Parse(certPEM, keyPEM, time.Now())
}

func cleanNames(names []string) []string {
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.Trim(strings.TrimSpace(n), "[]."))
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func covers(leaf *x509.Certificate, names []string) bool {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
				return false
			}
		} else if !slices.Contains(leaf.DNSNames, n) {
			return false
		}
	}
	return true
}

// LocalNames returns names this machine is likely reached by: its host
// name, "localhost" and its non-loopback interface addresses, plus extra.
func LocalNames(extra ...string) []string {
	names := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				names = append(names, n.IP.String())
			}
		}
	}
	return cleanNames(append(names, extra...))
}
