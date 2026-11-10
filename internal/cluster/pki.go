package cluster

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// serverName is in every node certificate. Peers check certificates
// against the cluster CA and this name, not against IPs or hostnames,
// which change and which the node can't know. It keeps the old project
// name (DNServe) because existing certificates carry it.
const serverName = "dnserve-node"

// certLife is long because nodes have no way to renew yet; trust comes
// from the private cluster CA, and a node is cut off by removing it.
const certLife = 20 * 365 * 24 * time.Hour

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// newCA makes the cluster's certificate authority.
func newCA(clusterID string) (certPEM, keyPEM string, err error) {
	key, err := newKey()
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "DNServ cluster " + clusterID},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return pemString("CERTIFICATE", der), pemString("PRIVATE KEY", kb), nil
}

// issue signs a node certificate for nodeID's public key.
func issue(caCertPEM, caKeyPEM, nodeID string, pub crypto.PublicKey) (string, error) {
	ca, err := parseCert(caCertPEM)
	if err != nil {
		return "", err
	}
	caKey, err := parseKey(caKeyPEM)
	if err != nil {
		return "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: nodeID},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		return "", err
	}
	return pemString("CERTIFICATE", der), nil
}

// fingerprint is the SHA-256 of a certificate, base64url. Join codes carry
// the CA's, so a new node knows it is talking to the right cluster.
func fingerprint(certPEM string) (string, error) {
	c, err := parseCert(certPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func pemString(typ string, b []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}))
}

func parseCert(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func parseKey(s string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("not a PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	sg, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", k)
	}
	return sg, nil
}

func parsePublicKey(s string) (crypto.PublicKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	return x509.ParsePKIXPublicKey(b.Bytes)
}

// creds are a node's TLS identity within its cluster.
type creds struct {
	cert   tls.Certificate // node cert + CA, with key
	pool   *x509.CertPool
	caPEM  string
	caFP   string
	nodeID string
}

func loadCreds(certPEM, keyPEM, caPEM string) (*creds, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM+caPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	ca, err := parseCert(caPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	fp, err := fingerprint(caPEM)
	if err != nil {
		return nil, err
	}
	return &creds{cert: pair, pool: pool, caPEM: caPEM, caFP: fp, nodeID: leaf.Subject.CommonName}, nil
}

// serverConfig accepts node connections. Client certificates are optional
// at the TLS layer (a joining node has none yet); each protocol enforces
// what it needs.
func (c *creds) serverConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c.cert},
		ClientCAs:    c.pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{alpnRaft, alpnRPC},
	}
}

func (c *creds) clientConfig(proto string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c.cert},
		RootCAs:      c.pool,
		ServerName:   serverName,
		NextProtos:   []string{proto},
	}
}

// pinnedConfig is for a node that is joining: it has no certificate yet
// and trusts the cluster only through the CA fingerprint in the join code.
func pinnedConfig(caFP string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // verified below against the pinned CA
		NextProtos:         []string{alpnRPC},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 2 {
				return errors.New("the other node sent no cluster certificate")
			}
			ca, err := x509.ParseCertificate(raw[len(raw)-1])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(ca.Raw)
			if base64.RawURLEncoding.EncodeToString(sum[:]) != caFP {
				return errors.New("the other node's cluster doesn't match the join code")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
}
