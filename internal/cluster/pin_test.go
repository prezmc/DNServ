package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/prezmc/dnserv/internal/store"
)

// forgedClient signs a certificate for nodeID with the cluster's CA key,
// as a node that was removed (and still has the key) could.
func forgedClient(t *testing.T, cs store.ClusterState, nodeID string) (*http.Client, *x509.Certificate) {
	t.Helper()
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := issue(cs.CACert, cs.CAKey, nodeID, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(certPEM+cs.CACert), []byte(keyPEM(key)))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(cs.CACert))
	conf := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: serverName, NextProtos: []string{alpnRPC}}
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: conf}
		return d.DialContext(ctx, network, addr)
	}}
	return &http.Client{Transport: tr}, leaf
}

func TestPinnedCertificates(t *testing.T) {
	a, b := pair(t)
	waitFor(t, "both nodes pinned", func() bool {
		ns := a.st.State().Cluster.Nodes
		return ns[a.c.ID()].CertFP == a.c.ownFP() && ns[b.c.ID()].CertFP == b.c.ownFP() && a.c.ownFP() != ""
	})

	// A certificate signed with the CA key for b's ID, but not b's own,
	// is refused by the node API and by Raft.
	cl, forged := forgedClient(t, a.st.State().Cluster, b.c.ID())
	resp, err := cl.Post("https://"+a.addr+"/rpc/status", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged certificate got HTTP %d, want 403", resp.StatusCode)
	}
	if a.c.isMember(forged) {
		t.Fatal("forged certificate counted as a member")
	}

	// A node can't pin a certificate for another node, nor re-pin its own.
	cmd, _ := json.Marshal(store.NewCommand(store.OpClusterCert, "system", store.ClusterCert{ID: b.c.ID(), CertFP: certFP(forged.Raw)}))
	if err := checkPin(cmd, forged); err != nil {
		t.Fatalf("checkPin for the cert itself: %v", err)
	}
	if err := checkPin(cmd, nil); err == nil {
		t.Fatal("pin accepted without a certificate")
	}
	if err := a.apply(store.OpClusterCert, store.ClusterCert{ID: b.c.ID(), CertFP: certFP(forged.Raw)}); err == nil {
		t.Fatal("re-pinned a pinned node")
	}
	// The real b still works.
	b.mustApply(store.OpUserCreate, store.UserCreate{ID: "u9", Username: "sam", Role: store.RoleViewer, PasswordHash: "h"})
}
