package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// One TCP port carries both Raft and the node-to-node API, told apart by
// the TLS ALPN protocol.
const (
	alpnRaft = "dnserve-raft/1"
	alpnRPC  = "dnserve-rpc/1"
)

var errClosed = errors.New("listener closed")

// mux accepts TLS connections on the cluster port and hands them to Raft
// or to the RPC server.
type mux struct {
	ln       net.Listener
	tlsConf  func() *tls.Config
	isMember func(nodeID string) bool
	log      *slog.Logger

	mu   sync.Mutex
	raft *streamLayer // current Raft instance's listener, if running
	rpc  *chanListener
}

func newMux(ln net.Listener, tlsConf func() *tls.Config, isMember func(string) bool, log *slog.Logger) *mux {
	return &mux{ln: ln, tlsConf: tlsConf, isMember: isMember, log: log, rpc: newChanListener(ln.Addr())}
}

func (m *mux) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				m.rpc.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go m.handle(conn)
	}
}

func (m *mux) handle(conn net.Conn) {
	tc := tls.Server(conn, m.tlsConf())
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	cs := tc.ConnectionState()
	switch cs.NegotiatedProtocol {
	case alpnRaft:
		// Raft only from current members: a node that was removed, or
		// left behind by a forced recovery, can't disturb the cluster.
		if len(cs.PeerCertificates) == 0 || !m.isMember(cs.PeerCertificates[0].Subject.CommonName) {
			m.log.Debug("refused raft connection", "remote", conn.RemoteAddr())
			conn.Close()
			return
		}
		m.mu.Lock()
		sl := m.raft
		m.mu.Unlock()
		if sl == nil || !sl.deliver(tc) {
			conn.Close()
		}
	case alpnRPC:
		// Wrapped so net/http serves it as plain HTTP/1.1 (it won't for a
		// *tls.Conn with an ALPN protocol it doesn't know); the TLS state
		// travels with it for the handlers.
		if !m.rpc.deliver(&peerConn{Conn: tc, state: cs}) {
			conn.Close()
		}
	default:
		conn.Close()
	}
}

func (m *mux) setRaft(sl *streamLayer) {
	m.mu.Lock()
	m.raft = sl
	m.mu.Unlock()
}

// chanListener is a net.Listener fed by the mux.
type chanListener struct {
	addr   net.Addr
	ch     chan net.Conn
	done   chan struct{}
	closer sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) deliver(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, errClosed
	}
}

func (l *chanListener) Close() error {
	l.closer.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

// streamLayer is raft.StreamLayer over the mux: Accept gets Raft
// connections, Dial opens mutual-TLS connections to peers.
type streamLayer struct {
	*chanListener
	advertise func() string
	dialConf  func() *tls.Config
}

var _ raft.StreamLayer = (*streamLayer)(nil)

func (s *streamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(d, "tcp", string(addr), s.dialConf())
}

func (s *streamLayer) Addr() net.Addr { return advAddr(s.advertise()) }

type advAddr string

func (a advAddr) Network() string { return "tcp" }
func (a advAddr) String() string  { return string(a) }

// peerConn is an RPC connection that has finished its TLS handshake.
type peerConn struct {
	net.Conn
	state tls.ConnectionState
}

type tlsStateKey struct{}

// connContext puts the connection's TLS state in each request's context.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*peerConn); ok {
		return context.WithValue(ctx, tlsStateKey{}, &pc.state)
	}
	return ctx
}

func peerID(r *http.Request) string {
	cs, _ := r.Context().Value(tlsStateKey{}).(*tls.ConnectionState)
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return ""
	}
	return cs.PeerCertificates[0].Subject.CommonName
}
