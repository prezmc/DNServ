package certs

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Listener lets one port serve plain HTTP and HTTPS. While TLS is on, a
// connection that starts with a TLS handshake gets one; every other
// connection is passed through as plain. Turning TLS off and on doesn't
// touch connections already open.
type Listener struct {
	net.Listener
	tls  *tls.Config
	on   atomic.Bool
	out  chan net.Conn
	done chan struct{}
	once sync.Once
	err  atomic.Pointer[error]
}

// sniffTimeout bounds how long a new connection may take to send its
// first byte before it is dropped.
var sniffTimeout = 10 * time.Second

// NewListener wraps ln. cfg must be able to find a certificate (through
// GetCertificate, usually a Holder's).
func NewListener(ln net.Listener, cfg *tls.Config) *Listener {
	l := &Listener{Listener: ln, tls: cfg, out: make(chan net.Conn), done: make(chan struct{})}
	go l.accept()
	return l
}

// SetTLS turns HTTPS on or off for new connections.
func (l *Listener) SetTLS(on bool) { l.on.Store(on) }

// TLS reports whether HTTPS is on.
func (l *Listener) TLS() bool { return l.on.Load() }

func (l *Listener) accept() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.err.Store(&err)
			l.once.Do(func() { close(l.done) })
			return
		}
		if !l.on.Load() {
			select {
			case l.out <- c:
			case <-l.done:
				c.Close()
			}
			continue
		}
		go l.sniff(c)
	}
}

// sniff peeks at the first byte off the accept loop, so a client that
// sends nothing can't hold up others.
func (l *Listener) sniff(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReaderSize(c, 1)
	first, err := br.Peek(1)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	var conn net.Conn = &peeked{Conn: c, r: br}
	if first[0] == 0x16 { // TLS handshake record
		conn = tls.Server(conn, l.tls)
	}
	select {
	case l.out <- conn:
	case <-l.done:
		conn.Close()
	}
}

// Accept returns the next connection, TLS or plain.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		if e := l.err.Load(); e != nil {
			return nil, *e
		}
		return nil, net.ErrClosed
	}
}

// Close stops listening.
func (l *Listener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.done) })
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// peeked is a connection whose first byte was read into r.
type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }
