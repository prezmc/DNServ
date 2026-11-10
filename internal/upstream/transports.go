package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Bootstrap resolves the hostnames of encrypted upstreams using plain DNS
// to fixed IP addresses, caching the result.
type Bootstrap struct {
	servers []string
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]bootEntry
}

type bootEntry struct {
	addrs   []string
	expires time.Time
}

// NewBootstrap creates a resolver over the given "ip:port" servers.
func NewBootstrap(servers []string, timeout time.Duration) *Bootstrap {
	return &Bootstrap{servers: servers, timeout: timeout, cache: map[string]bootEntry{}}
}

// Resolve returns IP addresses for host. IP literals are returned as is.
func (b *Bootstrap) Resolve(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	b.mu.Lock()
	if e, ok := b.cache[host]; ok && time.Now().Before(e.expires) {
		b.mu.Unlock()
		return e.addrs, nil
	}
	b.mu.Unlock()

	if len(b.servers) == 0 {
		var r net.Resolver
		addrs, err := r.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		b.store(host, addrs, 5*time.Minute)
		return addrs, nil
	}

	c := &dns.Client{Timeout: b.timeout}
	var (
		addrs  []string
		minTTL = uint32(3600)
		errs   []error
	)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qt)
		for _, srv := range b.servers {
			resp, _, err := c.ExchangeContext(ctx, m, srv)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					addrs = append(addrs, v.A.String())
				case *dns.AAAA:
					addrs = append(addrs, v.AAAA.String())
				default:
					continue
				}
				minTTL = min(minTTL, rr.Header().Ttl)
			}
			break
		}
	}
	if len(addrs) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("bootstrap %s: %w", host, errors.Join(errs...))
		}
		return nil, fmt.Errorf("bootstrap %s: no addresses", host)
	}
	b.store(host, addrs, max(time.Duration(minTTL)*time.Second, 5*time.Minute))
	return addrs, nil
}

func (b *Bootstrap) store(host string, addrs []string, ttl time.Duration) {
	b.mu.Lock()
	b.cache[host] = bootEntry{addrs: addrs, expires: time.Now().Add(ttl)}
	b.mu.Unlock()
}

// dialer dials host:port by resolving host through the bootstrap and
// trying each address.
func (b *Bootstrap) dial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := b.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	var errs []error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// --- DNS over HTTPS (RFC 8484) ---

type doh struct {
	url    string
	client *http.Client
}

func newDoH(u *url.URL, boot *Bootstrap, timeout time.Duration) *doh {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return boot.dial(ctx, network, addr, timeout)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	return &doh{url: u.String(), client: &http.Client{Transport: tr, Timeout: timeout}}
}

func (d *doh) String() string { return d.url }

func (d *doh) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := q.Copy()
	m.Id = 0 // RFC 8484 section 4.1: use ID 0 for cache friendliness
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	out.Id = q.Id
	return out, nil
}

// --- DNS over TLS (RFC 7858) with a small connection pool ---

type dot struct {
	addr, name string
	boot       *Bootstrap
	timeout    time.Duration
	pool       chan pooledConn
}

// pooledConn is an idle DoT connection and when it was last used.
type pooledConn struct {
	c    *dns.Conn
	used time.Time
}

// dotIdle is how long an idle DoT connection is kept for reuse. Servers
// and home routers drop idle connections, often without telling either
// end, and a query sent on one of those waits for the whole timeout
// before it is retried. A new TLS connection costs one round trip or two.
var dotIdle = 10 * time.Second

func newDoT(u *url.URL, boot *Bootstrap, timeout time.Duration) *dot {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "853"
	}
	return &dot{
		addr:    net.JoinHostPort(host, port),
		name:    host,
		boot:    boot,
		timeout: timeout,
		pool:    make(chan pooledConn, 8),
	}
}

func (d *dot) String() string { return "tls://" + d.addr }

func (d *dot) conn(ctx context.Context) (*dns.Conn, error) {
	for {
		select {
		case p := <-d.pool:
			if time.Since(p.used) < dotIdle {
				return p.c, nil
			}
			p.c.Close() // idle too long; it may be dead already
			continue
		default:
		}
		break
	}
	raw, err := d.boot.dial(ctx, "tcp", d.addr, d.timeout)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: d.name, MinVersion: tls.VersionTLS12})
	tc.SetDeadline(time.Now().Add(d.timeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return &dns.Conn{Conn: tc}, nil
}

func (d *dot) put(c *dns.Conn) {
	select {
	case d.pool <- pooledConn{c, time.Now()}:
	default:
		c.Close()
	}
}

func (d *dot) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	// A pooled connection may have been closed by the server; retry once
	// on a fresh one.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := d.conn(ctx)
		if err != nil {
			return nil, err
		}
		deadline := time.Now().Add(d.timeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		c.SetDeadline(deadline)
		if err := c.WriteMsg(q); err != nil {
			c.Close()
			lastErr = err
			continue
		}
		resp, err := c.ReadMsg()
		if err != nil {
			c.Close()
			lastErr = err
			continue
		}
		if resp.Id != q.Id {
			c.Close()
			lastErr = errors.New("response ID mismatch")
			continue
		}
		d.put(c)
		return resp, nil
	}
	return nil, lastErr
}

// --- plain UDP/TCP ---

type plain struct {
	addr   string
	net    string
	client *dns.Client
}

func newPlain(u *url.URL, timeout time.Duration) *plain {
	port := u.Port()
	if port == "" {
		port = "53"
	}
	return &plain{
		addr:   net.JoinHostPort(u.Hostname(), port),
		net:    u.Scheme,
		client: &dns.Client{Net: u.Scheme, Timeout: timeout},
	}
}

func (p *plain) String() string { return p.net + "://" + p.addr }

func (p *plain) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	resp, _, err := p.client.ExchangeContext(ctx, q, p.addr)
	if err == nil && resp.Truncated && p.net == "udp" {
		tcp := &dns.Client{Net: "tcp", Timeout: p.client.Timeout}
		resp, _, err = tcp.ExchangeContext(ctx, q, p.addr)
	}
	return resp, err
}
