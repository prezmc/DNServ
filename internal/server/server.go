// Package server answers client DNS queries: access control, filtering,
// cache, then upstream.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/prezmc/dnserve/internal/cache"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/policy"
	"github.com/prezmc/dnserve/internal/querylog"
)

// Resolver is the upstream path (forwarding group now; Unbound later).
type Resolver interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// Filter is the blocking engine.
type Filter interface {
	Lookup(name string) filter.Match
}

// Server handles DNS queries.
type Server struct {
	cfg    config.Config
	cache  *cache.Cache // nil when disabled
	filter Filter
	log    *slog.Logger
	// local forwards LAN names to the router (nil: answer not found).
	local atomic.Pointer[localFwd]
	// live holds what settings can change while running.
	live    atomic.Pointer[live]
	limiter *rateLimiter
	group   singleflight.Group
	Metrics *Metrics
	// qlog, when set, records every answered query.
	qlog atomic.Pointer[querylog.Log]
	// policy holds device groups (nil: everyone gets the shared filter).
	policy atomic.Pointer[policy.Set]
	loc    atomic.Pointer[time.Location] // for schedules; nil = time.Local

	mu       sync.Mutex
	servers  []*dns.Server
	https    []*http.Server
	dohAddrs []string
	// refreshCtx bounds background prefetch/revalidation work.
	refreshCtx    context.Context
	refreshCancel context.CancelFunc
}

// New creates a server. c may be nil to disable caching.
func New(cfg config.Config, c *cache.Cache, f Filter, r Resolver, log *slog.Logger) (*Server, error) {
	allowed, err := parseNets(cfg.DNS.AllowedNets)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg: cfg, cache: c, filter: f, log: log, Metrics: NewMetrics(),
		refreshCtx: ctx, refreshCancel: cancel,
	}
	s.live.Store(&live{resolver: r, allowed: allowed, filtering: cfg.Filtering})
	if cfg.DNS.RateLimit > 0 {
		s.limiter = newRateLimiter(cfg.DNS.RateLimit)
	}
	return s, nil
}

type live struct {
	resolver  Resolver
	allowed   []netip.Prefix
	filtering config.FilteringConfig
}

// Apply switches the resolver (nil keeps the current one), allowed client
// networks and filtering settings without dropping queries in flight.
// Cached answers are kept unless flush is set.
func (s *Server) Apply(r Resolver, allowedNets []string, fc config.FilteringConfig, flush bool) error {
	allowed, err := parseNets(allowedNets)
	if err != nil {
		return err
	}
	cur := s.live.Load()
	if r == nil {
		r = cur.resolver
	}
	s.live.Store(&live{resolver: r, allowed: allowed, filtering: fc})
	if flush && s.cache != nil {
		s.cache.Flush()
	}
	return nil
}

// DefaultAllowedNets are the client networks allowed when none are
// configured: private, loopback and link-local ranges. This keeps the node
// from becoming an open resolver if port 53 is exposed by mistake.
var DefaultAllowedNets = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
}

func parseNets(nets []string) ([]netip.Prefix, error) {
	if len(nets) == 0 {
		nets = DefaultAllowedNets
	}
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			a, aerr := netip.ParseAddr(n)
			if aerr != nil {
				return nil, fmt.Errorf("dns.allowed_nets: %q: %w", n, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Start listens on every configured address over UDP and TCP.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, addr := range s.cfg.DNS.Listen {
		for _, network := range []string{"udp", "tcp"} {
			ready := make(chan struct{})
			srv := &dns.Server{
				Addr: addr, Net: network, Handler: s,
				UDPSize:           int(s.cfg.DNS.UDPSize),
				ReadTimeout:       5 * time.Second,
				WriteTimeout:      5 * time.Second,
				NotifyStartedFunc: func() { close(ready) },
			}
			errc := make(chan error, 1)
			go func() { errc <- srv.ListenAndServe() }()
			select {
			case <-ready:
				s.servers = append(s.servers, srv)
				s.log.Info("dns listening", "addr", addr, "net", network)
			case err := <-errc:
				return fmt.Errorf("listen %s/%s: %w", addr, network, err)
			case <-time.After(5 * time.Second):
				return fmt.Errorf("listen %s/%s: timed out", addr, network)
			}
		}
	}
	return nil
}

// Addrs returns the bound addresses (useful when listening on port 0).
func (s *Server) Addrs() (udp, tcp []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.servers {
		if srv.PacketConn != nil {
			udp = append(udp, srv.PacketConn.LocalAddr().String())
		}
		if srv.Listener != nil {
			tcp = append(tcp, srv.Listener.Addr().String())
		}
	}
	return
}

// Shutdown stops the listeners and background refreshes.
func (s *Server) Shutdown(ctx context.Context) error {
	s.refreshCancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, srv := range s.servers {
		if err := srv.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	s.servers = nil
	for _, hs := range s.https {
		if err := hs.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	s.https = nil
	return errors.Join(errs...)
}

// ServeDNS implements dns.Handler for plain DNS (UDP/TCP) and DNS over TLS.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	_, isUDP := w.RemoteAddr().(*net.UDPAddr)
	resp := s.Handle(req, clientAddr(w.RemoteAddr()), isUDP)
	if resp == nil {
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		s.log.Debug("write failed", "err", err)
	}
}

// Handle answers one query from client. udp limits the response to the
// client's advertised buffer size. A nil result means drop the query.
func (s *Server) Handle(req *dns.Msg, client netip.Addr, udp bool) *dns.Msg {
	start := time.Now()
	if !s.clientAllowed(client) {
		s.Metrics.refused.Add(1)
		return s.finalize(req, rcodeMsg(req, dns.RcodeRefused), udp)
	}
	if s.limiter != nil && !s.limiter.allow(client, start) {
		s.Metrics.rateLimited.Add(1)
		return nil // drop silently, as Unbound's ratelimit does
	}
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 || req.Response {
		return s.finalize(req, rcodeMsg(req, dns.RcodeFormatError), udp)
	}
	resp, outcome, match := s.resolve(req, client)
	took := time.Since(start)
	s.Metrics.observe(outcome, resp, took)
	if ql := s.qlog.Load(); ql != nil {
		q := req.Question[0]
		e := querylog.Entry{
			Time: start, Client: client.Unmap(), Name: filter.Normalize(q.Name), Type: dns.TypeToString[q.Qtype],
			Result: outcomeResults[outcome], Rcode: dns.RcodeToString[resp.Rcode], Answers: len(resp.Answer),
			Duration: float64(took.Microseconds()) / 1000, Allowed: match.Allowed,
		}
		if match.Blocked || match.Allowed {
			e.List = match.Source
			if match.Rule.Domain != "" {
				e.Rule = match.Rule.Text()
			}
		}
		ql.Add(e)
	}
	return s.finalize(req, resp, udp)
}

// Outcome classifies how a query was answered.
type Outcome uint8

const (
	OutUpstream Outcome = iota
	OutCached
	OutStale
	OutBlocked
	OutLocal
	OutError
)

var outcomeResults = [...]string{
	OutUpstream: querylog.Answered, OutCached: querylog.Cached, OutStale: querylog.Stale,
	OutBlocked: querylog.Blocked, OutLocal: querylog.Local, OutError: querylog.Failed,
}

func (s *Server) resolve(req *dns.Msg, client netip.Addr) (*dns.Msg, Outcome, filter.Match) {
	q := req.Question[0]
	name := filter.Normalize(q.Name)

	if m, ok := s.localAnswer(req, name); ok {
		return m, OutLocal, filter.Match{}
	}

	// Firefox's canary domain: NXDOMAIN tells it not to switch on its own
	// DNS over HTTPS and bypass this server's filtering.
	if s.live.Load().filtering.Enabled && (name == "use-application-dns.net" || strings.HasSuffix(name, ".use-application-dns.net")) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = []dns.RR{s.blockSOA(q.Name)}
		return m, OutBlocked, filter.Match{Blocked: true, Source: "Firefox DoH canary", Rule: filter.Rule{Domain: "use-application-dns.net", Kind: filter.Suffix}}
	}

	var match filter.Match
	shared := true
	if g := s.policy.Load().For(client); g != nil {
		now := time.Now()
		if loc := s.loc.Load(); loc != nil {
			now = now.In(loc)
		}
		m, decided := g.Check(name, now)
		if decided {
			if m.Blocked {
				return s.blocked(req), OutBlocked, m
			}
			match, shared = m, false
		} else if g.SkipShared {
			shared = false
		}
	}
	if f := s.filter; f != nil && shared {
		if match = f.Lookup(name); match.Blocked {
			return s.blocked(req), OutBlocked, match
		}
	}

	key := ""
	if s.cache != nil {
		key = cache.Key(req)
		if res := s.cache.Get(key); res.State != cache.Miss {
			if res.Refresh {
				s.refresh(key, req)
			}
			res.Msg.Id = req.Id
			res.Msg.Question = req.Question
			if res.State == cache.Stale {
				return res.Msg, OutStale, match
			}
			return res.Msg, OutCached, match
		}
	}

	resp, err := s.fetch(key, req)
	if err != nil {
		s.log.Debug("upstream failed", "name", name, "type", dns.TypeToString[q.Qtype], "err", err)
		return rcodeMsg(req, dns.RcodeServerFailure), OutError, match
	}
	out := resp.Copy()
	out.Id = req.Id
	out.Question = req.Question
	return out, OutUpstream, match
}

// fetch asks upstream, collapsing identical concurrent queries into one.
func (s *Server) fetch(key string, req *dns.Msg) (*dns.Msg, error) {
	sfKey := key
	if sfKey == "" {
		sfKey = cache.Key(req)
	}
	v, err, _ := s.group.Do(sfKey, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Upstream.Timeout*2)
		defer cancel()
		return s.exchange(ctx, key, req)
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg), nil
}

func (s *Server) exchange(ctx context.Context, key string, req *dns.Msg) (*dns.Msg, error) {
	up := upstreamQuery(req)
	resp, err := s.live.Load().resolver.Exchange(ctx, up)
	if err != nil {
		s.Metrics.upstreamErrors.Add(1)
		return nil, err
	}
	if s.cache != nil && key != "" {
		s.cache.Set(key, resp)
	}
	return resp, nil
}

// refresh revalidates an entry in the background (prefetch or stale).
func (s *Server) refresh(key string, req *dns.Msg) {
	r := req.Copy()
	go func() {
		ctx, cancel := context.WithTimeout(s.refreshCtx, s.cfg.Upstream.Timeout*2)
		defer cancel()
		if _, err := s.exchange(ctx, key, r); err != nil {
			s.cache.Done(key)
		}
	}()
}

// upstreamQuery builds the query sent upstream: same question and flags,
// our own EDNS0 buffer size, DO preserved, client subnet never added.
func upstreamQuery(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.CheckingDisabled = req.CheckingDisabled
	m.Question = []dns.Question{req.Question[0]}
	do := false
	if o := req.IsEdns0(); o != nil {
		do = o.Do()
	}
	m.SetEdns0(1232, do)
	return m
}

// finalize sets response flags, mirrors the client's EDNS and truncates
// to what the transport allows.
func (s *Server) finalize(req, resp *dns.Msg, udp bool) *dns.Msg {
	if resp == nil {
		return nil
	}
	resp.Response = true
	resp.RecursionAvailable = true
	clientOpt := req.IsEdns0()
	// Only send an OPT record back if the client sent one.
	extra := resp.Extra[:0:0]
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra
	if clientOpt != nil {
		resp.SetEdns0(s.cfg.DNS.UDPSize, clientOpt.Do())
	}
	if udp {
		size := dns.MinMsgSize
		if clientOpt != nil {
			size = min(max(int(clientOpt.UDPSize()), dns.MinMsgSize), int(s.cfg.DNS.UDPSize))
		}
		resp.Truncate(size)
	} else {
		resp.Truncate(dns.MaxMsgSize)
	}
	return resp
}

func (s *Server) clientAllowed(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range s.live.Load().allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func clientAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func rcodeMsg(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

// blockSOA is the authority record on blocked negative answers, so clients
// cache the block for BlockTTL.
func (s *Server) blockSOA(zone string) dns.RR {
	ttl := uint32(s.live.Load().filtering.BlockTTL / time.Second)
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "dnserve.blocked.", Mbox: "blocked.dnserve.blocked.",
		Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: ttl,
	}
}

func (s *Server) blocked(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	ttl := uint32(s.live.Load().filtering.BlockTTL / time.Second)
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false
	switch s.live.Load().filtering.BlockMode {
	case "nxdomain":
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{s.blockSOA(q.Name)}
	case "refused":
		m.Rcode = dns.RcodeRefused
	default: // null_ip
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero.To4()}}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
		default:
			m.Ns = []dns.RR{s.blockSOA(q.Name)}
		}
	}
	return m
}

// localOnlySuffixes are never sent upstream: they only make sense on the
// local network, and leaking them reveals internal names.
var localOnlySuffixes = []string{"local", "lan", "home", "internal", "localdomain", "home.arpa", "corp", "intranet", "private"}

// localAnswer answers names that must not leave the network: single-label
// names, local-only suffixes, "localhost" and reverse lookups of private
// addresses (RFC 6761, RFC 6303). Conditional forwarding to the LAN router
// comes with per-device policies.
func (s *Server) localAnswer(req *dns.Msg, name string) (*dns.Msg, bool) {
	q := req.Question[0]
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		m := new(dns.Msg)
		m.SetReply(req)
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 3600}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1).To4()}}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6loopback}}
		}
		return m, true
	}
	if name == "" { // root
		return nil, false
	}
	nx := func() (*dns.Msg, bool) {
		if fwd := s.local.Load(); fwd != nil {
			return s.forwardLocal(fwd.r, req), true
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = []dns.RR{s.blockSOA(q.Name)}
		return m, true
	}
	if !strings.Contains(name, ".") && q.Qtype != dns.TypeDS && q.Qtype != dns.TypeNS && q.Qtype != dns.TypeSOA && q.Qtype != dns.TypeDNSKEY {
		return nx()
	}
	for _, suf := range localOnlySuffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return nx()
		}
	}
	if q.Qtype == dns.TypePTR && isPrivateReverse(name) {
		return nx()
	}
	return nil, false
}

// SetPolicy replaces the device groups.
func (s *Server) SetPolicy(p *policy.Set) { s.policy.Store(p) }

// SetTimeZone sets the time zone schedules run in.
func (s *Server) SetTimeZone(l *time.Location) { s.loc.Store(l) }

// SetQueryLog starts recording queries into l (nil stops).
func (s *Server) SetQueryLog(l *querylog.Log) { s.qlog.Store(l) }

type localFwd struct{ r Resolver }

// SetLocalDNS sets (or with nil, clears) the router that answers local
// names and private reverse lookups.
func (s *Server) SetLocalDNS(r Resolver) {
	if r == nil {
		s.local.Store(nil)
		return
	}
	s.local.Store(&localFwd{r: r})
}

func (s *Server) forwardLocal(r Resolver, req *dns.Msg) *dns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := r.Exchange(ctx, upstreamQuery(req))
	if err != nil {
		s.log.Debug("local dns failed", "name", req.Question[0].Name, "err", err)
		return rcodeMsg(req, dns.RcodeServerFailure)
	}
	out := resp.Copy()
	out.Id = req.Id
	out.Question = req.Question
	return out
}

// LookupName returns a LAN device's name from the router's reverse DNS,
// or "" when there is no router configured or no name.
func (s *Server) LookupName(ctx context.Context, a netip.Addr) string {
	fwd := s.local.Load()
	if fwd == nil {
		return ""
	}
	rev, err := dns.ReverseAddr(a.Unmap().String())
	if err != nil {
		return ""
	}
	q := new(dns.Msg)
	q.SetQuestion(rev, dns.TypePTR)
	resp, err := fwd.r.Exchange(ctx, q)
	if err != nil {
		return ""
	}
	for _, rr := range resp.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(p.Ptr, ".")
		}
	}
	return ""
}

func isPrivateReverse(name string) bool {
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) == 0 {
			return false
		}
		// Reverse the labels back into an address prefix.
		parts := make([]string, 0, 4)
		for i := len(labels) - 1; i >= 0 && len(parts) < 4; i-- {
			parts = append(parts, labels[i])
		}
		for len(parts) < 4 {
			parts = append(parts, "0")
		}
		a, err := netip.ParseAddr(strings.Join(parts, "."))
		if err != nil {
			return false
		}
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)
	case strings.HasSuffix(name, ".ip6.arpa"):
		nibbles := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(nibbles) == 0 {
			return false
		}
		first := nibbles[len(nibbles)-1]
		second := ""
		if len(nibbles) >= 2 {
			second = nibbles[len(nibbles)-2]
		}
		switch {
		case first == "f" && (second == "c" || second == "d"): // fc00::/7
			return true
		case first == "f" && second == "e": // fe80::/10 (approximate: fe8-feb)
			if len(nibbles) >= 3 {
				third := nibbles[len(nibbles)-3]
				return third == "8" || third == "9" || third == "a" || third == "b"
			}
		}
		return name == strings.Repeat("0.", 31)+"1.ip6.arpa" // ::1
	}
	return false
}
