package server

import (
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/config"
)

// recordTTL is short so a changed record reaches devices quickly.
const recordTTL = 60

// maxAliasChain bounds alias-to-alias lookups (and loops).
const maxAliasChain = 8

type localRec struct {
	ip    netip.Addr // A or AAAA
	alias string     // CNAME target, when ip is invalid
}

// Records answers the owner's local DNS records.
type Records struct {
	exact map[string][]localRec
	wild  map[string][]localRec // "lab.home" for "*.lab.home"
	ptr   map[string]string     // reverse name -> name
}

// NewRecords builds the lookup table. Records are assumed valid (see
// config.NormalizeRecords); invalid ones are skipped.
func NewRecords(in []config.Record) *Records {
	recs, err := config.NormalizeRecords(in)
	if err != nil {
		recs = nil
		for _, r := range in {
			if n, err := config.NormalizeRecords([]config.Record{r}); err == nil {
				recs = append(recs, n...)
			}
		}
	}
	t := &Records{exact: map[string][]localRec{}, wild: map[string][]localRec{}, ptr: map[string]string{}}
	for _, r := range recs {
		var lr localRec
		if ip, err := netip.ParseAddr(r.Value); err == nil {
			lr.ip = ip
		} else {
			lr.alias = r.Value
		}
		if w, ok := strings.CutPrefix(r.Name, "*."); ok {
			t.wild[w] = append(t.wild[w], lr)
			continue
		}
		t.exact[r.Name] = append(t.exact[r.Name], lr)
		if lr.ip.IsValid() {
			rev, err := dns.ReverseAddr(lr.ip.String())
			if err == nil {
				rev = strings.TrimSuffix(rev, ".")
				if _, taken := t.ptr[rev]; !taken {
					t.ptr[rev] = r.Name
				}
			}
		}
	}
	return t
}

// Len is the number of names with records.
func (t *Records) Len() int { return len(t.exact) + len(t.wild) }

// lookup finds the records for name: exact first, then the closest
// wildcard above it.
func (t *Records) lookup(name string) ([]localRec, bool) {
	if r, ok := t.exact[name]; ok {
		return r, true
	}
	for rest := name; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return nil, false
		}
		rest = rest[i+1:]
		if r, ok := t.wild[rest]; ok {
			return r, true
		}
	}
}

// SetRecords replaces the local records.
func (s *Server) SetRecords(t *Records) {
	if t != nil && t.Len() == 0 && len(t.ptr) == 0 {
		t = nil
	}
	s.records.Store(t)
}

// recordAnswer answers from the local records. ok is false when the name
// has none. An alias to a name outside the records is looked up as usual
// (cache, filters, upstream) and its answer appended.
func (s *Server) recordAnswer(req *dns.Msg, name string, client netip.Addr) (*dns.Msg, bool) {
	t := s.records.Load()
	if t == nil {
		return nil, false
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		return nil, false
	}
	if q.Qtype == dns.TypePTR {
		target, ok := t.ptr[name]
		if !ok {
			return nil, false
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: recordTTL}, Ptr: dns.Fqdn(target)}}
		return m, true
	}
	recs, ok := t.lookup(name)
	if !ok {
		return nil, false
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	owner := q.Name
	for depth := 0; ; depth++ {
		if len(recs) == 1 && recs[0].alias != "" {
			target := recs[0].alias
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: recordTTL}, Target: dns.Fqdn(target)})
			if q.Qtype == dns.TypeCNAME {
				return m, true
			}
			next, local := t.lookup(target)
			if !local {
				// Look the target up like any other name.
				sub := new(dns.Msg)
				sub.SetQuestion(dns.Fqdn(target), q.Qtype)
				sub.RecursionDesired = true
				if o := req.IsEdns0(); o != nil {
					sub.SetEdns0(o.UDPSize(), o.Do())
				}
				resp, _, _, _ := s.resolve(sub, client)
				m.Answer = append(m.Answer, resp.Answer...)
				m.Ns = resp.Ns
				m.Rcode = resp.Rcode
				m.Authoritative = false
				return m, true
			}
			if depth >= maxAliasChain {
				m.Rcode = dns.RcodeServerFailure
				return m, true
			}
			owner, recs = dns.Fqdn(target), next
			continue
		}
		break
	}
	for _, r := range recs {
		hdr := dns.RR_Header{Name: owner, Class: dns.ClassINET, Ttl: recordTTL}
		switch {
		case r.ip.Is4() && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY):
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(r.ip.AsSlice())})
		case r.ip.Is6() && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY):
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(r.ip.AsSlice())})
		}
	}
	if len(m.Answer) == 0 {
		// The name exists here but not with this type: say so, rather
		// than asking upstream about a name only this network knows.
		m.Ns = []dns.RR{s.blockSOA(q.Name)}
	}
	return m, true
}
