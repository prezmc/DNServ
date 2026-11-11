package recursive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Exchanger is the resolve call shared with the upstream package.
type Exchanger interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// ErrTunnelDown is returned in block mode while the tunnel is down.
var ErrTunnelDown = errors.New("tunnel down: refusing to resolve outside the VPN")

// Tunnel resolves through Primary (Unbound behind a VPN) while the tunnel
// checks pass, and otherwise through Fallback (encrypted forwarding) or not
// at all. Checks run in the background so queries never wait on them.
type Tunnel struct {
	Primary  Exchanger
	Fallback Exchanger // nil = block while down
	// Interface must exist and be up; empty skips the check.
	Interface string
	// Expected egress networks; empty skips the check.
	Expected []netip.Prefix
	// EgressProbe returns the address authoritative servers see for our
	// queries. Defaults to asking Google's o-o.myaddr.l.google.com via
	// Primary.
	EgressProbe func(ctx context.Context) (netip.Addr, error)
	Log         *slog.Logger

	up     atomic.Bool
	reason atomic.Value // string
	// interfaces is replaceable in tests.
	interfaces func() ([]net.Interface, error)
}

// ParsePrefixes accepts IPs or CIDRs.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Up reports the last check result and why it failed.
func (t *Tunnel) Up() (bool, string) {
	r, _ := t.reason.Load().(string)
	return t.up.Load(), r
}

// Exchange resolves q according to the tunnel state.
func (t *Tunnel) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if t.up.Load() {
		return t.Primary.Exchange(ctx, q)
	}
	if t.Fallback != nil {
		return t.Fallback.Exchange(ctx, q)
	}
	return nil, ErrTunnelDown
}

// ExchangeFrom is Exchange that also says which path answered: the
// tunnel, or the fallback's server.
func (t *Tunnel) ExchangeFrom(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	if t.up.Load() {
		resp, err := t.Primary.Exchange(ctx, q)
		return resp, "Recursive (through the tunnel)", err
	}
	if f, ok := t.Fallback.(interface {
		ExchangeFrom(context.Context, *dns.Msg) (*dns.Msg, string, error)
	}); ok {
		return f.ExchangeFrom(ctx, q)
	}
	resp, err := t.Exchange(ctx, q)
	return resp, "", err
}

// Check runs the tunnel checks once and updates the state.
func (t *Tunnel) Check(ctx context.Context) bool {
	ok, why := t.check(ctx)
	was := t.up.Swap(ok)
	t.reason.Store(why)
	if t.Log != nil && ok != was {
		if ok {
			t.Log.Info("tunnel up: resolving recursively through the VPN")
		} else if t.Fallback != nil {
			t.Log.Warn("tunnel down: falling back to encrypted forwarding", "reason", why)
		} else {
			t.Log.Warn("tunnel down: blocking resolution until it returns", "reason", why)
		}
	}
	return ok
}

func (t *Tunnel) check(ctx context.Context) (bool, string) {
	if t.Interface != "" {
		ifs := t.interfaces
		if ifs == nil {
			ifs = net.Interfaces
		}
		list, err := ifs()
		if err != nil {
			return false, "listing interfaces: " + err.Error()
		}
		found := false
		for _, i := range list {
			if i.Name == t.Interface {
				found = true
				if i.Flags&net.FlagUp == 0 {
					return false, "interface " + t.Interface + " is down"
				}
			}
		}
		if !found {
			return false, "interface " + t.Interface + " not found"
		}
	}
	if len(t.Expected) > 0 {
		probe := t.EgressProbe
		if probe == nil {
			probe = func(ctx context.Context) (netip.Addr, error) { return GoogleEgress(ctx, t.Primary) }
		}
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		addr, err := probe(pctx)
		if err != nil {
			return false, "egress check: " + err.Error()
		}
		for _, p := range t.Expected {
			if p.Contains(addr) {
				return true, ""
			}
		}
		return false, "queries leave from " + addr.String() + ", which is not in expected_egress"
	}
	return true, ""
}

// Run checks every interval until ctx ends.
func (t *Tunnel) Run(ctx context.Context, interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Check(ctx)
		}
	}
}

// GoogleEgress asks Google's authoritative servers which address our
// recursive queries come from (TXT o-o.myaddr.l.google.com).
func GoogleEgress(ctx context.Context, ex Exchanger) (netip.Addr, error) {
	m := new(dns.Msg)
	m.SetQuestion("o-o.myaddr.l.google.com.", dns.TypeTXT)
	m.RecursionDesired = true
	r, err := ex.Exchange(ctx, m)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		for _, s := range txt.Txt {
			if strings.HasPrefix(s, "edns0-client-subnet") {
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				return a.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, errors.New("no address in answer")
}
