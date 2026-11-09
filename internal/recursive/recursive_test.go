package recursive

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestConfigRendersHardening(t *testing.T) {
	conf, err := Config(Options{Dir: "/data/unbound", Port: 5335, CacheMB: 96, ServeExpired: time.Hour, OutgoingInterface: "10.64.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"interface: 127.0.0.1@5335", "qname-minimisation: yes", "use-caps-for-id: yes",
		"harden-dnssec-stripped: yes", "aggressive-nsec: yes", "auto-trust-anchor-file: \"/data/unbound/root.key\"",
		"serve-expired-ttl: 3600", "outgoing-interface: 10.64.0.2", "msg-cache-size: 32m", "rrset-cache-size: 64m",
		"private-address: 192.168.0.0/16", "module-config: \"validator iterator\"",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q", want)
		}
	}
	plain, _ := Config(Options{Dir: "/d", Port: 5335})
	if strings.Contains(plain, "outgoing-interface") || strings.Contains(plain, "serve-expired: yes") {
		t.Error("optional sections should be omitted when unset")
	}
}

// TestUnboundLifecycle runs the real Unbound when it is installed: the
// generated config must pass unbound-checkconf, the local health record
// must answer without network access, and a crash must be restarted.
func TestUnboundLifecycle(t *testing.T) {
	if _, err := exec.LookPath("unbound"); err != nil {
		t.Skip("unbound not installed")
	}
	anchorFound := false
	for _, p := range TrustAnchorSources {
		if _, err := os.Stat(p); err == nil {
			anchorFound = true
		}
	}
	if !anchorFound {
		t.Skip("no DNSSEC trust anchor installed")
	}
	port := freePort(t)
	u := New(Options{Binary: "unbound", Dir: filepath.Join(t.TempDir(), "unbound"), Port: port, CacheMB: 16}, quiet())
	path, err := u.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx, path); close(done) }()
	defer func() { cancel(); <-done }()

	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := u.WaitReady(wctx); err != nil {
		t.Fatal(err)
	}

	// Kill it; the supervisor must bring it back.
	exec.Command("pkill", "-f", "unbound -d -p -c "+path).Run()
	deadline := time.Now().Add(15 * time.Second)
	for u.Restarts() == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if u.Restarts() == 0 {
		t.Fatal("unbound exit was not noticed")
	}
	wctx2, wcancel2 := context.WithTimeout(ctx, 15*time.Second)
	defer wcancel2()
	if err := u.WaitReady(wctx2); err != nil {
		t.Fatal("unbound was not restarted:", err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

type stub struct {
	name  string
	calls int
}

func (s *stub) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	s.calls++
	r := new(dns.Msg)
	r.SetReply(q)
	return r, nil
}

func TestTunnelStates(t *testing.T) {
	primary, fallback := &stub{name: "p"}, &stub{name: "f"}
	ifUp := true
	egress := netip.MustParseAddr("185.65.0.10")
	tun := &Tunnel{
		Primary: primary, Fallback: fallback, Interface: "wg0",
		Expected:    []netip.Prefix{netip.MustParsePrefix("185.65.0.0/16")},
		EgressProbe: func(context.Context) (netip.Addr, error) { return egress, nil },
		Log:         quiet(),
	}
	tun.interfaces = func() ([]net.Interface, error) {
		if !ifUp {
			return []net.Interface{{Name: "eth0", Flags: net.FlagUp}}, nil
		}
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp}, {Name: "wg0", Flags: net.FlagUp}}, nil
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()

	if !tun.Check(ctx) {
		_, why := tun.Up()
		t.Fatal("tunnel should be up:", why)
	}
	tun.Exchange(ctx, q)
	if primary.calls != 1 {
		t.Fatal("up tunnel must use the primary")
	}

	ifUp = false
	if tun.Check(ctx) {
		t.Fatal("missing interface must mark the tunnel down")
	}
	tun.Exchange(ctx, q)
	if fallback.calls != 1 {
		t.Fatal("down tunnel must use the fallback")
	}

	ifUp = true
	egress = netip.MustParseAddr("203.0.113.5") // the ISP's address: a leak
	if tun.Check(ctx) {
		t.Fatal("unexpected egress must mark the tunnel down")
	}
	if _, why := tun.Up(); !strings.Contains(why, "203.0.113.5") {
		t.Fatalf("reason should name the leaking address, got %q", why)
	}

	tun.Fallback = nil
	if _, err := tun.Exchange(ctx, q); !errors.Is(err, ErrTunnelDown) {
		t.Fatalf("block mode must refuse, got %v", err)
	}
}

func TestGoogleEgressParsing(t *testing.T) {
	ex := exchangerFunc(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"185.65.1.2"}}}
		return r, nil
	})
	a, err := GoogleEgress(context.Background(), ex)
	if err != nil || a.String() != "185.65.1.2" {
		t.Fatalf("got %v %v", a, err)
	}
}

type exchangerFunc func(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

func (f exchangerFunc) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) { return f(ctx, q) }
