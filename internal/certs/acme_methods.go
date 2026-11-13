package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/prezmc/dnserv/internal/store"
)

// How long a helper or by-hand request waits for the records to show up.
// Let's Encrypt keeps a pending check open for 7 days.
var (
	waitForRecords = 3 * 24 * time.Hour
	waitInterval   = time.Minute
)

// manualDNS hands the TXT records to the owner and waits for them to
// appear (lego checks the authoritative name servers until they do).
type manualDNS struct {
	mu      sync.Mutex
	records []store.DNSRecord
	publish func([]store.DNSRecord)
}

func (p *manualDNS) Present(domain, _, keyAuth string) error {
	in := dns01.GetChallengeInfo(domain, keyAuth)
	p.mu.Lock()
	p.records = append(p.records, store.DNSRecord{Name: strings.TrimSuffix(in.FQDN, "."), Type: "TXT", Value: in.Value})
	recs := append([]store.DNSRecord(nil), p.records...)
	p.mu.Unlock()
	if p.publish != nil {
		p.publish(recs)
	}
	return nil
}

func (p *manualDNS) CleanUp(string, string, string) error { return nil }

func (p *manualDNS) Timeout() (time.Duration, time.Duration) { return waitForRecords, waitInterval }

// HelperCNAMEs are the one-time CNAME records the helper method needs.
func HelperCNAMEs(a *store.ACMESource) []store.DNSRecord {
	var out []store.DNSRecord
	for _, n := range a.Names {
		if acc, ok := a.HelperAccounts[n]; ok {
			out = append(out, store.DNSRecord{Name: "_acme-challenge." + n, Type: "CNAME", Value: acc.FullDomain})
		}
	}
	return out
}

// DefaultHelper is the public acme-dns server offered by default.
const DefaultHelper = "https://auth.acme-dns.io"

// RegisterHelper makes an account on an acme-dns server.
func RegisterHelper(ctx context.Context, server string) (store.HelperAccount, error) {
	var acc store.HelperAccount
	err := helperPost(ctx, strings.TrimRight(server, "/")+"/register", nil, []byte("{}"), &acc)
	if err == nil && (acc.Username == "" || acc.FullDomain == "" || acc.Subdomain == "") {
		err = errors.New("the acme-dns server sent back an incomplete account")
	}
	return acc, err
}

// helperDNS updates TXT records on an acme-dns server, where the owner's
// _acme-challenge names point with a CNAME.
type helperDNS struct {
	server   string
	accounts map[string]store.HelperAccount
}

func (p *helperDNS) Present(domain, _, keyAuth string) error {
	acc, ok := p.accounts[strings.TrimSuffix(domain, ".")]
	if !ok {
		return fmt.Errorf("no acme-dns account for %s; save the settings again", domain)
	}
	in := dns01.GetChallengeInfo(domain, keyAuth)
	body, _ := json.Marshal(map[string]string{"subdomain": acc.Subdomain, "txt": in.Value})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return helperPost(ctx, strings.TrimRight(p.server, "/")+"/update",
		map[string]string{"X-Api-User": acc.Username, "X-Api-Key": acc.Password}, body, nil)
}

func (p *helperDNS) CleanUp(string, string, string) error { return nil }

// Waits in case the owner hasn't added the CNAME yet.
func (p *helperDNS) Timeout() (time.Duration, time.Duration) { return waitForRecords, waitInterval }

var helperClient = &http.Client{Timeout: 30 * time.Second}

func helperPost(ctx context.Context, url string, headers map[string]string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := helperClient.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the acme-dns server: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the acme-dns server said %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("the acme-dns server sent something unexpected: %w", err)
		}
	}
	return nil
}
