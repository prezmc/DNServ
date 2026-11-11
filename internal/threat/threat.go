// Package threat scores domains for risk and says what kind of domain
// they are, for analytics. It never blocks anything itself.
//
// Risk comes from threat-intelligence feeds (malware, phishing and other
// threats) plus a few heuristics for names that look machine-generated or
// sit on often-abused top-level domains. Domain types and owners come from
// AdGuard's companies database. Every source is downloaded at run time,
// cached in data_dir/threat and refreshed twice a day; a source that
// can't be downloaded keeps its last copy.
package threat

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
)

// Kind is what a feed lists.
type Kind uint8

const (
	KindMalware Kind = 1 << iota
	KindPhishing
	KindThreat // mixed threat intelligence: scams, C2, malicious hosting
)

// Feed is a downloadable list of risky domains.
type Feed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Kind Kind   `json:"-"`
	// Wildcard feeds list registrable domains that cover every subdomain.
	Wildcard bool `json:"-"`
	// KeyedURL, when set, is where the feed is downloaded with an
	// abuse.ch Auth-Key, "{key}" standing for the key. Without a key the
	// feed is skipped. abuse.ch stopped keyless downloads on 21 October
	// 2026 (the old addresses answer 410 Gone).
	KeyedURL string `json:"-"`
}

// Feeds are the threat feeds DNServ uses.
var Feeds = []Feed{
	{ID: "urlhaus", Name: "URLhaus (abuse.ch) malware hosts", URL: "https://urlhaus.abuse.ch/", KeyedURL: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt", Kind: KindMalware},
	{ID: "threatfox", Name: "ThreatFox (abuse.ch) malware and C2 hosts", URL: "https://threatfox.abuse.ch/", KeyedURL: "https://threatfox-api.abuse.ch/v2/files/exports/{key}/hostfile.txt", Kind: KindMalware},
	{ID: "phishingarmy", Name: "Phishing Army", URL: "https://phishing.army/download/phishing_army_blocklist.txt", Kind: KindPhishing},
	{ID: "hagezi-tif", Name: "HaGeZi Threat Intelligence Feeds (medium)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt", Kind: KindThreat, Wildcard: true},
}

// IPFeed lists risky addresses or networks. A domain whose answer points
// into one is flagged.
type IPFeed struct {
	ID     string
	Name   string
	URL    string
	Reason string // "a botnet command server"
}

// IPFeeds are the address lists DNServ uses.
var IPFeeds = []IPFeed{
	{ID: "feodo", Name: "Feodo Tracker (abuse.ch) botnet C2 servers", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Reason: "a botnet command server (Feodo Tracker)"},
	{ID: "drop4", Name: "Spamhaus DROP (IPv4)", URL: "https://www.spamhaus.org/drop/drop_v4.json", Reason: "a hijacked or criminal network (Spamhaus DROP)"},
	{ID: "drop6", Name: "Spamhaus DROP (IPv6)", URL: "https://www.spamhaus.org/drop/drop_v6.json", Reason: "a hijacked or criminal network (Spamhaus DROP)"},
}

// Companies database (CC BY-SA 4.0, AdGuard).
const (
	trackersURL  = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/trackers.json"
	companiesURL = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/companies.json"
)

// Risk is a domain's score, 0 (nothing known) to 100.
type Risk struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"` // "", low, medium, high
	Reasons []string `json:"reasons,omitempty"`
	// Parts are the points behind the score, in the order they count.
	Parts []Part `json:"parts,omitempty"`
}

// Part is one step of a score: what counted and how many points it gave
// (or, with Cap, the most it could give).
type Part struct {
	What   string `json:"what"`
	Points int    `json:"points"`
	Note   string `json:"note,omitempty"`
}

// Type says what a domain is for and who runs it.
type Type struct {
	Category string `json:"category"`          // e.g. Advertising
	Company  string `json:"company,omitempty"` // e.g. Google
	URL      string `json:"url,omitempty"`
}

// db is one compiled snapshot of every source.
type db struct {
	feeds    map[string]uint8 // exact names -> bit i set for Feeds[i]
	wildcard map[string]uint8 // registrable domains covering subdomains
	trackers map[string]tracker
	// Address lists: single addresses, and networks grouped by prefix
	// length so a lookup is one map probe per length in use.
	ips     map[netip.Addr]uint8 // bit i set for IPFeeds[i]
	nets    map[netip.Prefix]uint8
	netBits []int
}

type tracker struct {
	category string
	company  string
	url      string
}

// SourceStatus reports one source.
type SourceStatus struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
	// NeedsKey is set for an abuse.ch feed while no Auth-Key is set.
	NeedsKey bool `json:"needs_key,omitempty"`
}

// ErrNeedsKey is the status of an abuse.ch feed without an Auth-Key.
var ErrNeedsKey = errors.New("needs a free abuse.ch Auth-Key (Settings > abuse.ch key)")

// Intel holds the current sources. Lookups are lock-free.
type Intel struct {
	dir     string
	client  *http.Client
	log     *slog.Logger
	cur     atomic.Pointer[db]
	status  atomic.Pointer[[]SourceStatus]
	enabled atomic.Bool
	trusted atomic.Pointer[[]string]
	abuseCH atomic.Pointer[string] // abuse.ch Auth-Key, "" for none
	scoring atomic.Pointer[config.RiskScoring]
	mu      sync.Mutex // one refresh at a time
	kick    chan struct{}
}

// New creates an Intel that keeps its downloads in dir.
func New(dir string, client *http.Client, log *slog.Logger) *Intel {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	in := &Intel{dir: dir, client: client, log: log, kick: make(chan struct{}, 1)}
	in.cur.Store(&db{})
	in.status.Store(&[]SourceStatus{})
	in.trusted.Store(&[]string{})
	in.abuseCH.Store(new(string))
	d := config.DefaultRiskScoring()
	in.scoring.Store(&d)
	return in
}

// SetAbuseCHKey sets the abuse.ch Auth-Key used for the URLhaus and
// ThreatFox feeds ("" for none). A new key downloads them again now.
func (in *Intel) SetAbuseCHKey(key string) {
	key = strings.TrimSpace(key)
	old := in.abuseCH.Swap(&key)
	if *old == key {
		return
	}
	for _, f := range Feeds {
		if *old == "" {
			break // first key (or startup): cached copies, if any, are fine
		}
		if f.KeyedURL != "" {
			os.Remove(filepath.Join(in.dir, f.ID+".txt"))
		}
	}
	select {
	case in.kick <- struct{}{}:
	default:
	}
}

// HasAbuseCHKey reports whether an abuse.ch Auth-Key is set.
func (in *Intel) HasAbuseCHKey() bool { return *in.abuseCH.Load() != "" }

// SetEnabled turns the threat feeds on or off. Domain types stay on (they
// are small and say nothing about risk).
func (in *Intel) SetEnabled(on bool) {
	if in.enabled.Swap(on) != on {
		select {
		case in.kick <- struct{}{}:
		default:
		}
	}
}

// Enabled reports whether threat feeds are on.
func (in *Intel) Enabled() bool { return in.enabled.Load() }

// SetTrusted sets domains (and their subdomains) that are never scored.
func (in *Intel) SetTrusted(domains []string) {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d = filter.Normalize(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	in.trusted.Store(&out)
}

// Status lists every source.
func (in *Intel) Status() []SourceStatus { return *in.status.Load() }

// Run loads cached copies, then refreshes now and every 12 hours.
func (in *Intel) Run(ctx context.Context) {
	select { // settings applied before start are covered by this refresh
	case <-in.kick:
	default:
	}
	in.Refresh(ctx, false)
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			in.Refresh(ctx, true)
		case <-in.kick:
			in.Refresh(ctx, false)
		}
	}
}

// Refresh rebuilds from the sources, downloading those that are missing
// or (with force) all of them.
func (in *Intel) Refresh(ctx context.Context, force bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := os.MkdirAll(in.dir, 0o700); err != nil {
		in.log.Warn("threat feeds: can't create folder", "err", err)
	}
	next := &db{feeds: map[string]uint8{}, wildcard: map[string]uint8{}, trackers: map[string]tracker{},
		ips: map[netip.Addr]uint8{}, nets: map[netip.Prefix]uint8{}}
	var status []SourceStatus
	feedIDs := map[string]string{}
	if in.enabled.Load() {
		for i, f := range Feeds {
			st := SourceStatus{ID: f.ID, Name: f.Name}
			src := f.URL
			if f.KeyedURL != "" {
				key := *in.abuseCH.Load()
				if key == "" {
					// Keep using a copy saved before keyless downloads ended.
					st.Error, st.NeedsKey = ErrNeedsKey.Error(), true
					path := filepath.Join(in.dir, f.ID+".txt")
					if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
						st.Updated = fi.ModTime()
						st.Entries, _ = loadFeed(path, i, f, next)
					}
					feedIDs[f.ID] = f.Name
					status = append(status, st)
					continue
				}
				src = strings.ReplaceAll(f.KeyedURL, "{key}", url.PathEscape(key))
			}
			path, updated, err := in.fetch(ctx, f.ID+".txt", src, force)
			st.Updated = updated
			if err != nil {
				st.Error = err.Error()
			}
			if path != "" {
				n, err := loadFeed(path, i, f, next)
				st.Entries = n
				if err != nil && st.Error == "" {
					st.Error = err.Error()
				}
			}
			feedIDs[f.ID] = f.Name
			status = append(status, st)
		}
		for i, f := range IPFeeds {
			st := SourceStatus{ID: f.ID, Name: f.Name}
			path, updated, err := in.fetch(ctx, f.ID+".txt", f.URL, force)
			st.Updated = updated
			if err != nil {
				st.Error = err.Error()
			}
			if path != "" {
				n, err := loadIPFeed(path, i, next)
				st.Entries = n
				if err != nil && st.Error == "" {
					st.Error = err.Error()
				}
			}
			status = append(status, st)
		}
		bits := map[int]bool{}
		for p := range next.nets {
			bits[p.Bits()] = true
		}
		for b := range bits {
			next.netBits = append(next.netBits, b)
		}
	} else {
		// Turned off: free the memory and the disk.
		for _, f := range Feeds {
			os.Remove(filepath.Join(in.dir, f.ID+".txt"))
		}
		for _, f := range IPFeeds {
			os.Remove(filepath.Join(in.dir, f.ID+".txt"))
		}
	}
	st := SourceStatus{ID: "companiesdb", Name: "AdGuard companies database (domain types and owners)"}
	tp, updated, err1 := in.fetch(ctx, "trackers.json", trackersURL, force)
	cp, _, err2 := in.fetch(ctx, "companies.json", companiesURL, force)
	st.Updated = updated
	if err := errors.Join(err1, err2); err != nil {
		st.Error = err.Error()
	}
	if tp != "" && cp != "" {
		n, err := loadCompanies(tp, cp, next)
		st.Entries = n
		if err != nil && st.Error == "" {
			st.Error = err.Error()
		}
	}
	status = append(status, st)
	in.cur.Store(next)
	in.status.Store(&status)
}

// fetch returns the local copy of src, downloading it when missing,
// older than 12 hours (force) or empty.
func (in *Intel) fetch(ctx context.Context, file, src string, force bool) (string, time.Time, error) {
	path := filepath.Join(in.dir, file)
	fi, statErr := os.Stat(path)
	have := statErr == nil && fi.Size() > 0
	if have && (!force || time.Since(fi.ModTime()) < 11*time.Hour) {
		return path, fi.ModTime(), nil
	}
	err := in.download(ctx, src, path)
	if fi2, e := os.Stat(path); e == nil && fi2.Size() > 0 {
		return path, fi2.ModTime(), err
	}
	return "", time.Time{}, err
}

// download saves src to path. Errors never include src, which can hold
// an Auth-Key.
func (in *Intel) download(ctx context.Context, src, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return errors.New("download failed: bad address")
	}
	resp, err := in.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		if strings.Contains(src, ".abuse.ch/v2/") {
			return fmt.Errorf("download failed: HTTP %d, check the abuse.ch Auth-Key", resp.StatusCode)
		}
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 200<<20)); err != nil {
		tmp.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loadFeed(path string, idx int, f Feed, d *db) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	target := d.feeds
	if f.Wildcard {
		target = d.wildcard
	}
	n := 0
	for sc.Scan() {
		rules, ok, _ := filter.ParseLine(sc.Text())
		if !ok {
			continue
		}
		for _, r := range rules {
			if r.Allow || r.Bad || r.Kind == filter.Pattern || r.Domain == "" || r.Domain == "localhost" {
				continue
			}
			if target[r.Domain]&(1<<idx) == 0 {
				target[r.Domain] |= 1 << idx
				n++
			}
		}
	}
	return n, sc.Err()
}

// loadIPFeed reads addresses or networks, one per line: plain text
// ("1.2.3.4", "1.2.3.0/24 ; SBL123") or JSON lines ({"cidr": "..."}).
func loadIPFeed(path string, idx int, d *db) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '{' {
			var v struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(line), &v) != nil || v.CIDR == "" {
				continue
			}
			line = v.CIDR
		}
		if i := strings.IndexAny(line, " \t;"); i >= 0 {
			line = line[:i]
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			p = p.Masked()
			if p.IsSingleIP() {
				d.ips[p.Addr().Unmap()] |= 1 << idx
			} else {
				d.nets[p] |= 1 << idx
			}
			n++
		} else if a, err := netip.ParseAddr(line); err == nil {
			d.ips[a.Unmap()] |= 1 << idx
			n++
		}
	}
	return n, sc.Err()
}

// ipFeeds returns the feeds that list a (bit i for IPFeeds[i]).
func (d *db) ipFeeds(a netip.Addr) uint8 {
	a = a.Unmap()
	m := d.ips[a]
	for _, b := range d.netBits {
		if b > a.BitLen() {
			continue
		}
		if p, err := a.Prefix(b); err == nil {
			m |= d.nets[p]
		}
	}
	return m
}

// CheckAnswer rates what a domain resolved to: addresses on an IP threat
// list, or a CNAME to a risky domain. It is meant for the history writer,
// off the query path.
func (in *Intel) CheckAnswer(name string, ips []netip.Addr, cnames []string) (int, string) {
	name = filter.Normalize(name)
	if in.trustedName(name) {
		return 0, ""
	}
	d := in.cur.Load()
	sc := in.scoring.Load()
	best, why := 0, ""
	for _, a := range ips {
		m := d.ipFeeds(a)
		for i, f := range IPFeeds {
			if pts := sc.Feeds[f.ID]; i < 8 && m&(1<<i) != 0 && pts > best {
				best, why = pts, "Answered with "+a.String()+", "+f.Reason
			}
		}
	}
	for _, c := range cnames {
		if r := in.Score(c); r.Score >= sc.Medium && r.Score > best {
			best, why = r.Score, "Points to "+c+" ("+strings.Join(r.Reasons, "; ")+")"
		}
	}
	return best, why
}

func (in *Intel) trustedName(name string) bool {
	for _, t := range *in.trusted.Load() {
		if name == t || strings.HasSuffix(name, "."+t) {
			return true
		}
	}
	return false
}

func loadCompanies(trackersPath, companiesPath string, d *db) (int, error) {
	var tr struct {
		Categories map[string]string `json:"categories"`
		Trackers   map[string]struct {
			Name       string `json:"name"`
			CategoryID int    `json:"categoryId"`
			URL        string `json:"url"`
			CompanyID  string `json:"companyId"`
		} `json:"trackers"`
		TrackerDomains map[string]string `json:"trackerDomains"`
	}
	var co struct {
		Companies map[string]struct {
			Name string `json:"name"`
			URL  string `json:"websiteUrl"`
		} `json:"companies"`
	}
	for _, x := range []struct {
		path string
		v    any
	}{{trackersPath, &tr}, {companiesPath, &co}} {
		b, err := os.ReadFile(x.path)
		if err != nil {
			return 0, err
		}
		if err := json.Unmarshal(b, x.v); err != nil {
			return 0, fmt.Errorf("companies database: %w", err)
		}
	}
	for dom, tid := range tr.TrackerDomains {
		t, ok := tr.Trackers[tid]
		if !ok {
			continue
		}
		v := tracker{category: categoryName(tr.Categories[fmt.Sprint(t.CategoryID)]), company: t.Name, url: t.URL}
		if c, ok := co.Companies[t.CompanyID]; ok && c.Name != "" {
			v.company = c.Name
			if c.URL != "" {
				v.url = c.URL
			}
		}
		d.trackers[filter.Normalize(dom)] = v
	}
	return len(d.trackers), nil
}

// categoryName turns "site_analytics" into "Site analytics".
func categoryName(c string) string {
	switch c {
	case "", "unknown":
		return "Other"
	case "cdn":
		return "Content delivery"
	case "pornvertising":
		return "Adult advertising"
	case "misc":
		return "Other"
	}
	c = strings.ReplaceAll(c, "_", " ")
	return strings.ToUpper(c[:1]) + c[1:]
}

// parents yields name and each parent domain, longest first.
func parents(name string, fn func(string) bool) {
	for {
		if !fn(name) {
			return
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return
		}
		name = name[i+1:]
	}
}

// TypeOf says what kind of domain name is, if known.
func (in *Intel) TypeOf(name string) *Type {
	d := in.cur.Load()
	var out *Type
	parents(filter.Normalize(name), func(n string) bool {
		if t, ok := d.trackers[n]; ok {
			out = &Type{Category: t.category, Company: t.company, URL: t.url}
			return false
		}
		return true
	})
	return out
}

// dga reports whether a label looks randomly generated: long, high
// character entropy and few vowels.
func dga(l string) bool {
	if len(l) < 12 || strings.Contains(l, "-") {
		return false
	}
	var counts [256]int
	vowels := 0
	for i := 0; i < len(l); i++ {
		counts[l[i]]++
		if strings.IndexByte("aeiou", l[i]) >= 0 {
			vowels++
		}
	}
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(len(l))
			h -= p * math.Log2(p)
		}
	}
	return h > 3.5 && float64(vowels)/float64(len(l)) < 0.3
}
