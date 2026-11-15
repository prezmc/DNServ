// Package geo says which country an address is in, from DB-IP's free
// "IP to Country Lite" database (CC BY 4.0, https://db-ip.com). It is
// optional and off by default. Lookups are for analytics (the history
// writer and the dashboard), never the query path.
//
// Each server downloads its own copy once a month (the file is published
// monthly), keeps it in its data folder and loads it into memory as two
// sorted tables of ranges, one for IPv4 and one for IPv6: a lookup is a
// binary search.
package geo

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Source names the database for the attribution its licence asks for.
const (
	SourceName = "IP to Country Lite by DB-IP"
	SourceURL  = "https://db-ip.com"
	License    = "CC BY 4.0"
)

// fileName is the local copy, as downloaded (gzipped CSV).
const fileName = "dbip-country-lite.csv.gz"

// urlFor is where a month's database is published.
func urlFor(t time.Time) string {
	return "https://download.db-ip.com/free/dbip-country-lite-" + t.Format("2006-01") + ".csv.gz"
}

// table is one loaded database. Ranges are sorted by start; each runs to
// the next start. A range with code 0 is a gap (no country).
type table struct {
	v4     []uint32
	v4cc   []uint16
	v6     [][2]uint64
	v6cc   []uint16
	ranges int
}

func pack(cc string) uint16 { return uint16(cc[0])<<8 | uint16(cc[1]) }

func unpack(c uint16) string {
	if c == 0 {
		return ""
	}
	return string([]byte{byte(c >> 8), byte(c)})
}

func v6key(a netip.Addr) [2]uint64 {
	b := a.As16()
	return [2]uint64{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func less6(a, b [2]uint64) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

func next6(k [2]uint64) ([2]uint64, bool) {
	if k[1] == ^uint64(0) {
		if k[0] == ^uint64(0) {
			return k, false
		}
		return [2]uint64{k[0] + 1, 0}, true
	}
	return [2]uint64{k[0], k[1] + 1}, true
}

// lookup returns the country code for a, "" when unknown.
func (t *table) lookup(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		i, found := slices.BinarySearch(t.v4, v)
		if !found {
			i--
		}
		if i < 0 {
			return ""
		}
		return unpack(t.v4cc[i])
	}
	if !a.Is6() {
		return ""
	}
	k := v6key(a)
	i, found := slices.BinarySearchFunc(t.v6, k, func(x, y [2]uint64) int {
		switch {
		case less6(x, y):
			return -1
		case less6(y, x):
			return 1
		}
		return 0
	})
	if !found {
		i--
	}
	if i < 0 {
		return ""
	}
	return unpack(t.v6cc[i])
}

// parse reads DB-IP's CSV: "start,end,CC" per line, ranges in order.
// Neighbouring ranges in the same country are joined, and a gap between
// ranges becomes a range with no country.
func parse(r io.Reader) (*table, error) {
	t := &table{}
	var end4 uint32
	var end6 [2]uint64
	have4, have6 := false, false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		for i := range parts {
			parts[i] = strings.Trim(strings.TrimSpace(parts[i]), `"`)
		}
		start, err1 := netip.ParseAddr(parts[0])
		end, err2 := netip.ParseAddr(parts[1])
		cc := strings.ToUpper(parts[2])
		if err1 != nil || err2 != nil || start.Is4() != end.Is4() || end.Less(start) {
			continue
		}
		code := uint16(0)
		if len(cc) == 2 && cc != "ZZ" && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
			code = pack(cc)
		}
		t.ranges++
		if start.Is4() {
			b, e := start.As4(), end.As4()
			s, en := binary.BigEndian.Uint32(b[:]), binary.BigEndian.Uint32(e[:])
			if have4 && s <= end4 {
				continue // out of order or overlapping: keep the first
			}
			if have4 && s > end4+1 {
				t.v4, t.v4cc = append(t.v4, end4+1), append(t.v4cc, 0)
			}
			if n := len(t.v4cc); n == 0 || t.v4cc[n-1] != code {
				t.v4, t.v4cc = append(t.v4, s), append(t.v4cc, code)
			}
			end4, have4 = en, true
			continue
		}
		s, en := v6key(start), v6key(end)
		if have6 && !less6(end6, s) {
			continue
		}
		if have6 {
			if nx, ok := next6(end6); ok && less6(nx, s) {
				t.v6, t.v6cc = append(t.v6, nx), append(t.v6cc, 0)
			}
		}
		if n := len(t.v6cc); n == 0 || t.v6cc[n-1] != code {
			t.v6, t.v6cc = append(t.v6, s), append(t.v6cc, code)
		}
		end6, have6 = en, true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// Past the last range: no country.
	if have4 && end4 != ^uint32(0) {
		t.v4, t.v4cc = append(t.v4, end4+1), append(t.v4cc, 0)
	}
	if have6 {
		if nx, ok := next6(end6); ok {
			t.v6, t.v6cc = append(t.v6, nx), append(t.v6cc, 0)
		}
	}
	if t.ranges == 0 {
		return nil, errors.New("no address ranges in the file")
	}
	return t, nil
}

// Status reports the database.
type Status struct {
	Enabled bool      `json:"enabled"`
	Loaded  bool      `json:"loaded"`
	Ranges  int       `json:"ranges"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
	Source  string    `json:"source"`
	URL     string    `json:"url"`
	License string    `json:"license"`
}

// DB is the current database. Lookups are lock-free.
type DB struct {
	dir     string
	client  *http.Client
	log     *slog.Logger
	cur     atomic.Pointer[table]
	enabled atomic.Bool
	status  atomic.Pointer[Status]
	onLoad  atomic.Pointer[func()]
	mu      sync.Mutex // one refresh at a time
	kick    chan struct{}
	now     func() time.Time
	url     func(time.Time) string
}

// New creates a DB that keeps its download in dir.
func New(dir string, client *http.Client, log *slog.Logger) *DB {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	d := &DB{dir: dir, client: client, log: log, kick: make(chan struct{}, 1), now: time.Now, url: urlFor}
	d.status.Store(&Status{Source: SourceName, URL: SourceURL, License: License})
	return d
}

// Country returns the two-letter country code (ISO 3166) for a, or ""
// when it isn't known or the database is off or not loaded yet.
func (d *DB) Country(a netip.Addr) string {
	if d == nil || !d.enabled.Load() {
		return ""
	}
	t := d.cur.Load()
	if t == nil || !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return ""
	}
	return t.lookup(a)
}

// Ready reports whether lookups can answer.
func (d *DB) Ready() bool { return d != nil && d.enabled.Load() && d.cur.Load() != nil }

// Status returns the database's state.
func (d *DB) Status() Status { return *d.status.Load() }

// SetOnLoad sets a function run (on the refresh goroutine) after a
// database is loaded.
func (d *DB) SetOnLoad(fn func()) { d.onLoad.Store(&fn) }

// SetEnabled turns location data on or off. Off frees the memory and
// removes the download.
func (d *DB) SetEnabled(on bool) {
	if d.enabled.Swap(on) == on {
		return
	}
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// Enabled reports whether location data is on.
func (d *DB) Enabled() bool { return d.enabled.Load() }

// Run loads the saved copy and keeps it current, checking daily.
func (d *DB) Run(ctx context.Context) {
	select {
	case <-d.kick:
	default:
	}
	d.Refresh(ctx)
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Refresh(ctx)
		case <-d.kick:
			d.Refresh(ctx)
		}
	}
}

// maxAge is how old the saved copy may get before a new month's is
// fetched; DB-IP publishes at the start of each month.
const maxAge = 30 * 24 * time.Hour

// Refresh loads the saved copy, downloading a new one when it is missing
// or a month old.
func (d *DB) Refresh(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Source: SourceName, URL: SourceURL, License: License, Enabled: d.enabled.Load()}
	path := filepath.Join(d.dir, fileName)
	if !st.Enabled {
		d.cur.Store(nil)
		os.Remove(path)
		d.status.Store(&st)
		return
	}
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		st.Error = err.Error()
	}
	fi, err := os.Stat(path)
	have := err == nil && fi.Size() > 0
	fresh := have && d.now().Sub(fi.ModTime()) < maxAge
	downloaded := false
	if !fresh {
		if err := d.download(ctx, path); err != nil {
			st.Error = err.Error()
			if have {
				st.Error += " (using the copy from " + fi.ModTime().Format("2 Jan 2006") + ")"
			}
		} else {
			downloaded = true
		}
	}
	reload := downloaded || d.cur.Load() == nil
	if reload {
		if t, err := load(path); err != nil {
			if !os.IsNotExist(err) && st.Error == "" {
				st.Error = err.Error()
			}
		} else {
			d.cur.Store(t)
			if fn := d.onLoad.Load(); fn != nil && *fn != nil {
				(*fn)()
			}
		}
	}
	if t := d.cur.Load(); t != nil {
		st.Loaded, st.Ranges = true, t.ranges
		if fi, err := os.Stat(path); err == nil {
			st.Updated = fi.ModTime()
		}
	}
	d.status.Store(&st)
	if st.Error != "" {
		d.log.Warn("location data", "err", st.Error)
	}
}

func load(path string) (*table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("location data: %w", err)
	}
	defer zr.Close()
	return parse(zr)
}

// download fetches this month's file, or last month's early in a month
// before the new one is out.
func (d *DB) download(ctx context.Context, path string) error {
	now := d.now().UTC()
	var last error
	for _, m := range []time.Time{now, time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)} {
		err := d.fetch(ctx, d.url(m), path)
		if err == nil {
			return nil
		}
		last = err
		if !errors.Is(err, errNotFound) {
			break
		}
	}
	return last
}

var errNotFound = errors.New("not published yet")

func (d *DB) fetch(ctx context.Context, src, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 100<<20)); err != nil {
		tmp.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Check it reads before replacing a good copy.
	if _, err := load(tmp.Name()); err != nil {
		return fmt.Errorf("download unreadable: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}
