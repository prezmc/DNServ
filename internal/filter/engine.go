package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prezmc/dnserv/internal/config"
)

// maxListBytes bounds a single downloaded list.
const maxListBytes = 256 << 20

// ListStatus reports the state of one list.
type ListStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Allowlist bool      `json:"allowlist"`
	Rules     int       `json:"rules"`
	Skipped   int       `json:"skipped"`
	Updated   time.Time `json:"updated"` // when this server last downloaded it
	FromCache bool      `json:"from_cache"`
	// Changed is when the list's owner last changed it, as far as can be
	// told; ChangedFrom says how: "list" (its own header), "server" (the
	// Last-Modified header) or "seen" (a download brought new contents).
	Changed     time.Time `json:"changed,omitzero"`
	ChangedFrom string    `json:"changed_from,omitempty"`
	// SHA256 identifies the downloaded copy in use; FromLeader says it
	// came from the cluster leader rather than the list's own server.
	SHA256     string `json:"sha256,omitempty"`
	FromLeader bool   `json:"from_leader,omitempty"`
	// GroupsOnly: the list is off for the household and loaded because
	// a device group uses it.
	GroupsOnly bool   `json:"groups_only,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Engine owns the current Index and rebuilds it when lists change. Lookups
// are lock-free: a rebuild compiles a new Index and swaps it in atomically.
type Engine struct {
	cfg    atomic.Pointer[config.FilteringConfig]
	dir    string
	client *http.Client
	log    *slog.Logger

	idx    atomic.Pointer[Index]
	mu     sync.Mutex // serializes rebuilds
	status atomic.Pointer[[]ListStatus]

	peer      atomic.Pointer[Peer]
	onRebuild atomic.Pointer[func(changed bool)]

	// extra are lists (by URL) that only some groups use: loaded even
	// when switched off for the household.
	extra atomic.Pointer[map[string]bool]
}

// NewEngine creates an engine. dataDir caches downloaded lists so a
// restart works without internet access.
func NewEngine(cfg config.FilteringConfig, dataDir string, client *http.Client, log *slog.Logger) *Engine {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	e := &Engine{dir: filepath.Join(dataDir, "lists"), client: client, log: log}
	e.cfg.Store(&cfg)
	empty := []ListStatus{}
	e.status.Store(&empty)
	return e
}

// Enabled reports whether filtering is on.
func (e *Engine) Enabled() bool { return e.cfg.Load().Enabled }

// SetConfig replaces the filtering settings. Call Rebuild afterwards when
// lists or rules changed; Enabled takes effect at once.
func (e *Engine) SetConfig(cfg config.FilteringConfig) { e.cfg.Store(&cfg) }

// Lookup checks a normalized name against the current index.
func (e *Engine) Lookup(name string) Match {
	if !e.cfg.Load().Enabled {
		return Match{}
	}
	return e.idx.Load().Lookup(name)
}

// LookupFor is Lookup for a group with its own Selection (nil: the
// household's).
func (e *Engine) LookupFor(name string, sel *Selection) Match {
	if !e.cfg.Load().Enabled {
		return Match{}
	}
	ix := e.idx.Load()
	if sel == nil {
		return ix.Lookup(name)
	}
	if ix == nil || sel.Empty() {
		return Match{}
	}
	return ix.LookupMask(name, sel.Mask(ix))
}

// SetGroupLists sets the lists (by URL) groups use. It reports whether
// that adds a list not loaded before, so the caller knows to Rebuild.
func (e *Engine) SetGroupLists(urls []string) (changed bool) {
	next := map[string]bool{}
	for _, u := range urls {
		next[u] = true
	}
	old := e.extra.Swap(&next)
	if old == nil {
		return len(next) > 0
	}
	return !maps.Equal(*old, next)
}

// Rules returns the number of rules in the current index.
func (e *Engine) Rules() int { return e.idx.Load().Len() }

// Status returns per-list status from the last rebuild.
func (e *Engine) Status() []ListStatus { return *e.status.Load() }

// Rebuild downloads (or reads) every list and compiles a new index. When a
// download fails the cached copy is used; when there is none, the list is
// skipped and the error is reported in Status.
func (e *Engine) Rebuild(ctx context.Context, forceDownload bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	start := time.Now()
	cfg := *e.cfg.Load()
	before := e.Versions()

	// In a cluster, use the leader's copy of each list, so every node has
	// exactly the same rules. If the leader can't be asked, download as a
	// single node would.
	var follow map[string]string
	var peer Peer
	if p := e.peer.Load(); p != nil {
		peer = *p
		vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		v, err := peer.Versions(vctx)
		cancel()
		if err == nil {
			follow = v
		}
	}

	b := NewBuilder()
	var statuses []ListStatus
	extra := map[string]bool{}
	if x := e.extra.Load(); x != nil {
		extra = *x
	}

	custom := b.AddSourceKey("Custom rules", TierCustom, "custom", true)
	for _, line := range cfg.Rules {
		if _, _, has, _ := ClientTargets(line); has {
			continue // for some devices only: the device groups apply it
		}
		rules, ok, _ := ParseLine(line)
		if !ok {
			e.log.Warn("ignoring unsupported custom rule", "rule", line)
			continue
		}
		for _, r := range rules {
			b.Add(custom, r)
		}
	}

	if cfg.BlockBypass {
		src := b.AddSourceKey("Bypass protection", TierList, "bypass", true)
		for _, d := range BypassDomains {
			b.Add(src, Rule{Domain: d, Kind: Suffix})
		}
	}

	AddServices(b, cfg.BlockedServices)

	load := func(l config.ListConfig, allow bool) {
		if !l.Enabled && !extra[l.URL] {
			return
		}
		st := ListStatus{Name: l.Name, URL: l.URL, Allowlist: allow, GroupsOnly: !l.Enabled}
		if st.Name == "" {
			st.Name = l.URL
		}
		var rc io.ReadCloser
		var fromCache bool
		var updated time.Time
		var err error
		if want := follow[l.URL]; want != "" && isURL(l.URL) {
			rc, updated, err = e.openLeaderCopy(ctx, peer, l.URL, want)
			if err == nil {
				st.FromLeader, fromCache = true, true
			} else {
				e.log.Warn("couldn't get the leader's copy of a list; downloading it here", "list", st.Name, "err", err)
			}
		}
		if rc == nil {
			rc, fromCache, updated, err = e.open(ctx, l.URL, forceDownload)
		}
		if err != nil {
			st.Error = err.Error()
			statuses = append(statuses, st)
			e.log.Warn("list unavailable", "list", st.Name, "err", err)
			return
		}
		defer rc.Close()
		src := b.AddSourceKey(st.Name, TierList, "list:"+l.URL, l.Enabled)
		ps, err := ParseList(rc, func(r Rule) {
			r.Allow = r.Allow || allow
			b.Add(src, r)
		})
		st.Rules, st.Skipped, st.FromCache, st.Updated = ps.Rules, ps.Skipped, fromCache, updated
		if err != nil {
			st.Error = err.Error()
		}
		if isURL(l.URL) {
			st.SHA256, _ = fileSHA(e.localCopy(l.URL))
		}
		st.Changed, st.ChangedFrom = listChanged(e.localCopy(l.URL))
		statuses = append(statuses, st)
	}
	for _, l := range cfg.Allowlists {
		load(l, true)
	}
	for _, l := range cfg.Lists {
		load(l, false)
	}

	idx := b.Build()
	e.idx.Store(idx)
	e.status.Store(&statuses)
	e.log.Info("filter index built", "rules", idx.Len(), "lists", len(statuses), "from_leader", follow != nil, "took", time.Since(start).Round(time.Millisecond))
	if fn := e.onRebuild.Load(); fn != nil {
		changed := !maps.Equal(before, e.Versions())
		go (*fn)(changed)
	}
	return nil
}

// openLeaderCopy opens the cached copy of src when it is the leader's
// version (want), fetching the leader's copy first if it isn't.
func (e *Engine) openLeaderCopy(ctx context.Context, peer Peer, src, want string) (io.ReadCloser, time.Time, error) {
	path := e.localCopy(src)
	if sum, err := fileSHA(path); err != nil || sum != want {
		fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := e.fetchFromPeer(fctx, peer, src, want)
		cancel()
		if err != nil {
			return nil, time.Time{}, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	fi, _ := f.Stat()
	return f, fi.ModTime(), nil
}

// Run rebuilds on the configured interval until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	every := e.cfg.Load().RefreshInterval
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Rebuild(ctx, true); err != nil {
				e.log.Error("list refresh failed", "err", err)
			}
		}
	}
}

// open returns a reader for a list. Local paths are read directly. URLs
// are served from the on-disk cache when it is fresh (unless force), else
// downloaded and cached; on download failure a stale cache is used.
func (e *Engine) open(ctx context.Context, src string, force bool) (io.ReadCloser, bool, time.Time, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		f, err := os.Open(strings.TrimPrefix(src, "file://"))
		if err != nil {
			return nil, false, time.Time{}, err
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			f.Close()
			return nil, false, time.Time{}, fmt.Errorf("list %s isn't a file", src)
		}
		// Bounded like a download, so a huge file can't stall the rebuild.
		return limitedFile{io.LimitReader(f, maxListBytes), f}, false, fi.ModTime(), nil
	}

	cachePath := e.localCopy(src)
	if fi, err := os.Stat(cachePath); err == nil && !force && time.Since(fi.ModTime()) < e.cfg.Load().RefreshInterval {
		f, err := os.Open(cachePath)
		if err == nil {
			return f, true, fi.ModTime(), nil
		}
	}

	if err := e.download(ctx, src, cachePath); err != nil {
		if f, cerr := os.Open(cachePath); cerr == nil {
			fi, _ := f.Stat()
			e.log.Warn("list download failed, using cached copy", "url", src, "err", err)
			return f, true, fi.ModTime(), nil
		}
		return nil, false, time.Time{}, err
	}
	f, err := os.Open(cachePath)
	if err != nil {
		return nil, false, time.Time{}, err
	}
	return f, false, time.Now(), nil
}

type limitedFile struct {
	io.Reader
	io.Closer
}

// DownloadURL is where a list is fetched from. GitHub file pages
// (github.com/OWNER/REPO/raw/REF/PATH or /blob/) are fetched from
// raw.githubusercontent.com, which serves the same file: the github.com
// form can answer 404 to programs even when the file exists.
func DownloadURL(src string) string {
	u, err := url.Parse(src)
	if err != nil || !strings.EqualFold(u.Host, "github.com") && !strings.EqualFold(u.Host, "www.github.com") {
		return src
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 5)
	if len(parts) != 5 || (parts[2] != "raw" && parts[2] != "blob") || parts[3] == "" || parts[4] == "" {
		return src
	}
	return "https://raw.githubusercontent.com/" + parts[0] + "/" + parts[1] + "/" + parts[3] + "/" + parts[4]
}

func (e *Engine) download(ctx context.Context, src, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DownloadURL(src), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "DNServ")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", src, resp.StatusCode)
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.dir, "dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxListBytes {
		return fmt.Errorf("download %s: list larger than %d MB", src, maxListBytes>>20)
	}
	old, _ := fileSHA(dst)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	noteCopy(dst, old, lastModified(resp.Header))
	return nil
}
