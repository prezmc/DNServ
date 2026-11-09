package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prezmc/dnserve/internal/config"
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
	Updated   time.Time `json:"updated"`
	FromCache bool      `json:"from_cache"`
	Error     string    `json:"error,omitempty"`
}

// Engine owns the current Index and rebuilds it when lists change. Lookups
// are lock-free: a rebuild compiles a new Index and swaps it in atomically.
type Engine struct {
	cfg    config.FilteringConfig
	dir    string
	client *http.Client
	log    *slog.Logger

	idx    atomic.Pointer[Index]
	mu     sync.Mutex // serializes rebuilds
	status atomic.Pointer[[]ListStatus]
}

// NewEngine creates an engine. dataDir caches downloaded lists so a
// restart works without internet access.
func NewEngine(cfg config.FilteringConfig, dataDir string, client *http.Client, log *slog.Logger) *Engine {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	e := &Engine{cfg: cfg, dir: filepath.Join(dataDir, "lists"), client: client, log: log}
	empty := []ListStatus{}
	e.status.Store(&empty)
	return e
}

// Enabled reports whether filtering is on.
func (e *Engine) Enabled() bool { return e.cfg.Enabled }

// Lookup checks a normalized name against the current index.
func (e *Engine) Lookup(name string) Match {
	if !e.cfg.Enabled {
		return Match{}
	}
	return e.idx.Load().Lookup(name)
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

	b := NewBuilder()
	var statuses []ListStatus

	custom := b.AddSource("Custom rules", TierCustom)
	for _, line := range e.cfg.Rules {
		rules, ok, _ := ParseLine(line)
		if !ok {
			e.log.Warn("ignoring unsupported custom rule", "rule", line)
			continue
		}
		for _, r := range rules {
			b.Add(custom, r)
		}
	}

	load := func(l config.ListConfig, allow bool) {
		if !l.Enabled {
			return
		}
		st := ListStatus{Name: l.Name, URL: l.URL, Allowlist: allow}
		if st.Name == "" {
			st.Name = l.URL
		}
		rc, fromCache, updated, err := e.open(ctx, l.URL, forceDownload)
		if err != nil {
			st.Error = err.Error()
			statuses = append(statuses, st)
			e.log.Warn("list unavailable", "list", st.Name, "err", err)
			return
		}
		defer rc.Close()
		src := b.AddSource(st.Name, TierList)
		ps, err := ParseList(rc, func(r Rule) {
			r.Allow = r.Allow || allow
			b.Add(src, r)
		})
		st.Rules, st.Skipped, st.FromCache, st.Updated = ps.Rules, ps.Skipped, fromCache, updated
		if err != nil {
			st.Error = err.Error()
		}
		statuses = append(statuses, st)
	}
	for _, l := range e.cfg.Allowlists {
		load(l, true)
	}
	for _, l := range e.cfg.Lists {
		load(l, false)
	}

	idx := b.Build()
	e.idx.Store(idx)
	e.status.Store(&statuses)
	e.log.Info("filter index built", "rules", idx.Len(), "lists", len(statuses), "took", time.Since(start).Round(time.Millisecond))
	return nil
}

// Run rebuilds on the configured interval until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	if e.cfg.RefreshInterval <= 0 {
		return
	}
	t := time.NewTicker(e.cfg.RefreshInterval)
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
		fi, _ := f.Stat()
		return f, false, fi.ModTime(), nil
	}

	sum := sha256.Sum256([]byte(src))
	cachePath := filepath.Join(e.dir, hex.EncodeToString(sum[:8])+".txt")
	if fi, err := os.Stat(cachePath); err == nil && !force && time.Since(fi.ModTime()) < e.cfg.RefreshInterval {
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

func (e *Engine) download(ctx context.Context, src, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "DNServe")
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
	return os.Rename(tmp.Name(), dst)
}
