package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Peer lets a cluster member use the leader's copy of each list, so every
// node filters with exactly the same rules. Without one (or when it
// returns an error, for example on the leader itself) a node downloads
// lists on its own.
type Peer interface {
	// Versions returns the SHA-256 of each list the leader is using, by
	// URL.
	Versions(ctx context.Context) (map[string]string, error)
	// Fetch writes the leader's copy of the list with this SHA-256 to w.
	Fetch(ctx context.Context, sha string, w io.Writer) error
}

// SetPeer sets (or, with nil, clears) where to get the leader's lists.
func (e *Engine) SetPeer(p Peer) {
	if p == nil {
		e.peer.Store(nil)
		return
	}
	e.peer.Store(&p)
}

// SetOnRebuild runs fn (in its own goroutine) after every rebuild, with
// whether any list's contents changed.
func (e *Engine) SetOnRebuild(fn func(changed bool)) { e.onRebuild.Store(&fn) }

// Versions returns the SHA-256 of each downloaded list in the current
// index, by URL.
func (e *Engine) Versions() map[string]string {
	out := map[string]string{}
	for _, s := range e.Status() {
		if s.SHA256 != "" {
			out[s.URL] = s.SHA256
		}
	}
	return out
}

// FileBySHA returns the path of a list in the current index with this
// SHA-256, for serving to other nodes.
func (e *Engine) FileBySHA(sha string) (string, bool) {
	for _, s := range e.Status() {
		if s.SHA256 != "" && s.SHA256 == sha && isURL(s.URL) {
			return e.localCopy(s.URL), true
		}
	}
	return "", false
}

func isURL(s string) bool { return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") }

// fileSHA returns a cached list's SHA-256, from its sidecar file when it
// is current, else by reading the list (and then saving the sidecar).
func fileSHA(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	side := path + ".sha256"
	if b, err := os.ReadFile(side); err == nil {
		if sum, mod, ok := strings.Cut(strings.TrimSpace(string(b)), " "); ok && mod == fi.ModTime().UTC().Format(time.RFC3339Nano) && len(sum) == 64 {
			return sum, nil
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	_ = os.WriteFile(side, []byte(sum+" "+fi.ModTime().UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
	return sum, nil
}

// fetchFromPeer replaces the cached copy of src with the leader's, which
// must have the given SHA-256.
func (e *Engine) fetchFromPeer(ctx context.Context, p Peer, src, want string) error {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.dir, "peer-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	lw := &limitWriter{w: io.MultiWriter(tmp, h), n: maxListBytes}
	ferr := p.Fetch(ctx, want, lw)
	if cerr := tmp.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr != nil {
		return ferr
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("the leader's copy doesn't match (got %s, want %s)", got[:12], want[:12])
	}
	dst := e.localCopy(src)
	old, _ := fileSHA(dst)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	noteCopy(dst, old, time.Time{}) // also writes the SHA-256 sidecar
	return nil
}

type limitWriter struct {
	w io.Writer
	n int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("list larger than the size limit")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}
