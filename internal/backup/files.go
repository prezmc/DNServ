package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// Ext is the backup file extension.
const Ext = ".dnsbak"

// DefaultKeep is how many scheduled backups are kept when Keep is 0.
const DefaultKeep = 14

// Manager makes backups for one node and keeps them in Dir.
type Manager struct {
	Store   *store.Store
	Dir     string // local folder, normally /data/backups
	Node    func() string
	Cluster func() string // cluster ID
	// IsLeader says whether this node writes to the off-box folder, so a
	// cluster writes each scheduled backup there once.
	IsLeader func() bool
	Version  string
	// Loc is the time zone schedules run in (nil: the container's).
	Loc func() *time.Location
	Log *slog.Logger
	Now func() time.Time
}

// File is a stored backup.
type File struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
	Node    string    `json:"node"`
	Where   string    `json:"where"` // "local" or "offsite"
}

func (m *Manager) now() time.Time {
	t := time.Now()
	if m.Now != nil {
		t = m.Now()
	}
	if m.Loc != nil {
		t = t.In(m.Loc())
	}
	return t
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// FileName is a backup's name: node and time, so files from several
// nodes can share a folder.
func FileName(node string, t time.Time) string {
	n := strings.Trim(unsafeName.ReplaceAllString(node, "-"), "-")
	if n == "" {
		n = "node"
	}
	return fmt.Sprintf("dnserv-%s-%s%s", n, t.UTC().Format("20060102-150405"), Ext)
}

// Make encrypts the current state into a backup file.
func (m *Manager) Make() (name string, file []byte, err error) {
	st := m.Store.State()
	t := m.now().UTC()
	h := Header{Created: t, Version: m.Version}
	if m.Node != nil {
		h.Node = m.Node()
	}
	if m.Cluster != nil {
		h.ClusterID = m.Cluster()
	}
	file, err = Seal(st.BackupData(), st.Backup, h)
	return FileName(h.Node, t), file, err
}

// Due reports the scheduled time that a backup is due for: the latest
// slot at or before now, when that is after last. ok is false when
// nothing is due.
func Due(cfg store.BackupConfig, last, now time.Time) (slot time.Time, ok bool) {
	if cfg.Every == "" || !cfg.Configured() {
		return time.Time{}, false
	}
	at, err := time.Parse("15:04", cfg.At)
	if err != nil {
		return time.Time{}, false
	}
	slot = time.Date(now.Year(), now.Month(), now.Day(), at.Hour(), at.Minute(), 0, 0, now.Location())
	if slot.After(now) {
		slot = slot.AddDate(0, 0, -1)
	}
	if cfg.Every == "weekly" {
		slot = slot.AddDate(0, 0, -int(slot.Weekday())) // back to Sunday
	}
	return slot, last.Before(slot)
}

const lastFile = ".last-scheduled"

func (m *Manager) last() time.Time {
	b, err := os.ReadFile(filepath.Join(m.Dir, lastFile))
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	return t
}

// Run makes scheduled backups until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if err := m.RunDue(); err != nil {
			m.Log.Warn("scheduled backup failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// RunDue makes a scheduled backup if one is due.
func (m *Manager) RunDue() error {
	cfg := m.Store.State().Backup
	now := m.now()
	last := m.last()
	if _, ok := Due(cfg, last, now); !ok {
		return nil
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	if last.IsZero() {
		// Schedule just turned on: start from the next slot, as the
		// dashboard says, rather than backfilling the one just past.
		return os.WriteFile(filepath.Join(m.Dir, lastFile), []byte(now.UTC().Format(time.RFC3339)), 0o600)
	}
	// Record the run first, so a failing backup is retried at the next
	// slot rather than every minute.
	if err := os.WriteFile(filepath.Join(m.Dir, lastFile), []byte(now.UTC().Format(time.RFC3339)), 0o600); err != nil {
		return err
	}
	name, file, err := m.Make()
	if err != nil {
		return err
	}
	keep := cfg.Keep
	if keep == 0 {
		keep = DefaultKeep
	}
	var errs []error
	if err := writeFile(m.Dir, name, file); err != nil {
		errs = append(errs, err)
	} else {
		m.Log.Info("backup saved", "file", filepath.Join(m.Dir, name))
		prune(m.Dir, keep, m.Log)
	}
	if cfg.Offsite != "" && (m.IsLeader == nil || m.IsLeader()) {
		if err := writeFile(cfg.Offsite, name, file); err != nil {
			errs = append(errs, fmt.Errorf("off-box folder: %w", err))
		} else {
			m.Log.Info("backup copied off the box", "file", filepath.Join(cfg.Offsite, name))
			prune(cfg.Offsite, keep, m.Log)
		}
	}
	return errors.Join(errs...)
}

func writeFile(dir, name string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

func listDir(dir, where string) []File {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []File
	for _, e := range ents {
		if e.IsDir() || !isBackupName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		f := File{Name: e.Name(), Size: info.Size(), Created: info.ModTime().UTC(), Where: where}
		if b, err := readHead(filepath.Join(dir, e.Name())); err == nil {
			if h, _, _, err := ReadHeader(b); err == nil {
				f.Created, f.Node = h.Created, h.Node
			}
		}
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b File) int { return b.Created.Compare(a.Created) })
	return out
}

// readHead reads enough of a file for its header.
func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 4096)
	n, _ := f.Read(b)
	return b[:n], nil
}

func prune(dir string, keep int, log *slog.Logger) {
	files := listDir(dir, "")
	for _, f := range files[min(keep, len(files)):] {
		if err := os.Remove(filepath.Join(dir, f.Name)); err != nil {
			log.Warn("couldn't remove an old backup", "file", f.Name, "err", err)
		}
	}
}

// List returns the stored backups, newest first: this node's, then the
// off-box folder's.
func (m *Manager) List() []File {
	out := listDir(m.Dir, "local")
	if off := m.Store.State().Backup.Offsite; off != "" {
		out = append(out, listDir(off, "offsite")...)
	}
	return out
}

// Read returns a stored backup by name.
func (m *Manager) Read(where, name string) ([]byte, error) {
	if name != filepath.Base(name) || !isBackupName(name) {
		return nil, errors.New("no such backup")
	}
	dir := m.Dir
	if where == "offsite" {
		dir = m.Store.State().Backup.Offsite
		if dir == "" {
			return nil, errors.New("no such backup")
		}
	}
	return os.ReadFile(filepath.Join(dir, name))
}

// isBackupName reports whether name looks like a backup file. Files made
// before the rename to DNServ start with "dnserve-" and still count.
func isBackupName(name string) bool {
	return (strings.HasPrefix(name, "dnserv-") || strings.HasPrefix(name, "dnserve-")) && strings.HasSuffix(name, Ext)
}
