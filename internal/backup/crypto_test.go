package backup

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

func TestSealOpen(t *testing.T) {
	pub, salt, err := NewKey("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.BackupConfig{PublicKey: pub, Salt: salt}
	data := store.BackupData{SetupDone: true, ConfigSeq: 7}
	file, err := Seal(data, cfg, Header{Node: "a"})
	if err != nil {
		t.Fatal(err)
	}
	h, got, err := Open(file, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if h.Node != "a" || !got.SetupDone || got.ConfigSeq != 7 {
		t.Fatalf("round trip: %+v %+v", h, got)
	}
	if _, _, err := Open(file, "wrong passphrase here"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	bad := append([]byte{}, file...)
	bad[len(bad)-1] ^= 1
	if _, _, err := Open(bad, "correct horse battery staple"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("tampered: %v", err)
	}
	if _, _, err := Open([]byte("hello"), "x"); err == nil {
		t.Fatal("non-backup accepted")
	}
	if _, _, err := NewKey("short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestDue(t *testing.T) {
	cfg := store.BackupConfig{PublicKey: "k", Salt: "s", Every: "daily", At: "03:00"}
	loc := time.UTC
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, loc) // a Monday
	slot, ok := Due(cfg, time.Time{}, now)
	if !ok || !slot.Equal(time.Date(2026, 11, 9, 3, 0, 0, 0, loc)) {
		t.Fatalf("daily: %v %v", slot, ok)
	}
	if _, ok := Due(cfg, now.Add(-time.Hour), now); ok {
		t.Fatal("ran after the slot already")
	}
	early := time.Date(2026, 11, 9, 2, 0, 0, 0, loc)
	if slot, _ := Due(cfg, time.Time{}, early); slot.Day() != 8 {
		t.Fatalf("before today's time: %v", slot)
	}
	cfg.Every = "weekly"
	slot, ok = Due(cfg, time.Date(2026, 11, 8, 4, 0, 0, 0, loc), now)
	if ok || slot.Weekday() != time.Sunday || slot.Day() != 8 {
		t.Fatalf("weekly: %v %v", slot, ok)
	}
	cfg.Every = ""
	if _, ok := Due(cfg, time.Time{}, now); ok {
		t.Fatal("on-demand only")
	}
}

func TestRunDueKeepsAndPrunes(t *testing.T) {
	dir, off := t.TempDir(), t.TempDir()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, salt, _ := NewKey("correct horse battery staple")
	if _, err := st.Apply(store.NewCommand(store.OpBackupConfig, "t", store.BackupConfig{PublicKey: pub, Salt: salt, Every: "daily", At: "03:00", Keep: 2, Offsite: off})); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	leader := false
	m := &Manager{Store: st, Dir: dir, Node: func() string { return "node a" }, IsLeader: func() bool { return leader },
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}
	if err := m.RunDue(); err != nil {
		t.Fatal(err)
	}
	if f := listDir(dir, "local"); len(f) != 0 {
		t.Fatalf("backed up the slot before the schedule began: %+v", f)
	}
	now = now.AddDate(0, 0, 1)
	for i := range 4 {
		leader = i == 3
		if err := m.RunDue(); err != nil {
			t.Fatal(err)
		}
		if err := m.RunDue(); err != nil { // same slot: nothing
			t.Fatal(err)
		}
		now = now.AddDate(0, 0, 1)
	}
	local := listDir(dir, "local")
	if len(local) != 2 || !strings.HasPrefix(local[0].Name, "dnserv-node-a-20261105") {
		t.Fatalf("local: %+v", local)
	}
	if o := listDir(off, "offsite"); len(o) != 1 {
		t.Fatalf("offsite: %+v", o)
	}
	b, err := m.Read("local", local[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(b, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Read("local", "../etc/passwd"); err == nil {
		t.Fatal("path escape")
	}
}
