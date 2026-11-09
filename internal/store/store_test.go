package store

import (
	"errors"
	"testing"

	"github.com/prezmc/dnserve/internal/config"
)

func mustApply(t *testing.T, s *Store, op string, d any) {
	t.Helper()
	if _, err := s.Apply(NewCommand(op, "test", d)); err != nil {
		t.Fatalf("%s: %v", op, err)
	}
}

func TestUsersAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustApply(t, s, OpUserCreate, UserCreate{ID: "a1", Username: "admin", Role: RoleAdmin, PasswordHash: "h"})
	mustApply(t, s, OpUserCreate, UserCreate{ID: "p1", Username: "pat", Role: RolePower, Perms: []string{PermRules}, PasswordHash: "h"})
	if _, err := s.Apply(NewCommand(OpUserCreate, "test", UserCreate{ID: "x", Username: "PAT", Role: RoleViewer, PasswordHash: "h"})); err == nil {
		t.Fatal("duplicate username (different case) accepted")
	}
	if _, err := s.Apply(NewCommand(OpUserCreate, "test", UserCreate{ID: "v", Username: "vic", Role: RolePower, Perms: []string{PermUsers}, PasswordHash: "h"})); err == nil {
		t.Fatal("power user given an admin-only permission")
	}

	st := s.State()
	if !st.Users["p1"].Has(PermRules) || st.Users["p1"].Has(PermUpstream) || !st.Users["p1"].Has(PermDashboard) {
		t.Fatal("power user permissions wrong")
	}

	// The last admin can't be removed or demoted.
	if _, err := s.Apply(NewCommand(OpUserDelete, "test", IDOnly{ID: "a1"})); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting last admin: %v", err)
	}
	viewer := RoleViewer
	if _, err := s.Apply(NewCommand(OpUserUpdate, "test", UserUpdate{ID: "a1", Role: &viewer})); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting last admin: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.State(); len(got.Users) != 2 || got.Version != st.Version || len(got.Audit) == 0 {
		t.Fatalf("state not persisted: users=%d version=%d audit=%d", len(got.Users), got.Version, len(got.Audit))
	}
}

func TestTOTPReplayAndRecovery(t *testing.T) {
	s, _ := Open(t.TempDir())
	mustApply(t, s, OpUserCreate, UserCreate{ID: "a1", Username: "admin", Role: RoleAdmin, PasswordHash: "h"})
	mustApply(t, s, OpTOTPBegin, TOTPBegin{ID: "a1", Secret: "S"})
	mustApply(t, s, OpTOTPConfirm, TOTPConfirm{ID: "a1", Step: 100, RecoveryHashes: []string{"r1", "r2"}})
	st := s.State()
	if !st.Users["a1"].MFAEnrolled() || !st.SetupDone {
		t.Fatal("enrollment didn't complete setup")
	}
	if _, err := s.Apply(NewCommand(OpTOTPUsed, "test", TOTPUsed{ID: "a1", Step: 100})); err == nil {
		t.Fatal("replayed step accepted")
	}
	mustApply(t, s, OpTOTPUsed, TOTPUsed{ID: "a1", Step: 101})
	mustApply(t, s, OpRecoveryUsed, RecoveryUsed{ID: "a1", Hash: "r1"})
	if _, err := s.Apply(NewCommand(OpRecoveryUsed, "test", RecoveryUsed{ID: "a1", Hash: "r1"})); err == nil {
		t.Fatal("recovery code used twice")
	}
	mustApply(t, s, OpMFAReset, IDOnly{ID: "a1"})
	if s.State().Users["a1"].MFAEnrolled() {
		t.Fatal("MFA still enrolled after reset")
	}
}

func TestSettingsOverlayAndReset(t *testing.T) {
	s, _ := Open(t.TempDir())
	var notified int
	s.Subscribe(func(old, new *State) { notified++ })
	mode := "recursive"
	rules := []string{"||ads.example^"}
	mustApply(t, s, OpSettingsUpdate, Settings{UpstreamMode: &mode, Rules: &rules})

	base := config.Default()
	eff := s.State().Settings.Overlay(base)
	if eff.Upstream.Mode != "recursive" || len(eff.Filtering.Rules) != 1 {
		t.Fatalf("overlay: %+v", eff.Upstream.Mode)
	}
	if base.Upstream.Mode == "recursive" {
		t.Fatal("overlay modified base")
	}
	mustApply(t, s, OpSettingsReset, SettingsReset{Fields: []string{"upstream_mode"}})
	if s.State().Settings.UpstreamMode != nil || s.State().Settings.Rules == nil {
		t.Fatal("reset cleared the wrong fields")
	}
	if _, err := s.Apply(NewCommand(OpSettingsReset, "test", SettingsReset{Fields: []string{"nope"}})); err == nil {
		t.Fatal("unknown field reset accepted")
	}
	if notified != 2 {
		t.Fatalf("subscribers notified %d times, want 2", notified)
	}
}
