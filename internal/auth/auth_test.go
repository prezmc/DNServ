package auth

import (
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("right password rejected")
	}
	if VerifyPassword(h, "correct horse batterY") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("garbage", "x") {
		t.Fatal("bad hash accepted")
	}
}

func TestPasswordStrength(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short":               false,
		"aaaaaaaaaaaaaaaa":    false,
		"alice-is-the-best!1": false, // contains username
		"plum orchard 42 sky": true,
	} {
		if err := CheckPasswordStrength(pw, "alice"); (err == nil) != ok {
			t.Errorf("%q: err=%v, want ok=%v", pw, err, ok)
		}
	}
}

// RFC 6238 appendix B vectors (SHA1), truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %q, want %q (%v)", ts, got, want, err)
		}
	}
}

func TestVerifyTOTPSkew(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	prev, _ := TOTPCode(secret, now.Add(-30*time.Second))
	if step, ok := VerifyTOTP(secret, prev, now); !ok || step != now.Unix()/30-1 {
		t.Fatalf("previous step: ok=%v step=%d", ok, step)
	}
	old, _ := TOTPCode(secret, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(secret, old, now); ok {
		t.Fatal("code from 3 steps ago accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now); ok {
		t.Fatal("short code accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes := NewRecoveryCodes(10)
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatal("wrong count")
	}
	if HashToken(NormalizeRecovery(" "+toUpper(codes[0])+" ")) != hashes[0] {
		t.Fatal("normalized code doesn't match its hash")
	}
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func TestSessions(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSessions(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	tok, x := s.Create("u1", StageMFA, "1.2.3.4", "test")
	if g := s.Get(tok); g == nil || g.Stage != StageMFA {
		t.Fatal("session not found")
	}
	full, y, ok := s.Promote(tok, StageFull)
	if !ok || y.ID != x.ID || y.CSRF == x.CSRF {
		t.Fatal("promote failed or didn't rotate CSRF")
	}
	if s.Get(tok) != nil {
		t.Fatal("old token still works after promote")
	}
	// Survives a restart.
	s2, _ := OpenSessions(dir)
	s2.now = s.now
	if s2.Get(full) == nil {
		t.Fatal("session lost on reload")
	}
	now = now.Add(IdleTTL + time.Minute)
	if s2.Get(full) != nil {
		t.Fatal("idle session not expired")
	}
}

func TestPendingSessionExpires(t *testing.T) {
	s, _ := OpenSessions(t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	tok, _ := s.Create("u1", StageMFA, "", "")
	now = now.Add(PendingTTL + time.Second)
	if s.Get(tok) != nil {
		t.Fatal("pending session outlived its TTL")
	}
}

func TestThrottle(t *testing.T) {
	th := NewThrottle()
	now := time.Unix(1_700_000_000, 0)
	th.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		th.Fail("k")
	}
	if ok, _ := th.Allowed("k"); !ok {
		t.Fatal("blocked too early")
	}
	th.Fail("k")
	if ok, wait := th.Allowed("k"); ok || wait <= 0 {
		t.Fatal("not blocked after 5 failures")
	}
	th.Succeed("k")
	if ok, _ := th.Allowed("k"); !ok {
		t.Fatal("still blocked after success")
	}
}
