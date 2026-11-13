package filter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHeaderDate(t *testing.T) {
	for _, tc := range []struct{ head, want string }{
		{"! Title: AdGuard DNS filter\n! Last modified: 2026-11-12T12:31:38.522Z\n||ads.example^", "2026-11-12T12:31:38Z"},
		{"# Title: HaGeZi's Pro DNS Blocklist\n# Version: 2026.1112.1021.44\n# Syntax: Adblock\n||x^", "2026-11-12T10:21:00Z"},
		{"[Adblock Plus]\n! Last modified: 12 Nov 2026 10:21 UTC\n||x^", "2026-11-12T10:21:00Z"},
		{"# Title: StevenBlack/hosts\n# Date: 12 November 2026 05:44:12 (UTC)\n0.0.0.0 x", "2026-11-12T05:44:12Z"},
		{"# Updated: 2026-10-01\n0.0.0.0 x", "2026-10-01T00:00:00Z"},
		{"\ufeff[Adblock Plus 3.13]\n! Version: 08November2026v3\n||x^", "2026-11-08T00:00:00Z"},
		{"0.0.0.0 x\n# Last modified: 2026-11-12", ""}, // rules come first: no header
		{"! Version: 3.14\n||x^", ""},           // not a date
		{"# Last modified: whenever\n||x^", ""}, // unreadable
	} {
		got := parseHeaderDate(strings.NewReader(tc.head))
		if s := map[bool]string{true: "", false: got.Format(time.RFC3339)}[got.IsZero()]; s != tc.want {
			t.Errorf("%q: got %q, want %q", strings.SplitN(tc.head, "\n", 3)[1], s, tc.want)
		}
	}
}

func TestListChangedSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("||a.example^\n")
	noteCopy(path, "", time.Time{})
	if at, from := listChanged(path); !at.IsZero() || from != "" {
		t.Fatalf("first copy: %v %q, want unknown", at, from)
	}
	// The same contents again: still unknown.
	old, _ := fileSHA(path)
	time.Sleep(10 * time.Millisecond)
	write("||a.example^\n")
	noteCopy(path, old, time.Time{})
	if at, _ := listChanged(path); !at.IsZero() {
		t.Fatalf("unchanged copy marked changed at %v", at)
	}
	// New contents: changed now.
	old, _ = fileSHA(path)
	time.Sleep(10 * time.Millisecond)
	write("||a.example^\n||b.example^\n")
	noteCopy(path, old, time.Time{})
	if at, from := listChanged(path); from != "seen" || time.Since(at) > time.Minute {
		t.Fatalf("changed copy: %v %q", at, from)
	}
	// A newer date in the header wins; an older server date doesn't.
	write("! Last modified: " + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n||c.example^\n")
	noteCopy(path, "", time.Now().Add(-48*time.Hour))
	if _, from := listChanged(path); from != "list" {
		t.Fatalf("from = %q, want list", from)
	}
}
