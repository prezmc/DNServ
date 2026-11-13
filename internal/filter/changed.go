package filter

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// How recently a list's owner changed it, as opposed to when DNServ last
// downloaded it. Three sources, and the newest one wins:
//
//   - "list": a date in the list's own header (! Last modified: …,
//     # Date: …, ! Version: 2026.1112.1021.44 and the like);
//   - "server": the Last-Modified header the list's server sent;
//   - "seen": when a download first brought different contents.

// changeInfo is kept next to each downloaded list.
type changeInfo struct {
	SHA256 string    `json:"sha256"`
	Seen   time.Time `json:"seen,omitzero"`   // when these contents first arrived, if they replaced others
	Server time.Time `json:"server,omitzero"` // the server's Last-Modified
}

func changePath(listPath string) string { return listPath + ".changed.json" }

func readChange(listPath string) changeInfo {
	var ci changeInfo
	if b, err := os.ReadFile(changePath(listPath)); err == nil {
		_ = json.Unmarshal(b, &ci)
	}
	return ci
}

// noteCopy records a newly saved copy of a list: oldSHA is the copy it
// replaced ("" if none) and server the Last-Modified time, if any.
func noteCopy(listPath, oldSHA string, server time.Time) {
	sum, err := fileSHA(listPath)
	if err != nil {
		return
	}
	ci := readChange(listPath)
	if ci.SHA256 != sum {
		prev := ci.SHA256
		if prev == "" {
			prev = oldSHA
		}
		if prev != "" && prev != sum {
			ci.Seen = time.Now().UTC()
		}
		ci.SHA256 = sum
	}
	if !server.IsZero() {
		ci.Server = server.UTC()
	}
	if b, err := json.Marshal(ci); err == nil {
		_ = os.WriteFile(changePath(listPath), b, 0o600)
	}
}

// lastModified reads a response's Last-Modified header.
func lastModified(h http.Header) time.Time {
	t, err := http.ParseTime(h.Get("Last-Modified"))
	if err != nil {
		return time.Time{}
	}
	return t
}

// listChanged says when a list's owner last changed it, and how that is
// known.
func listChanged(listPath string) (time.Time, string) {
	best, from := time.Time{}, ""
	consider := func(t time.Time, src string) {
		if !t.IsZero() && t.After(best) && t.Before(time.Now().Add(48*time.Hour)) && t.Year() >= 2000 {
			best, from = t, src
		}
	}
	consider(headerDate(listPath), "list")
	ci := readChange(listPath)
	consider(ci.Server, "server")
	consider(ci.Seen, "seen")
	return best, from
}

var (
	headerDateRe = regexp.MustCompile(`(?i)^[!#]+\s*(last[ _-]?modified|last[ _-]?updated|updated|date|time ?updated|version)\s*:\s*(.+?)\s*$`)
	versionRe    = regexp.MustCompile(`^(\d{4})\.?(\d{2})(\d{2})\.?(\d{2})?(\d{2})?`)
	dayMonthRe   = regexp.MustCompile(`^(\d{1,2})\s*([A-Za-z]{3,9})\s*(\d{4})`)
	dateLayouts  = []string{
		time.RFC3339Nano, time.RFC3339, time.RFC1123Z, time.RFC1123, time.RFC850, time.ANSIC,
		"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
		"2006-01-02T15:04:05", "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05", "2006-01-02 15:04 MST", "2006-01-02 15:04", "2006-01-02",
		"02 Jan 2006 15:04", "2 Jan 2006 15:04", "02 Jan 2006 15:04 MST", "2 Jan 2006 15:04 MST", "02 Jan 2006 15:04:05 MST", "2 Jan 2006 15:04:05 MST", "2 Jan 2006",
		"02 January 2006 15:04:05", "2 January 2006 15:04:05", "2 January 2006 15:04", "2 January 2006", "January 2, 2006", "Jan 2, 2006",
		"02.01.2006 15:04", "02.01.2006", "2006/01/02 15:04:05", "2006/01/02",
	}
)

// headerDate finds a date in the comment lines at the top of a list.
func headerDate(listPath string) time.Time {
	f, err := os.Open(listPath)
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	return parseHeaderDate(io.LimitReader(f, 64<<10))
}

func parseHeaderDate(r io.Reader) time.Time {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for n := 0; sc.Scan() && n < 80; n++ {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" {
			continue
		}
		if line[0] != '!' && line[0] != '#' && line[0] != '[' {
			break // the rules have started
		}
		m := headerDateRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if t := parseListDate(m[2], strings.EqualFold(m[1], "version")); !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func parseListDate(v string, version bool) time.Time {
	if version {
		// Versions that are dates: 08November2026v3.
		if m := dayMonthRe.FindStringSubmatch(v); m != nil {
			if t, err := time.Parse("2 January 2006", m[1]+" "+m[2]+" "+m[3]); err == nil {
				return t
			}
			if t, err := time.Parse("2 Jan 2006", m[1]+" "+m[2]+" "+m[3]); err == nil {
				return t
			}
			return time.Time{}
		}
		// HaGeZi-style versions: 2026.1112.1021.44 (year.monthday.time).
		m := versionRe.FindStringSubmatch(v)
		if m == nil {
			return time.Time{}
		}
		n := func(s string) int { i, _ := strconv.Atoi(s); return i }
		t := time.Date(n(m[1]), time.Month(n(m[2])), n(m[3]), n(m[4]), n(m[5]), 0, 0, time.UTC)
		if t.Month() != time.Month(n(m[2])) || n(m[2]) < 1 {
			return time.Time{}
		}
		return t
	}
	// Drop a trailing "(UTC)" or similar note.
	if i := strings.IndexByte(v, '('); i > 0 {
		v = strings.TrimSpace(v[:i])
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
