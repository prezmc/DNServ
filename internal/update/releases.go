package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ReleaseNote is one numbered release, for "What's new".
type ReleaseNote struct {
	Version   string    `json:"version"` // 1.2.3
	Name      string    `json:"name,omitempty"`
	Published time.Time `json:"published"`
	URL       string    `json:"url,omitempty"`
	// Items are the release notes' bullet points, cleaned up ("Add
	// built-in updates (#71)"); Text is anything else they say.
	Items []string `json:"items"`
	Text  string   `json:"text,omitempty"`
}

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// semver parses 1.2.3 or v1.2.3.
func semver(s string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func semverLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

var releaseVersion = regexp.MustCompile(`^v(\d+\.\d+\.\d+)-[0-9a-f]{40}$`)

// VersionOf is the release number in a build's version string
// ("v1.2.3-<commit>" is "1.2.3"), or "" for a build of main.
func VersionOf(version string) string {
	if m := releaseVersion.FindStringSubmatch(version); m != nil {
		return m[1]
	}
	return ""
}

// GitHub's generated notes: "* Title by @user in https://.../pull/71".
var (
	noteBy   = regexp.MustCompile(`\s+by @[\w-]+(?:\[bot\])?\s+in\s+https://github\.com/\S+/pull/(\d+)\s*$`)
	notePR   = regexp.MustCompile(`\s*\(?https://github\.com/\S+/pull/(\d+)\)?\s*$`)
	noteLink = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)
)

// parseNotes turns a release's Markdown into bullet points and text.
func parseNotes(body string) ([]string, string) {
	items := []string{}
	var text []string
	for _, ln := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "", strings.HasPrefix(ln, "#"), strings.HasPrefix(ln, "**Full Changelog**"), strings.HasPrefix(ln, "<!--"):
			continue
		case strings.HasPrefix(ln, "* "), strings.HasPrefix(ln, "- "):
			it := strings.TrimSpace(ln[2:])
			if m := noteBy.FindStringSubmatch(it); m != nil {
				it = noteBy.ReplaceAllString(it, "") + " (#" + m[1] + ")"
			} else if m := notePR.FindStringSubmatch(it); m != nil {
				it = notePR.ReplaceAllString(it, "") + " (#" + m[1] + ")"
			}
			items = append(items, noteLink.ReplaceAllString(it, "$1"))
		default:
			text = append(text, noteLink.ReplaceAllString(ln, "$1"))
		}
	}
	return items, strings.Join(text, "\n")
}

// GitHubReleases lists the published releases of a GitHub source, newest
// first (nil for a source that isn't on GitHub).
func GitHubReleases(ctx context.Context, c *http.Client, apiBase, source string) ([]ReleaseNote, error) {
	m := githubRepo.FindStringSubmatch(source)
	if m == nil {
		return nil, nil
	}
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/%s/releases?per_page=30", apiBase, m[1], m[2]), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered HTTP %d", resp.StatusCode)
	}
	var list []struct {
		TagName     string    `json:"tag_name"`
		Name        string    `json:"name"`
		Body        string    `json:"body"`
		HTMLURL     string    `json:"html_url"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, err
	}
	var out []ReleaseNote
	for _, r := range list {
		v, ok := semver(r.TagName)
		if r.Draft || r.Prerelease || !ok {
			continue
		}
		n := ReleaseNote{Version: fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]), Name: r.Name, Published: r.PublishedAt, URL: r.HTMLURL}
		n.Items, n.Text = parseNotes(r.Body)
		out = append(out, n)
	}
	return out, nil
}

// notesBetween are the releases after from (a version, "" for unknown)
// up to and including to, newest first. With no from, just to's.
func notesBetween(all []ReleaseNote, from, to string) []ReleaseNote {
	tv, ok := semver(to)
	if !ok {
		return nil
	}
	fv, haveFrom := semver(from)
	var out []ReleaseNote
	for _, n := range all {
		v, _ := semver(n.Version)
		if semverLess(tv, v) {
			continue
		}
		if haveFrom && !semverLess(fv, v) {
			continue
		}
		if !haveFrom && v != tv {
			continue
		}
		out = append(out, n)
		if len(out) == 10 {
			break
		}
	}
	return out
}
