package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Changes is what changed between two revisions, for "What's new".
type Changes struct {
	// Items are pull request titles (or commit subjects), newest first.
	Items []string `json:"items"`
	// Total counts commits, which can be more than Items.
	Total int    `json:"total"`
	URL   string `json:"url,omitempty"` // the full comparison, on GitHub
}

var githubRepo = regexp.MustCompile(`^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$`)

var mergeTitle = regexp.MustCompile(`^Merge pull request #(\d+) from `)

// GitHubChanges lists the pull requests merged between from and to, for
// images whose source is a GitHub repository (nil otherwise). It asks
// GitHub's public API, which allows 60 requests an hour without a key;
// callers cache the answer.
func GitHubChanges(ctx context.Context, c *http.Client, apiBase, source, from, to string) (*Changes, error) {
	m := githubRepo.FindStringSubmatch(source)
	if m == nil || from == "" || to == "" || from == to {
		return nil, nil
	}
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/%s/compare/%s...%s", apiBase, m[1], m[2], from, to), nil)
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
	var cmp struct {
		HTMLURL      string `json:"html_url"`
		Status       string `json:"status"`
		TotalCommits int    `json:"total_commits"`
		Commits      []struct {
			Commit struct {
				Message string `json:"message"`
			} `json:"commit"`
		} `json:"commits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&cmp); err != nil {
		return nil, err
	}
	out := &Changes{Items: []string{}, Total: cmp.TotalCommits, URL: cmp.HTMLURL}
	var merges, plain []string
	for i := len(cmp.Commits) - 1; i >= 0; i-- {
		msg := strings.TrimSpace(cmp.Commits[i].Commit.Message)
		subject, rest, _ := strings.Cut(msg, "\n")
		if pr := mergeTitle.FindStringSubmatch(subject); pr != nil {
			title := strings.TrimSpace(strings.SplitN(strings.TrimSpace(rest), "\n", 2)[0])
			if title == "" {
				title = subject
			}
			merges = append(merges, title+" (#"+pr[1]+")")
			continue
		}
		plain = append(plain, subject)
	}
	// A repository that merges pull requests: their titles say it best.
	// Otherwise the commit subjects.
	out.Items = merges
	if len(merges) == 0 {
		out.Items = plain
	}
	if len(out.Items) > 30 {
		out.Items = out.Items[:30]
	}
	return out, nil
}
