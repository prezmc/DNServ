package filter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/prezmc/dnserve/internal/config"
)

// ListHit is a list that has a rule for a domain.
type ListHit struct {
	List      string `json:"list"`
	Rule      string `json:"rule"`
	Allowlist bool   `json:"allowlist,omitempty"`
}

// Matches reports whether the rule covers name.
func (r Rule) Matches(name string) bool {
	switch r.Kind {
	case Exact:
		return name == r.Domain
	case Suffix:
		return name == r.Domain || strings.HasSuffix(name, "."+r.Domain)
	case SubOnly:
		return strings.HasSuffix(name, "."+r.Domain)
	}
	return false
}

// AlsoOn finds every enabled list (and the custom rules) with a rule
// covering name, by reading the saved copies of the lists. It reads files,
// so it is for showing a domain's details on request; the query path
// uses the compiled index, which keeps only the winning rule per domain.
func (e *Engine) AlsoOn(ctx context.Context, name string) []ListHit {
	name = Normalize(name)
	cfg := *e.cfg.Load()
	var out []ListHit
	for _, line := range cfg.Rules {
		rules, ok, _ := ParseLine(line)
		for _, r := range rules {
			if ok && r.Matches(name) {
				out = append(out, ListHit{List: "Custom rules", Rule: r.Text(), Allowlist: r.Allow})
			}
		}
	}
	if cfg.BlockBypass {
		for _, d := range BypassDomains {
			if r := (Rule{Domain: d, Kind: Suffix}); r.Matches(name) {
				out = append(out, ListHit{List: "Bypass protection", Rule: r.Text()})
			}
		}
	}
	// Any rule for name or a parent contains its last two labels, so most
	// lines are skipped with a byte search before being parsed.
	tail := name
	if parts := strings.Split(name, "."); len(parts) > 2 {
		tail = strings.Join(parts[len(parts)-2:], ".")
	}
	needle := []byte(tail)
	type job struct {
		l     config.ListConfig
		allow bool
	}
	var jobs []job
	for _, l := range cfg.Allowlists {
		if l.Enabled {
			jobs = append(jobs, job{l, true})
		}
	}
	for _, l := range cfg.Lists {
		if l.Enabled {
			jobs = append(jobs, job{l, false})
		}
	}
	hits := make([][]ListHit, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			label := j.l.Name
			if label == "" {
				label = j.l.URL
			}
			f, err := os.Open(e.localCopy(j.l.URL))
			if err != nil {
				return
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			seen := map[string]bool{}
			for n := 0; sc.Scan(); n++ {
				if n%65536 == 0 && ctx.Err() != nil {
					return
				}
				if line := sc.Bytes(); !bytes.Contains(line, needle) &&
					(!hasUpper(line) || !bytes.Contains(bytes.ToLower(line), needle)) {
					continue
				}
				rules, ok, _ := ParseLine(sc.Text())
				for _, r := range rules {
					r.Allow = r.Allow || j.allow
					if ok && r.Matches(name) && !seen[r.Text()] {
						seen[r.Text()] = true
						hits[i] = append(hits[i], ListHit{List: label, Rule: r.Text(), Allowlist: r.Allow})
					}
				}
			}
		}()
	}
	wg.Wait()
	for _, h := range hits {
		out = append(out, h...)
	}
	return out
}

// localCopy is where a list is read from: its saved download, or the
// file itself for local lists.
func (e *Engine) localCopy(src string) string {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return strings.TrimPrefix(src, "file://")
	}
	sum := sha256.Sum256([]byte(src))
	return filepath.Join(e.dir, hex.EncodeToString(sum[:8])+".txt")
}

func hasUpper(b []byte) bool {
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
