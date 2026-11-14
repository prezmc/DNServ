package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestVersionOf(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for in, want := range map[string]string{
		"v1.3.0-" + sha: "1.3.0",
		"main-" + sha:   "",
		"dev":           "",
	} {
		if got := VersionOf(in); got != want {
			t.Errorf("VersionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNotes(t *testing.T) {
	body := "## What's Changed\n* Add built-in updates by @someone in https://github.com/prezmc/DNServ/pull/71\n* Fix cache by @x in https://github.com/prezmc/DNServ/pull/72\n\n**Full Changelog**: https://github.com/prezmc/DNServ/compare/v1.0.0...v1.1.0"
	items, _ := parseNotes(body)
	want := []string{"Add built-in updates (#71)", "Fix cache (#72)"}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("items = %q, want %q", items, want)
	}
}

func TestNotesBetween(t *testing.T) {
	all := []ReleaseNote{{Version: "1.3.0"}, {Version: "1.2.1"}, {Version: "1.2.0"}, {Version: "1.1.0"}}
	vers := func(l []ReleaseNote) (out []string) {
		for _, n := range l {
			out = append(out, n.Version)
		}
		return
	}
	if got := vers(notesBetween(all, "1.2.0", "1.3.0")); !reflect.DeepEqual(got, []string{"1.3.0", "1.2.1"}) {
		t.Errorf("1.2.0 -> 1.3.0: %v", got)
	}
	if got := vers(notesBetween(all, "", "1.2.1")); !reflect.DeepEqual(got, []string{"1.2.1"}) {
		t.Errorf("unknown -> 1.2.1: %v", got)
	}
	if got := notesBetween(all, "1.3.0", "1.3.0"); len(got) != 0 {
		t.Errorf("up to date: %v", got)
	}
}

func TestGitHubReleases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/prezmc/DNServ/releases" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`[{"tag_name":"v1.1.0","name":"DNServ 1.1.0","body":"* A by @u in https://github.com/prezmc/DNServ/pull/3"},
			{"tag_name":"v1.1.0-rc1","prerelease":true},{"tag_name":"nightly"},{"tag_name":"v1.0.0","draft":true}]`))
	}))
	defer srv.Close()
	got, err := GitHubReleases(context.Background(), srv.Client(), srv.URL, "https://github.com/prezmc/DNServ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Version != "1.1.0" || len(got[0].Items) != 1 || got[0].Items[0] != "A (#3)" {
		t.Fatalf("got %+v", got)
	}
}

func TestChannelTags(t *testing.T) {
	for _, c := range [][3]string{
		{"ghcr.io/prezmc/dnserv:latest", "stable", "ghcr.io/prezmc/dnserv:stable"},
		{"ghcr.io/prezmc/dnserv", "stable", "ghcr.io/prezmc/dnserv:stable"},
		{"localhost:5000/dnserv:stable", "latest", "localhost:5000/dnserv:latest"},
	} {
		if got := withTag(c[0], c[1]); got != c[2] {
			t.Errorf("withTag(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for ref, want := range map[string]bool{
		"ghcr.io/prezmc/dnserv:stable": true, "ghcr.io/prezmc/dnserve": true, "localhost:5000/dnserv": true,
		"registry:2": false, "sha256:abc": false, "ghcr.io/x/dnserv-updater": false,
	} {
		if got := isDNServImage(ref); got != want {
			t.Errorf("isDNServImage(%q) = %v", ref, got)
		}
	}
}

func TestNodesShowReleaseForSameCode(t *testing.T) {
	rev := strings.Repeat("d", 40)
	m := &Manager{Version: "main-" + rev, Sidecar: NewClient("/nonexistent/updater.sock")}
	m.latest = &Release{Revision: rev, Version: "1.0.1"}
	n := m.Nodes(context.Background())
	if len(n) != 1 || n[0].Release != "1.0.1" || n[0].Behind {
		t.Fatalf("got %+v", n)
	}
	m.latest = &Release{Revision: strings.Repeat("e", 40), Version: "1.0.2"}
	if n := m.Nodes(context.Background()); n[0].Release != "" || !n[0].Behind {
		t.Fatalf("different code: %+v", n)
	}
}
