// Package update finds new DNServ images and installs them.
//
// Finding needs nothing but network access: a node asks the image
// registry (ghcr.io by default) what the newest image for its tag is and
// compares that image's git revision with its own.
//
// Installing needs the optional updater, a second small container (the
// same image, run with -updater) that holds the Docker socket. It has no
// network port: DNServ reaches it through a Unix socket on a volume the
// two containers share, and all it can be asked is "update the container
// you were set up for to the newest image of its own tag". See sidecar.go.
//
// In a cluster, the node an admin asks updates the others one at a time,
// waiting for each to answer DNS again before the next, and itself last,
// so the network never loses DNS. See rollout.go.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// DefaultImage is where official images are published.
const DefaultImage = "ghcr.io/prezmc/dnserv:latest"

// OCI label (and annotation) names the publish workflow sets.
const (
	labelRevision = "org.opencontainers.image.revision"
	labelVersion  = "org.opencontainers.image.version"
	labelCreated  = "org.opencontainers.image.created"
	labelSource   = "org.opencontainers.image.source"
)

// Release is one image on the registry.
type Release struct {
	Image    string    `json:"image"`
	Digest   string    `json:"digest,omitempty"`
	Revision string    `json:"revision"`
	Version  string    `json:"version,omitempty"`
	Created  time.Time `json:"created,omitzero"`
	Source   string    `json:"source,omitempty"`
}

// Ref is a parsed image reference.
type Ref struct {
	Registry string // host, e.g. ghcr.io or registry-1.docker.io
	Repo     string // e.g. prezmc/dnserv or library/alpine
	Tag      string
	Digest   string // set for name@sha256:..., which never updates
}

// ParseRef splits an image reference the way Docker does: no registry
// means Docker Hub, no tag means latest.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, errors.New("no image name")
	}
	var r Ref
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest, s = s[i+1:], s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		r.Tag, s = s[i+1:], s[:i]
	}
	if i := strings.Index(s, "/"); i > 0 && (strings.ContainsAny(s[:i], ".:") || s[:i] == "localhost") {
		r.Registry, r.Repo = s[:i], s[i+1:]
	} else {
		r.Registry, r.Repo = "docker.io", s
	}
	if r.Registry == "docker.io" || r.Registry == "index.docker.io" {
		r.Registry = "registry-1.docker.io"
		if !strings.Contains(r.Repo, "/") {
			r.Repo = "library/" + r.Repo
		}
	}
	if r.Tag == "" {
		r.Tag = "latest"
	}
	if r.Repo == "" {
		return Ref{}, fmt.Errorf("bad image name %q", s)
	}
	return r, nil
}

// Registry reads image manifests from an OCI registry, anonymously.
type Registry struct {
	Client *http.Client
	// Scheme is https, or http for tests.
	Scheme string
	// Arch is the platform to look at (default: this one).
	Arch string
	// Host, when set, is asked instead of the registry in the image name
	// (a mirror, or a test lab's registry).
	Host string
}

var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

type manifest struct {
	MediaType   string            `json:"mediaType"`
	Annotations map[string]string `json:"annotations"`
	Manifests   []struct {
		Digest   string `json:"digest"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
}

// Latest returns the image the reference's tag points at now.
func (g *Registry) Latest(ctx context.Context, image string) (*Release, error) {
	ref, err := ParseRef(image)
	if err != nil {
		return nil, err
	}
	if ref.Digest != "" {
		return nil, errors.New("this image is pinned to one digest, so there is never a newer one")
	}
	if g.Host != "" {
		ref.Registry = g.Host
	}
	s := &regSession{g: g, ref: ref}
	var top manifest
	digest, err := s.getJSON(ctx, "manifests/"+ref.Tag, manifestTypes, &top)
	if err != nil {
		return nil, err
	}
	rel := &Release{Image: image, Digest: digest}
	labels := top.Annotations
	if labels[labelRevision] == "" {
		// No annotations on the index: read the labels from this
		// platform's image config.
		m := top
		if len(top.Manifests) > 0 {
			arch := g.Arch
			if arch == "" {
				arch = runtime.GOARCH
			}
			pick := ""
			for _, x := range top.Manifests {
				if x.Platform.OS == "linux" && x.Platform.Architecture == arch {
					pick = x.Digest
					break
				}
			}
			if pick == "" {
				return nil, fmt.Errorf("the image has no linux/%s version", arch)
			}
			m = manifest{}
			if _, err := s.getJSON(ctx, "manifests/"+pick, manifestTypes, &m); err != nil {
				return nil, err
			}
		}
		if m.Config.Digest == "" {
			return nil, errors.New("the registry returned an image with no config")
		}
		var cfg struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if _, err := s.getJSON(ctx, "blobs/"+m.Config.Digest, "", &cfg); err != nil {
			return nil, err
		}
		labels = cfg.Config.Labels
	}
	rel.Revision = labels[labelRevision]
	rel.Version = labels[labelVersion]
	rel.Source = labels[labelSource]
	if t, err := time.Parse(time.RFC3339, labels[labelCreated]); err == nil {
		rel.Created = t
	}
	if rel.Revision == "" {
		return nil, errors.New("the newest image doesn't say which version it is")
	}
	return rel, nil
}

// regSession is one conversation with a registry, holding its token.
type regSession struct {
	g     *Registry
	ref   Ref
	token string
}

func (s *regSession) client() *http.Client {
	if s.g.Client != nil {
		return s.g.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *regSession) getJSON(ctx context.Context, path, accept string, v any) (string, error) {
	scheme := s.g.Scheme
	if scheme == "" {
		scheme = "https"
		// Like Docker, a registry on this machine may be plain HTTP.
		if h := strings.Split(s.ref.Registry, ":")[0]; h == "localhost" || h == "127.0.0.1" {
			scheme = "http"
		}
	}
	u := scheme + "://" + s.ref.Registry + "/v2/" + s.ref.Repo + "/" + path
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.client().Do(req)
		if err != nil {
			return "", fmt.Errorf("can't reach %s: %w", s.ref.Registry, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if err := s.login(ctx, resp.Header.Get("WWW-Authenticate")); err != nil {
				return "", err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s answered HTTP %d for %s", s.ref.Registry, resp.StatusCode, s.ref.Repo)
		}
		if err := json.Unmarshal(body, v); err != nil {
			return "", fmt.Errorf("%s sent something unreadable: %w", s.ref.Registry, err)
		}
		return resp.Header.Get("Docker-Content-Digest"), nil
	}
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// login gets an anonymous pull token, as the registry's challenge says.
func (s *regSession) login(ctx context.Context, challenge string) error {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return fmt.Errorf("%s wants a sign-in DNServ can't do", s.ref.Registry)
	}
	p := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		p[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Host == "" {
		return fmt.Errorf("%s sent a bad sign-in challenge", s.ref.Registry)
	}
	q := realm.Query()
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	q.Set("scope", "repository:"+s.ref.Repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("can't reach %s: %w", realm.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s refused an anonymous pull token (HTTP %d); is the image private?", realm.Host, resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return err
	}
	s.token = tok.Token
	if s.token == "" {
		s.token = tok.AccessToken
	}
	return nil
}

var shaSuffix = regexp.MustCompile(`([0-9a-f]{40})$`)

// RevisionOf finds the git commit in a version string as the publish
// workflow builds it ("main-<commit>", "v1.2.0-<commit>"). Empty for a
// development build.
func RevisionOf(version string) string {
	if m := shaSuffix.FindStringSubmatch(version); m != nil {
		return m[1]
	}
	return ""
}
