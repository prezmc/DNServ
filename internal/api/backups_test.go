package api

import (
	"bytes"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/prezmc/dnserv/internal/backup"
	"github.com/prezmc/dnserv/internal/store"
)

func (c *client) upload(path string, file []byte, fields map[string]string) (int, string) {
	c.e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "x.dnsbak")
	fw.Write(file)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", c.e.srv.URL+path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHistoryAndBackups(t *testing.T) {
	e := newEnv(t)
	e.api.Backups = &backup.Manager{Store: e.api.Store, Dir: filepath.Join(t.TempDir(), "backups"), Node: func() string { return "a" }, Log: slog.New(slog.DiscardHandler)}
	admin, _ := e.setupAdmin()

	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"upstream_mode": "recursive"}, nil)
	var list struct {
		Versions []struct {
			ID      uint64
			Summary string
		}
		Current uint64
	}
	admin.want(200, "GET", "/api/v1/config/versions", nil, &list)
	if len(list.Versions) != 2 {
		t.Fatalf("versions: %+v", list)
	}
	base := list.Versions[1].ID
	var v struct {
		Changes []Change
	}
	admin.want(200, "GET", "/api/v1/config/versions/"+itoa(base), nil, &v)
	found := false
	for _, c := range v.Changes {
		if c.Path == "settings.upstream_mode" && c.Now == "recursive" {
			found = true
		}
	}
	if !found {
		t.Fatalf("diff: %+v", v.Changes)
	}
	admin.want(204, "POST", "/api/v1/config/versions/"+itoa(base)+"/restore", map[string]any{}, nil)
	if m := e.api.Store.State().Settings.UpstreamMode; m != nil && *m == "recursive" {
		t.Fatal("restore didn't take")
	}

	// Backups need a passphrase first.
	admin.want(400, "POST", "/api/v1/backups/download", map[string]any{}, nil)
	admin.want(400, "PUT", "/api/v1/backups/schedule", map[string]any{"every": "daily", "at": "03:00"}, nil)
	admin.want(401, "POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": "lantern copper meadow", "password": "wrong"}, nil)
	admin.want(400, "POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": "aaaaaaaaaaaaaaa", "password": pw}, nil)
	const pp = "lantern copper meadow"
	admin.want(204, "POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": pp, "password": pw}, nil)
	admin.want(204, "PUT", "/api/v1/backups/schedule", map[string]any{"every": "daily", "at": "03:00", "keep": 7}, nil)

	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/backups/download", bytes.NewReader([]byte("{}")))
	req.Header.Set("X-CSRF-Token", admin.csrf)
	resp, err := admin.http.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("download: %v %v", err, resp.Status)
	}
	file, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if _, _, err := backup.Open(file, pp); err != nil {
		t.Fatal(err)
	}

	// Change something, then restore the backup over it.
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"upstream_mode": "recursive"}, nil)
	if code, body := admin.upload("/api/v1/backups/restore", file, map[string]string{"passphrase": "nope nope nope", "password": pw}); code != 400 {
		t.Fatalf("wrong passphrase: %d %s", code, body)
	}
	if code, body := admin.upload("/api/v1/backups/restore", file, map[string]string{"passphrase": pp, "password": pw}); code != 200 {
		t.Fatalf("restore: %d %s", code, body)
	}
	if m := e.api.Store.State().Settings.UpstreamMode; m != nil && *m == "recursive" {
		t.Fatal("backup restore didn't take")
	}
	if !e.api.Store.State().Backup.Configured() {
		t.Fatal("restore dropped the backup settings")
	}

	// A fresh node can be set up from the backup.
	f := newEnv(t)
	c := f.client()
	if code, _ := c.upload("/api/v1/setup/restore", file, map[string]string{"code": "WRONG", "passphrase": pp}); code != 403 {
		t.Fatalf("wrong setup code: %d", code)
	}
	if code, body := c.upload("/api/v1/setup/restore", file, map[string]string{"code": f.api.SetupCode(), "passphrase": pp}); code != 200 {
		t.Fatalf("setup restore: %d %s", code, body)
	}
	if len(f.api.Store.State().Users) != 1 || f.api.SetupCode() != "" {
		t.Fatal("setup restore didn't bring the users")
	}
	if b := f.api.Store.State().Backup; !b.Configured() || b.Every != "daily" {
		t.Fatalf("setup restore didn't bring the backup schedule: %+v", b)
	}
	if code, _ := c.upload("/api/v1/setup/restore", file, map[string]string{"code": "x", "passphrase": pp}); code != 409 {
		t.Fatalf("second setup restore: %d", code)
	}
}

func TestDiffConfigWholeItems(t *testing.T) {
	now := store.ConfigSnapshot{Groups: map[string]*store.Group{"g1": {ID: "g1", Name: "Kids", Rules: []string{"||a.com^"}}}}
	ch := DiffConfig(now, store.ConfigSnapshot{})
	if len(ch) != 1 || ch[0].Path != "groups.Kids" || ch[0].Now != "present" || ch[0].Then != "" {
		t.Fatalf("added group: %+v", ch)
	}
	then := store.ConfigSnapshot{Groups: map[string]*store.Group{"g1": {ID: "g1", Name: "Kids"}}}
	ch = DiffConfig(now, then)
	if len(ch) != 1 || ch[0].Path != "groups.Kids.rules" {
		t.Fatalf("changed group: %+v", ch)
	}
}
