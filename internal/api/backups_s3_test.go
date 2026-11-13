package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/backup"
)

// bucket is a tiny path-style S3 stand-in for bucket "b".
func bucket(t *testing.T) (*httptest.Server, map[string][]byte) {
	var mu sync.Mutex
	objs := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=AK/") {
			w.WriteHeader(403)
			io.WriteString(w, "<Error><Code>InvalidAccessKeyId</Code></Error>")
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/b/")
		switch {
		case r.Method == "PUT":
			objs[key], _ = io.ReadAll(r.Body)
		case r.Method == "DELETE":
			delete(objs, key)
		case r.URL.Query().Get("list-type") == "2":
			io.WriteString(w, "<ListBucketResult>")
			for k, v := range objs {
				if p := r.URL.Query().Get("prefix"); strings.HasPrefix(k, p) {
					fmt.Fprintf(w, "<Contents><Key>%s</Key><Size>%d</Size></Contents>", k, len(v))
				}
			}
			io.WriteString(w, "</ListBucketResult>")
		default:
			b, ok := objs[key]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, objs
}

func TestBackupsS3(t *testing.T) {
	e := newEnv(t)
	e.api.Backups = &backup.Manager{Store: e.api.Store, Dir: filepath.Join(t.TempDir(), "backups"), Node: func() string { return "a" }, Log: slog.New(slog.DiscardHandler)}
	admin, _ := e.setupAdmin()
	srv, objs := bucket(t)
	target := map[string]any{"endpoint": srv.URL, "bucket": "b", "prefix": "dns", "access_key": "AK", "secret_key": "SK", "path_style": true}

	// A bad key is caught before anything is saved.
	bad := map[string]any{"endpoint": srv.URL, "bucket": "b", "access_key": "WRONG", "secret_key": "SK", "path_style": true}
	admin.want(400, "PUT", "/api/v1/backups/s3", bad, nil)
	if e.api.Store.State().BackupS3 != nil {
		t.Fatal("saved a bucket that failed the check")
	}
	admin.want(204, "PUT", "/api/v1/backups/s3", target, nil)
	if len(objs) != 0 {
		t.Fatalf("check left files behind: %v", objs)
	}
	// Saving again without the secret keeps it.
	target["secret_key"] = ""
	admin.want(204, "PUT", "/api/v1/backups/s3", target, nil)
	if e.api.Store.State().BackupS3.SecretKey != "SK" {
		t.Fatal("lost the secret key")
	}

	// Uploads need a passphrase; then one lands in the folder.
	admin.want(502, "POST", "/api/v1/backups/s3/upload", map[string]any{}, nil)
	admin.want(204, "POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": "lantern copper meadow", "password": pw}, nil)
	admin.want(200, "POST", "/api/v1/backups/s3/upload", map[string]any{}, nil)
	var st struct {
		S3    map[string]any
		Files []backup.File
	}
	admin.want(200, "GET", "/api/v1/backups", nil, &st)
	if _, leaked := st.S3["secret_key"]; leaked || st.S3["secret_set"] != true {
		t.Fatalf("s3 status: %v", st.S3)
	}
	var name string
	for _, f := range st.Files {
		if f.Where == "s3" {
			name = f.Name
			if f.Node != "a" {
				t.Fatalf("node from name: %+v", f)
			}
		}
	}
	if name == "" || objs["dns/"+name] == nil {
		t.Fatalf("no S3 backup listed: %+v / %v", st.Files, objs)
	}
	admin.want(200, "GET", "/api/v1/backups/files/s3/"+name, nil, nil)

	admin.want(204, "PUT", "/api/v1/backups/s3", map[string]any{"bucket": ""}, nil)
	if e.api.Store.State().BackupS3 != nil {
		t.Fatal("didn't turn off")
	}
}

func TestBackupsSMB(t *testing.T) {
	e := newEnv(t)
	e.api.Backups = &backup.Manager{Store: e.api.Store, Dir: filepath.Join(t.TempDir(), "backups"), Node: func() string { return "a" }, Log: slog.New(slog.DiscardHandler)}
	admin, _ := e.setupAdmin()
	e.api.smbDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "nas.lan:445" {
			t.Errorf("dialled %s", addr)
		}
		return nil, errors.New("connection refused")
	}
	admin.want(400, "PUT", "/api/v1/backups/smb", map[string]any{"server": `\\nas.lan\backups`, "user": "u"}, nil) // no password
	var res struct{ Error string }
	if code := admin.do("PUT", "/api/v1/backups/smb", map[string]any{"server": `\\nas.lan\backups\dnserv`, "user": "u", "password": "p"}, &res); code != 400 || !strings.Contains(res.Error, "couldn't reach nas.lan") {
		t.Fatalf("unreachable share: %d %+v", code, res)
	}
	if e.api.Store.State().BackupSMB != nil {
		t.Fatal("saved a share that failed the check")
	}
	admin.want(404, "POST", "/api/v1/backups/ftp/upload", map[string]any{}, nil)

	// Against a real share when one is given (see internal/backup/smb_test.go).
	spec := strings.Fields(os.Getenv("DNSERV_SMB_TEST"))
	if len(spec) != 3 {
		return
	}
	e.api.smbDial = nil
	target := map[string]any{"server": spec[0], "folder": "api-test/" + strconv.FormatInt(time.Now().UnixNano(), 36), "user": spec[1], "password": strings.ReplaceAll(spec[2], "+", " ")}
	admin.want(204, "PUT", "/api/v1/backups/smb", target, nil)
	admin.want(204, "POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": "lantern copper meadow", "password": pw}, nil)
	admin.want(200, "POST", "/api/v1/backups/smb/upload", map[string]any{}, nil)
	var st struct {
		SMB   map[string]any
		Files []backup.File
	}
	admin.want(200, "GET", "/api/v1/backups", nil, &st)
	if _, leaked := st.SMB["password"]; leaked || st.SMB["password_set"] != true {
		t.Fatalf("smb status: %v", st.SMB)
	}
	n := 0
	for _, f := range st.Files {
		if f.Where == "smb" {
			n++
			admin.want(200, "GET", "/api/v1/backups/files/smb/"+f.Name, nil, nil)
		}
	}
	if n != 1 {
		t.Fatalf("files: %+v", st.Files)
	}
}
