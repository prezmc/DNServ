package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/auth"
	"github.com/prezmc/dnserv/internal/backup"
	"github.com/prezmc/dnserv/internal/store"
)

// maxBackup is the largest backup file accepted for a restore.
const maxBackup = 64 << 20

func (a *API) backupRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/config/versions", a.authed(store.PermBackups, a.listVersions))
	m.HandleFunc("GET /api/v1/config/versions/{id}", a.authed(store.PermBackups, a.getVersion))
	m.HandleFunc("POST /api/v1/config/versions/{id}/restore", a.authed(store.PermBackups, a.restoreVersion))
	m.HandleFunc("GET /api/v1/backups", a.authed(store.PermBackups, a.backupStatus))
	m.HandleFunc("PUT /api/v1/backups/schedule", a.authed(store.PermBackups, a.backupSchedule))
	m.HandleFunc("POST /api/v1/backups/passphrase", a.authed(store.PermBackups, a.backupPassphrase))
	m.HandleFunc("POST /api/v1/backups/download", a.authed(store.PermBackups, a.backupNow))
	m.HandleFunc("GET /api/v1/backups/files/{where}/{name}", a.authed(store.PermBackups, a.backupFile))
	m.HandleFunc("PUT /api/v1/backups/s3", a.authed(store.PermBackups, a.backupS3Set))
	m.HandleFunc("POST /api/v1/backups/s3/upload", a.authed(store.PermBackups, a.backupS3Upload))
	m.HandleFunc("POST /api/v1/backups/restore", a.authed(store.PermBackups, a.backupRestore))
	m.HandleFunc("POST /api/v1/setup/restore", a.setupRestore)
}

func (a *API) listVersions(w http.ResponseWriter, r *http.Request, p *Principal) {
	st := a.Store.State()
	type item struct {
		ID      uint64    `json:"id"`
		Time    time.Time `json:"time"`
		Actor   string    `json:"actor"`
		Summary string    `json:"summary"`
	}
	out := []item{}
	for _, v := range slices.Backward(st.ConfigVersions) {
		out = append(out, item{v.ID, v.Time, v.Actor, v.Summary})
	}
	var current uint64
	if n := len(st.ConfigVersions); n > 0 {
		current = st.ConfigVersions[n-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out, "current": current, "max": store.MaxVersions})
}

// getVersion returns one version and what restoring it would change.
func (a *API) getVersion(w http.ResponseWriter, r *http.Request, p *Principal) {
	st := a.Store.State()
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	v := st.VersionByID(id)
	if v == nil {
		writeErr(w, http.StatusNotFound, "that version is no longer kept")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": v.ID, "time": v.Time, "actor": v.Actor, "summary": v.Summary,
		"changes": DiffConfig(st.ConfigSnapshot(), v.Config),
	})
}

func (a *API) restoreVersion(w http.ResponseWriter, r *http.Request, p *Principal) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such version")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpConfigRestore, p.Actor(), store.VersionID{ID: id})); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) backupStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	b := a.Store.State().Backup
	_, zone := a.zone()
	out := map[string]any{
		"configured": b.Configured(), "every": b.Every, "at": b.At, "keep": b.Keep, "offsite": b.Offsite,
		"default_keep": backup.DefaultKeep, "min_passphrase": backup.MinPassphrase,
		"time_zone": zone, "files": []backup.File{},
	}
	if t := a.Store.State().BackupS3; t != nil {
		// Everything but the secret key.
		out["s3"] = map[string]any{"endpoint": t.Endpoint, "region": t.Region, "bucket": t.Bucket, "prefix": t.Prefix,
			"access_key": t.AccessKey, "path_style": t.PathStyle, "secret_set": t.SecretKey != ""}
	}
	if a.Backups != nil {
		out["dir"] = a.Backups.Dir
		f, err := a.Backups.List(r.Context())
		if f != nil {
			out["files"] = f
		}
		if err != nil {
			out["s3_error"] = err.Error()
		}
		if st := a.Backups.S3Status(); !st.At.IsZero() {
			out["s3_last"] = st
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// backupS3Set sets (or, with an empty bucket, turns off) the S3 bucket
// backups are uploaded to. It checks the bucket works before saving. An
// empty secret key keeps the one already saved.
func (a *API) backupS3Set(w http.ResponseWriter, r *http.Request, p *Principal) {
	var t store.S3Target
	if !readJSON(w, r, &t) {
		return
	}
	if strings.TrimSpace(t.Bucket) == "" {
		if _, ok := a.apply(w, store.NewCommand(store.OpBackupS3, p.Actor(), store.S3Target{})); ok {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if strings.TrimSpace(t.SecretKey) == "" {
		if old := a.Store.State().BackupS3; old != nil {
			t.SecretKey = old.SecretKey
		}
	}
	if err := t.Clean(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c := &backup.S3{T: t}
	if a.Backups != nil {
		c.Client = a.Backups.Client
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := c.Test(ctx); err != nil {
		writeErr(w, http.StatusBadRequest, "DNServ couldn't use that bucket, so nothing was saved: "+err.Error())
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpBackupS3, p.Actor(), t)); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

// backupS3Upload makes a backup now and uploads it to the bucket.
func (a *API) backupS3Upload(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Backups == nil {
		writeErr(w, http.StatusNotFound, "backups aren't available on this node")
		return
	}
	if err := a.Backups.UploadNow(); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	a.Log.Info("backup uploaded to S3 by hand", "actor", p.Actor())
	writeJSON(w, http.StatusOK, a.Backups.S3Status())
}

func (a *API) backupSchedule(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Every   string
		At      string
		Keep    int
		Offsite string
	}
	if !readJSON(w, r, &req) {
		return
	}
	b := a.Store.State().Backup
	b.Every, b.At, b.Keep, b.Offsite = req.Every, req.At, req.Keep, req.Offsite
	if _, ok := a.apply(w, store.NewCommand(store.OpBackupConfig, p.Actor(), b)); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

// backupPassphrase sets the passphrase new backups are encrypted with.
// Older backups still open with the passphrase they were made with.
func (a *API) backupPassphrase(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Passphrase, Password string }
	if !readJSON(w, r, &req) || !a.sessionWithPassword(w, r, p, req.Password) {
		return
	}
	if msg := passphraseProblem(req.Passphrase, p.User.Username); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	pub, salt, err := backup.NewKey(req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	b := a.Store.State().Backup
	b.PublicKey, b.Salt = pub, salt
	if _, ok := a.apply(w, store.NewCommand(store.OpBackupConfig, p.Actor(), b)); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

// passphraseProblem rejects passphrases that are easy to guess. A backup
// file can be attacked offline, so this is stricter than for passwords.
func passphraseProblem(pp, username string) string {
	if len([]rune(pp)) < backup.MinPassphrase {
		return fmt.Sprintf("use a passphrase of at least %d characters (a few random words works well)", backup.MinPassphrase)
	}
	if err := auth.CheckPasswordStrength(pp, username); err != nil {
		return err.Error()
	}
	distinct := map[rune]bool{}
	for _, c := range pp {
		distinct[c] = true
	}
	if len(distinct) < 6 {
		return "that passphrase repeats too few characters; pick a few random words"
	}
	return ""
}

func (a *API) backupNow(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Backups == nil {
		writeErr(w, http.StatusNotFound, "backups aren't available on this node")
		return
	}
	name, file, err := a.Backups.Make()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.Log.Info("backup downloaded", "actor", p.Actor(), "file", name)
	sendFile(w, name, file)
}

func (a *API) backupFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Backups == nil {
		writeErr(w, http.StatusNotFound, "backups aren't available on this node")
		return
	}
	name := r.PathValue("name")
	file, err := a.Backups.Read(r.PathValue("where"), name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such backup")
		return
	}
	sendFile(w, name, file)
}

func sendFile(w http.ResponseWriter, name string, b []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

// readBackupForm reads a multipart upload: the file and form fields.
func readBackupForm(w http.ResponseWriter, r *http.Request) (file []byte, form map[string]string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackup+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "upload a backup file (up to 64 MB)")
		return nil, nil, false
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "choose a backup file")
		return nil, nil, false
	}
	defer f.Close()
	file, err = io.ReadAll(io.LimitReader(f, maxBackup+1))
	if err != nil || len(file) > maxBackup {
		writeErr(w, http.StatusBadRequest, "that file is too large to be a backup")
		return nil, nil, false
	}
	form = map[string]string{}
	for k, v := range r.MultipartForm.Value {
		if len(v) > 0 {
			form[k] = v[0]
		}
	}
	return file, form, true
}

// openUpload decrypts an uploaded backup.
func (a *API) openUpload(w http.ResponseWriter, file []byte, passphrase, ip string) (backup.Header, store.BackupData, bool) {
	key := "backup:" + ip
	if ok, wait := a.Throttle.Allowed(key); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return backup.Header{}, store.BackupData{}, false
	}
	h, data, err := backup.Open(file, passphrase)
	if errors.Is(err, backup.ErrBadPassphrase) {
		a.Throttle.Fail(key)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return h, data, false
	}
	return h, data, true
}

func (a *API) restoreBackup(w http.ResponseWriter, actor string, h backup.Header, data store.BackupData) bool {
	_, ok := a.apply(w, store.NewCommand(store.OpBackupRestore, actor, store.BackupRestore{Data: data, Created: h.Created, From: h.Node}))
	if ok {
		a.Log.Warn("restored a backup", "actor", actor, "made", h.Created, "by", h.Node)
	}
	return ok
}

// backupRestore replaces the users and configuration with a backup's.
// The cluster itself (nodes, leadership) and the backup settings stay.
func (a *API) backupRestore(w http.ResponseWriter, r *http.Request, p *Principal) {
	file, form, ok := readBackupForm(w, r)
	if !ok || !a.sessionWithPassword(w, r, p, form["password"]) {
		return
	}
	h, data, ok := a.openUpload(w, file, form["passphrase"], clientIP(r))
	if !ok {
		return
	}
	if a.restoreBackup(w, p.Actor(), h, data) {
		writeJSON(w, http.StatusOK, map[string]any{"created": h.Created, "node": h.Node, "signed_out": data.Users[p.User.ID] == nil})
	}
}

// setupRestore is the first-run alternative to creating an admin: set the
// node up from a backup. Like setup, it needs the code from the log.
func (a *API) setupRestore(w http.ResponseWriter, r *http.Request) {
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	file, form, ok := readBackupForm(w, r)
	if !ok {
		return
	}
	ip := clientIP(r)
	if ok, wait := a.Throttle.Allowed("setup:" + ip); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	a.setupOnce.Lock()
	defer a.setupOnce.Unlock()
	if a.setupCode == "" || len(a.Store.State().Users) > 0 {
		writeErr(w, http.StatusConflict, "this node is already set up; sign in and use Backups to restore")
		return
	}
	if subtle.ConstantTimeCompare([]byte(auth.NormalizeSetupCode(form["code"])), []byte(auth.NormalizeSetupCode(a.setupCode))) != 1 {
		a.Throttle.Fail("setup:" + ip)
		writeErr(w, http.StatusForbidden, "that setup code doesn't match; check the container log (a restart prints a new one)")
		return
	}
	h, data, ok := a.openUpload(w, file, form["passphrase"], ip)
	if !ok {
		return
	}
	if a.restoreBackup(w, "setup", h, data) {
		a.setupCode = ""
		writeJSON(w, http.StatusOK, map[string]any{"created": h.Created, "node": h.Node})
	}
}

// Change is one difference between two configurations.
type Change struct {
	Path string `json:"path"`
	Now  string `json:"now"`  // "" when absent now
	Then string `json:"then"` // "" when absent in the version
}

// DiffConfig lists what restoring then over now would change. Devices
// and groups are named by their names, not their IDs.
func DiffConfig(now, then store.ConfigSnapshot) []Change {
	a, b := flatten(now), flatten(then)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	// A device or group that exists on only one side is one change, not
	// one per field.
	whole := map[string]bool{}
	for k := range keys {
		if strings.Count(k, ".") == 1 && (strings.HasPrefix(k, "devices.") || strings.HasPrefix(k, "groups.")) && a[k] != b[k] {
			whole[k] = true
		}
	}
	out := []Change{}
	for k := range keys {
		if i := strings.Index(k, "."); i > 0 {
			if j := strings.Index(k[i+1:], "."); j > 0 && whole[k[:i+1+j]] {
				continue
			}
		}
		if a[k] != b[k] {
			out = append(out, Change{Path: k, Now: a[k], Then: b[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func flatten(c store.ConfigSnapshot) map[string]string {
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				walk(join(prefix, k), x)
			}
		case []any:
			if len(t) == 0 {
				return
			}
			if allScalar(t) {
				parts := make([]string, len(t))
				for i, x := range t {
					parts[i] = scalar(x)
				}
				out[prefix] = strings.Join(parts, ", ")
				return
			}
			for i, x := range t {
				walk(join(prefix, strconv.Itoa(i+1)), x)
			}
		case nil:
		default:
			if s := scalar(t); s != "" && s != "false" && s != "0" {
				out[prefix] = s
			}
		}
	}
	var s map[string]any
	b, _ := json.Marshal(c.Settings)
	_ = json.Unmarshal(b, &s)
	walk("settings", s)
	named := func(kind string, m any) {
		var items map[string]map[string]any
		b, _ := json.Marshal(m)
		_ = json.Unmarshal(b, &items)
		for id, it := range items {
			name, _ := it["name"].(string)
			if name == "" {
				name = id
			}
			delete(it, "id")
			delete(it, "created_at")
			delete(it, "updated_at")
			delete(it, "name")
			walk(kind+"."+name, it)
			out[kind+"."+name] = "present"
		}
	}
	named("devices", c.Devices)
	named("groups", c.Groups)
	return out
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

func allScalar(xs []any) bool {
	for _, x := range xs {
		switch x.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
