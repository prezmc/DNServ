// Package web serves the dashboard: a small single-page app with no
// build step and no external assets, so it works on a network with no
// internet access.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed static
var files embed.FS

// Handler serves the UI. Unknown paths get index.html so links into the
// app work after a reload.
func Handler() http.Handler {
	sub, _ := fs.Sub(files, "static")
	fsrv := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			p = "index.html"
		}
		if p == "index.html" {
			h.Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, sub, "index.html")
			return
		}
		h.Set("Cache-Control", "no-cache")
		fsrv.ServeHTTP(w, r)
	})
}
