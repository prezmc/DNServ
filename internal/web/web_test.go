package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler()
	for path, want := range map[string]string{
		"/":         "<!doctype html>",
		"/settings": "<!doctype html>", // app routes fall back to the page
		"/app.js":   "'use strict'",
		"/app.css":  ":root",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: HTTP %d, body doesn't contain %q", path, rec.Code, want)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP %q", path, csp)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/../web.go", nil))
	if strings.Contains(rec.Body.String(), "package web") {
		t.Fatal("served a file outside the static folder")
	}
}
