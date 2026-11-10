package api

import (
	"context"
	"testing"
	"time"
)

func TestSelfServiceSecondFactor(t *testing.T) {
	e := newEnv(t)
	admin, oldSecret := e.setupAdmin()
	type codes struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}

	// New recovery codes need the password; old ones stop working.
	admin.want(401, "POST", "/api/v1/auth/recovery-codes", map[string]string{"password": "wrong"}, nil)
	var rc codes
	admin.want(200, "POST", "/api/v1/auth/recovery-codes", map[string]string{"password": pw}, &rc)
	if len(rc.RecoveryCodes) != 10 {
		t.Fatalf("got %d codes", len(rc.RecoveryCodes))
	}

	// Move to a new authenticator. The old one works until confirmed.
	admin.want(401, "POST", "/api/v1/auth/authenticator/begin", map[string]string{"password": "wrong"}, nil)
	admin.want(400, "POST", "/api/v1/auth/authenticator/confirm", map[string]string{"code": "123456"}, nil)
	var begin struct{ Secret string }
	admin.want(200, "POST", "/api/v1/auth/authenticator/begin", map[string]string{"password": pw}, &begin)
	if begin.Secret == "" || begin.Secret == oldSecret {
		t.Fatal("no new secret")
	}
	e.now = e.now.Add(time.Minute)
	b := e.client()
	b.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	b.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(oldSecret)}, nil) // still the old app

	admin.want(401, "POST", "/api/v1/auth/authenticator/confirm", map[string]string{"code": e.code(oldSecret)}, nil)
	var rc2 codes
	e.now = e.now.Add(time.Minute)
	admin.want(200, "POST", "/api/v1/auth/authenticator/confirm", map[string]string{"code": e.code(begin.Secret)}, &rc2)
	if len(rc2.RecoveryCodes) != 10 || rc2.RecoveryCodes[0] == rc.RecoveryCodes[0] {
		t.Fatal("recovery codes not replaced")
	}

	e.now = e.now.Add(time.Minute)
	c := e.client()
	c.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	c.want(401, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(oldSecret)}, nil)
	c.want(401, "POST", "/api/v1/auth/mfa", map[string]string{"code": rc.RecoveryCodes[0]}, nil)
	c.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(begin.Secret)}, nil)

	// List updates: 503 without a hook, 202 with one.
	admin.want(503, "POST", "/api/v1/lists/update", nil, nil)
	called := make(chan struct{}, 1)
	e.api.UpdateLists = func() { called <- struct{}{} }
	admin.want(202, "POST", "/api/v1/lists/update", nil, nil)
	<-called

	// Clearing the cache: 503 without a hook, each server's result with one.
	admin.want(503, "POST", "/api/v1/cache/clear", nil, nil)
	e.api.ClearCache = func(context.Context) []CacheCleared {
		return []CacheCleared{{Server: "n1", Entries: 12}, {Server: "n2", Error: "down"}}
	}
	var cleared struct{ Servers []CacheCleared }
	admin.want(200, "POST", "/api/v1/cache/clear", nil, &cleared)
	if len(cleared.Servers) != 2 || cleared.Servers[0].Entries != 12 || cleared.Servers[1].Error != "down" {
		t.Fatalf("cache clear result %+v", cleared)
	}
}
