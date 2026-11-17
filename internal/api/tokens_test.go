package api

import (
	"strings"
	"testing"
	"time"
)

type tokenRow struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Perms    []string  `json:"perms"`
	LastUsed time.Time `json:"last_used"`
	LastAddr string    `json:"last_addr"`
}

// waitToken polls the token list until ok accepts the token's row, since
// use is recorded in the background.
func waitToken(t *testing.T, c *client, id string, ok func(tokenRow) bool) tokenRow {
	t.Helper()
	var last tokenRow
	for i := 0; i < 100; i++ {
		var rows []tokenRow
		c.want(200, "GET", "/api/v1/tokens", nil, &rows)
		for _, r := range rows {
			if r.ID == id {
				last = r
				if ok(r) {
					return r
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("token %s never got there; last %+v", id, last)
	return last
}

func TestTokenLastUsed(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var tok struct{ ID, Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "script", "perms": []string{"dashboard.view"}}, &tok)

	row := waitToken(t, admin, tok.ID, func(r tokenRow) bool { return true })
	if !row.LastUsed.IsZero() || row.LastAddr != "" {
		t.Fatalf("new token already used: %+v", row)
	}

	bot := e.client()
	bot.token = tok.Token
	bot.want(200, "GET", "/api/v1/status", nil, nil)
	first := waitToken(t, admin, tok.ID, func(r tokenRow) bool { return !r.LastUsed.IsZero() })
	if first.LastAddr != "127.0.0.1" {
		t.Fatalf("last address %q, want 127.0.0.1", first.LastAddr)
	}

	// Within a few minutes, more use isn't written again.
	e.now = e.now.Add(2 * time.Minute)
	bot.want(200, "GET", "/api/v1/status", nil, nil)
	time.Sleep(50 * time.Millisecond)
	if again := waitToken(t, admin, tok.ID, func(tokenRow) bool { return true }); !again.LastUsed.Equal(first.LastUsed) {
		t.Fatalf("use recorded again after 2 minutes: %v then %v", first.LastUsed, again.LastUsed)
	}

	// Later it is.
	e.now = e.now.Add(tokenUseEvery)
	bot.want(200, "GET", "/api/v1/status", nil, nil)
	waitToken(t, admin, tok.ID, func(r tokenRow) bool { return r.LastUsed.After(first.LastUsed) })

	// Use isn't audited.
	for _, a := range e.api.Store.State().Audit {
		if strings.Contains(a.Op, "token.used") {
			t.Fatalf("token use audited: %+v", a)
		}
	}
}

func TestTokenEdit(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var tok struct{ ID, Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "script", "perms": []string{"dashboard.view"}}, &tok)
	bot := e.client()
	bot.token = tok.Token
	bot.want(403, "POST", "/api/v1/domains", map[string]string{"domain": "ads.example", "action": "block"}, nil)

	// Rename and widen it; the same secret keeps working with the new rights.
	var row tokenRow
	admin.want(200, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"name": "Home Assistant", "perms": []string{"dashboard.view", "domains.allowblock"}}, &row)
	if row.Name != "Home Assistant" || len(row.Perms) != 2 {
		t.Fatalf("after edit: %+v", row)
	}
	bot.want(200, "POST", "/api/v1/domains", map[string]string{"domain": "ads.example", "action": "block"}, nil)

	// Name only keeps the permissions.
	admin.want(200, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"name": "HA"}, &row)
	if row.Name != "HA" || len(row.Perms) != 2 {
		t.Fatalf("after rename: %+v", row)
	}

	admin.want(400, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"perms": []string{}}, nil)
	admin.want(400, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"name": "  "}, nil)
	admin.want(404, "PATCH", "/api/v1/tokens/nope", map[string]any{"name": "x"}, nil)

	// A token can't edit tokens, not even itself.
	bot.want(403, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"perms": []string{"users.manage"}}, nil)

	// The change is audited.
	found := false
	for _, a := range e.api.Store.State().Audit {
		if a.Op == "token.update" && strings.Contains(a.Summary, "domains.allowblock") {
			found = true
		}
	}
	if !found {
		t.Fatal("token change not in the audit log")
	}
}

func TestTokenEditLimits(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "pat", "password": pw, "role": "power", "perms": []string{"dashboard.view", "rules.edit"}}, nil)
	pat, _ := e.signInNew("pat", pw)
	var tok struct{ ID, Token string }
	pat.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "pat's", "perms": []string{"dashboard.view"}}, &tok)

	// Pat can't give their token more than they have.
	pat.want(403, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"perms": []string{"users.manage"}}, nil)
	pat.want(200, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"perms": []string{"rules.edit"}}, nil)

	// An admin can edit Pat's token, but not past what Pat can do.
	admin.want(403, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"perms": []string{"lists.manage"}}, nil)
	admin.want(200, "PATCH", "/api/v1/tokens/"+tok.ID, map[string]any{"name": "renamed by admin"}, nil)

	// Someone else's token is invisible to a non-admin.
	var adminTok struct{ ID string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "mine", "perms": []string{"dashboard.view"}}, &adminTok)
	pat.want(404, "PATCH", "/api/v1/tokens/"+adminTok.ID, map[string]any{"name": "x"}, nil)
}
