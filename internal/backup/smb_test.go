package backup

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// TestSMB runs against a real share when DNSERV_SMB_TEST is set to
// "\\\\host:port\\share user password" (see docs/development.md).
func TestSMB(t *testing.T) {
	spec := strings.Fields(os.Getenv("DNSERV_SMB_TEST"))
	if len(spec) != 3 {
		t.Skip("set DNSERV_SMB_TEST to test against a real share")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, user, pass := spec[0], spec[1], strings.ReplaceAll(spec[2], "+", " ")
	tg := store.SMBTarget{Server: srv + `\dnserv\home`, User: user, Password: pass}
	if err := tg.Clean(); err != nil {
		t.Fatal(err)
	}
	c := &SMB{T: tg}
	if err := c.Test(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "dnserv-a-20261113-030000.dnsbak", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "dnserv-a-20261113-030000.dnsbak", []byte("hello2")); err != nil {
		t.Fatal("overwrite:", err)
	}
	l, err := c.List(ctx)
	b, err := c.Get(ctx, "dnserv-a-20261113-030000.dnsbak")
	if string(b) != "hello2" || err != nil {
		t.Fatal(string(b), err)
	}
	if err := c.Delete(ctx, "dnserv-a-20261113-030000.dnsbak"); err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || err != nil {
		t.Fatalf("list %+v %v", l, err)
	}
	bad := &SMB{T: tg}
	bad.T.Password = "wrong"
	if err := bad.Test(ctx); err == nil || !strings.Contains(err.Error(), "password was refused") {
		t.Fatalf("bad password: %v", err)
	}
	bad = &SMB{T: tg}
	bad.T.Share = "no-such-share"
	if err := bad.Test(ctx); err == nil || !strings.Contains(err.Error(), "no share by that name") {
		t.Fatalf("bad share: %v", err)
	}
	empty := &SMB{T: tg}
	empty.T.Folder = "not/yet"
	if l, err := empty.List(ctx); len(l) != 0 || err != nil {
		t.Fatalf("missing folder: %v %v", l, err)
	}
}
