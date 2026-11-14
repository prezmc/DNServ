package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// softKey is a software passkey: what a phone or laptop does, in a test.
type softKey struct {
	t      *testing.T
	id     []byte
	key    *ecdsa.PrivateKey
	user   []byte
	count  uint32
	origin string
}

func newSoftKey(t *testing.T, origin string) *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softKey{t: t, id: id, key: k, origin: origin}
}

var enc = base64.RawURLEncoding

func (k *softKey) authData(rpID string, withKey bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04 | 0x08 | 0x10) // present, verified, backup eligible + backed up
	if withKey {
		flags |= 0x40
	}
	k.count++
	b := append(h[:], flags)
	b = binary.BigEndian.AppendUint32(b, k.count)
	if withKey {
		b = append(b, make([]byte, 16)...) // AAGUID
		b = binary.BigEndian.AppendUint16(b, uint16(len(k.id)))
		b = append(b, k.id...)
		x, y := k.key.PublicKey.X.FillBytes(make([]byte, 32)), k.key.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		b = append(b, cose...)
	}
	return b
}

func (k *softKey) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": k.origin})
	return b
}

type wireOptions struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// create answers registration options.
func (k *softKey) create(opts wireOptions) map[string]any {
	k.user, _ = enc.DecodeString(opts.User.ID)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(opts.RP.ID, true)})
	return map[string]any{"id": enc.EncodeToString(k.id), "rawId": enc.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": enc.EncodeToString(k.clientData("webauthn.create", opts.Challenge)), "attestationObject": enc.EncodeToString(att), "transports": []string{"internal"}}}
}

// get answers sign-in options.
func (k *softKey) get(opts wireOptions) map[string]any {
	ad := k.authData(opts.RPID, false)
	cd := k.clientData("webauthn.get", opts.Challenge)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return map[string]any{"id": enc.EncodeToString(k.id), "rawId": enc.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": enc.EncodeToString(cd), "authenticatorData": enc.EncodeToString(ad), "signature": enc.EncodeToString(sig), "userHandle": enc.EncodeToString(k.user)}}
}

type begun struct {
	Ticket  string
	Domain  string
	Options wireOptions
}

func TestPasskeys(t *testing.T) {
	e := newEnv(t)
	const origin = "https://dns1.example.com"
	e.api.AllowedOrigins = []string{"dns1.example.com"}
	admin, secret := e.setupAdmin()
	admin.origin = origin
	key := newSoftKey(t, origin)

	// Adding a passkey needs the password, and a name.
	admin.want(401, "POST", "/api/v1/auth/passkeys/begin", map[string]any{"password": "wrong"}, nil)
	var b begun
	admin.want(200, "POST", "/api/v1/auth/passkeys/begin", map[string]any{"password": pw}, &b)
	if b.Domain != "dns1.example.com" || b.Options.RP.ID != "dns1.example.com" {
		t.Fatalf("passkey domain %q / %q, want this server's name only", b.Domain, b.Options.RP.ID)
	}
	admin.want(201, "POST", "/api/v1/auth/passkeys/finish", map[string]any{"ticket": b.Ticket, "name": "Shannon's Mac", "credential": key.create(b.Options)}, nil)
	// The challenge works once.
	admin.want(400, "POST", "/api/v1/auth/passkeys/finish", map[string]any{"ticket": b.Ticket, "name": "x", "credential": key.create(b.Options)}, nil)

	var list []passkeyView
	admin.want(200, "GET", "/api/v1/auth/passkeys", nil, &list)
	if len(list) != 1 || list[0].Name != "Shannon's Mac" || !list[0].Synced || list[0].Domain != "dns1.example.com" {
		t.Fatalf("list %+v", list)
	}
	admin.want(204, "PATCH", "/api/v1/auth/passkeys/"+list[0].ID, map[string]any{"name": "MacBook"}, nil)
	admin.want(400, "PATCH", "/api/v1/auth/passkeys/"+list[0].ID, map[string]any{"name": " "}, nil)

	// Sign in with the passkey alone: straight to a full session.
	c := e.client()
	c.origin = origin
	var lb begun
	c.want(200, "POST", "/api/v1/auth/passkey/begin", nil, &lb)
	if lb.Options.RPID != "dns1.example.com" {
		t.Fatalf("sign-in rpId %q", lb.Options.RPID)
	}
	c.want(200, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": key.get(lb.Options)}, nil)
	c.want(200, "GET", "/api/v1/users", nil, nil)
	admin.want(200, "GET", "/api/v1/auth/passkeys", nil, &list)
	if list[0].LastUsed.IsZero() || list[0].Name != "MacBook" {
		t.Fatalf("after sign-in %+v", list[0])
	}

	// Another server under the same domain can't use it: each server's
	// passkey is for that server's name only.
	key.origin = "https://dns2.example.com"
	e.api.AllowedOrigins = append(e.api.AllowedOrigins, "dns2.example.com")
	c2 := e.client()
	c2.origin = key.origin
	c2.want(200, "POST", "/api/v1/auth/passkey/begin", nil, &lb)
	if lb.Options.RPID != "dns2.example.com" {
		t.Fatalf("dns2 sign-in rpId %q", lb.Options.RPID)
	}
	c2.want(401, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": key.get(lb.Options)}, nil)
	c2.want(401, "GET", "/api/v1/users", nil, nil)

	// A different key, or a signature for another challenge, fails.
	other := newSoftKey(t, origin)
	other.user = key.user
	c3 := e.client()
	c3.origin = origin
	c3.want(200, "POST", "/api/v1/auth/passkey/begin", nil, &lb)
	c3.want(401, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": other.get(lb.Options)}, nil)
	key.origin = origin
	c3.want(200, "POST", "/api/v1/auth/passkey/begin", nil, &lb)
	stale := lb.Options
	stale.Challenge = enc.EncodeToString([]byte("not the challenge"))
	c3.want(401, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": key.get(stale)}, nil)
	c3.want(401, "GET", "/api/v1/users", nil, nil)

	// After the password, a passkey stands in for the 6-digit code.
	d := e.client()
	d.origin = origin
	d.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	d.want(200, "POST", "/api/v1/auth/mfa/passkey/begin", nil, &lb)
	d.want(200, "POST", "/api/v1/auth/mfa/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": key.get(lb.Options)}, nil)
	d.want(200, "GET", "/api/v1/users", nil, nil)

	// The authenticator app still works.
	e.now = e.now.Add(time.Minute)
	f := e.client()
	f.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	f.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)

	// Passkeys can't be used by IP address.
	g := e.client()
	g.origin = e.srv.URL
	g.want(400, "POST", "/api/v1/auth/passkey/begin", nil, nil)

	// Removing it stops it working.
	admin.want(204, "DELETE", "/api/v1/auth/passkeys/"+list[0].ID, nil, nil)
	h := e.client()
	h.origin = origin
	h.want(200, "POST", "/api/v1/auth/passkey/begin", nil, &lb)
	h.want(401, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ticket": lb.Ticket, "credential": key.get(lb.Options)}, nil)
}

func TestRPCandidates(t *testing.T) {
	for host, want := range map[string][]string{
		"dns1.example.com": {"dns1.example.com", "example.com"},
		"example.com":      {"example.com"},
		"dns.lan":          {"dns.lan"},
		"localhost":        {"localhost"},
	} {
		got := rpCandidates(host)
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
}
