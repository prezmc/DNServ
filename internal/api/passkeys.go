package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/prezmc/dnserv/internal/auth"
	"github.com/prezmc/dnserv/internal/store"
)

// Passkeys (WebAuthn). A user adds them from their account page once the
// authenticator app is set up; the app and recovery codes stay as the
// fallback. A passkey can sign in on its own (it is already two factors:
// the device, plus Face ID, a fingerprint or the device PIN) or stand in
// for the 6-digit code after the password.
//
// The relying party ID is the dashboard's domain. When the dashboard is
// opened at a name with three or more labels (dns1.example.com), a passkey
// is made for the parent domain (example.com) so the same passkey works on
// every server under it; the browser refuses that for public suffixes, and
// the page then retries for the full name. Browsers allow passkeys only
// over HTTPS (or on localhost) and never for an IP address.

func (a *API) passkeyRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/auth/passkeys", a.authed("", a.listPasskeys))
	m.HandleFunc("POST /api/v1/auth/passkeys/begin", a.authed("", a.passkeyRegisterBegin))
	m.HandleFunc("POST /api/v1/auth/passkeys/finish", a.authed("", a.passkeyRegisterFinish))
	m.HandleFunc("PATCH /api/v1/auth/passkeys/{id}", a.authed("", a.renamePasskey))
	m.HandleFunc("DELETE /api/v1/auth/passkeys/{id}", a.authed("", a.deletePasskey))
	// Sign-in with a passkey alone, from the sign-in page.
	m.HandleFunc("POST /api/v1/auth/passkey/begin", a.passkeyLoginBegin)
	m.HandleFunc("POST /api/v1/auth/passkey/finish", a.passkeyLoginFinish)
	// A passkey in place of the code, after the password.
	m.HandleFunc("POST /api/v1/auth/mfa/passkey/begin", a.stage(auth.StageMFA, a.passkeyMFABegin))
	m.HandleFunc("POST /api/v1/auth/mfa/passkey/finish", a.stage(auth.StageMFA, a.passkeyMFAFinish))
}

// --- ceremonies in progress ---

const (
	ceremonyTTL = 3 * time.Minute
	maxCeremony = 500
)

type ceremony struct {
	kind    string // "register", "login", "mfa"
	userID  string // "" for a sign-in with a passkey alone
	rpID    string
	origin  string
	data    webauthn.SessionData
	expires time.Time
}

type ceremonies struct {
	mu sync.Mutex
	m  map[string]*ceremony
}

func (c *ceremonies) put(x *ceremony, now time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*ceremony{}
	}
	if len(c.m) >= maxCeremony {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxCeremony {
			return "", errors.New("too many passkey sign-ins in progress; try again in a minute")
		}
	}
	id := auth.RandomID(18)
	x.expires = now.Add(ceremonyTTL)
	c.m[id] = x
	return id, nil
}

// take returns and forgets a ceremony, so each challenge is used once.
func (c *ceremonies) take(id, kind string, now time.Time) *ceremony {
	c.mu.Lock()
	defer c.mu.Unlock()
	x, ok := c.m[id]
	if !ok {
		return nil
	}
	delete(c.m, id)
	if x.kind != kind || now.After(x.expires) {
		return nil
	}
	return x
}

// --- relying party ---

// rpOrigin returns the page's origin and its host name. WebAuthn needs the
// browser's Origin header, which every passkey request has.
func (a *API) rpOrigin(r *http.Request) (origin, host string, err error) {
	o := r.Header.Get("Origin")
	if o == "" {
		return "", "", errors.New("passkeys need a browser")
	}
	if err := a.checkOrigin(r); err != nil {
		return "", "", err
	}
	u, err := url.Parse(o)
	if err != nil || u.Hostname() == "" {
		return "", "", errors.New("bad origin")
	}
	host = strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil {
		return "", "", errors.New("passkeys don't work when the dashboard is opened by IP address; open it by its name over HTTPS")
	}
	return o, host, nil
}

// rpCandidates lists the relying party IDs a page at host may use, widest
// first: the parent domain (when host has three or more labels), then host.
func rpCandidates(host string) []string {
	if i := strings.IndexByte(host, '.'); i > 0 && strings.Count(host, ".") >= 2 {
		return []string{host[i+1:], host}
	}
	return []string{host}
}

// rpFor picks the relying party ID for a sign-in: the first candidate that
// some stored passkey was made for (of user, or of anyone when user is
// nil), else the widest.
func rpFor(st *store.State, user *store.User, host string) string {
	cands := rpCandidates(host)
	for _, c := range cands {
		for _, u := range st.Users {
			if user != nil && u.ID != user.ID {
				continue
			}
			for _, p := range u.Passkeys {
				if p.RPID == c {
					return c
				}
			}
		}
	}
	return cands[0]
}

func newRP(rpID, origin string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: Issuer, RPOrigins: []string{origin}})
}

// waUser adapts a user to the WebAuthn library, offering only the passkeys
// made for one relying party.
type waUser struct {
	u    *store.User
	rpID string
}

func (w waUser) WebAuthnID() []byte          { return []byte(w.u.ID) }
func (w waUser) WebAuthnName() string        { return w.u.Username }
func (w waUser) WebAuthnDisplayName() string { return w.u.Username }
func (w waUser) WebAuthnCredentials() []webauthn.Credential {
	var out []webauthn.Credential
	for _, p := range w.u.Passkeys {
		if p.RPID != w.rpID {
			continue
		}
		tr := make([]protocol.AuthenticatorTransport, len(p.Transports))
		for i, t := range p.Transports {
			tr[i] = protocol.AuthenticatorTransport(t)
		}
		out = append(out, webauthn.Credential{
			ID: p.ID, PublicKey: p.PublicKey, AttestationType: p.AttType, AttestationFormat: p.AttFormat, Transport: tr,
			Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: p.UV, BackupEligible: p.BE, BackupState: p.BS},
			Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount, Attachment: protocol.AuthenticatorAttachment(p.Attachment)},
		})
	}
	return out
}

func descriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, len(creds))
	for i, c := range creds {
		out[i] = c.Descriptor()
	}
	return out
}

// --- managing passkeys ---

type passkeyView struct {
	ID       string    `json:"id"` // base64url credential ID
	Name     string    `json:"name"`
	Domain   string    `json:"domain"`
	Synced   bool      `json:"synced"` // can be backed up / synced (iCloud Keychain, Google, 1Password …)
	Created  time.Time `json:"created_at"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *API) listPasskeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	out := []passkeyView{}
	for _, k := range p.User.Passkeys {
		out = append(out, passkeyView{ID: b64(k.ID), Name: k.Name, Domain: k.RPID, Synced: k.BE, Created: k.CreatedAt, LastUsed: k.LastUsed})
	}
	writeJSON(w, http.StatusOK, out)
}

func sessionOnly(w http.ResponseWriter, p *Principal) bool {
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "API tokens can't manage passkeys")
		return false
	}
	return true
}

// passkeyRegisterBegin asks for the password again (a stolen session must
// not be able to add a lasting way in), then returns creation options.
func (a *API) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !sessionOnly(w, p) {
		return
	}
	var req struct {
		Password string
		// Host makes the passkey for this server's full name only, after
		// the browser refused the parent domain.
		Host bool
	}
	if !readJSON(w, r, &req) {
		return
	}
	key := "pw:" + p.User.ID
	if ok, wait := a.Throttle.Allowed(key); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many wrong passwords; try again in %s", wait.Round(time.Second)))
		return
	}
	if !auth.VerifyPassword(p.User.PasswordHash, req.Password) {
		a.Throttle.Fail(key)
		writeErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	a.Throttle.Succeed(key)
	origin, host, err := a.rpOrigin(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rpID := rpCandidates(host)[0]
	if req.Host {
		rpID = host
	}
	rp, err := newRP(rpID, origin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Exclude every passkey the user has, whatever its domain, so one
	// device isn't registered twice.
	var excl []protocol.CredentialDescriptor
	for _, k := range p.User.Passkeys {
		excl = append(excl, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: k.ID})
	}
	opts, data, err := rp.BeginRegistration(waUser{u: p.User, rpID: rpID},
		webauthn.WithExclusions(excl),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ticket, err := a.passkeyCer.put(&ceremony{kind: "register", userID: p.User.ID, rpID: rpID, origin: origin, data: *data}, a.now())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "options": opts.Response, "domain": rpID})
}

func (a *API) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !sessionOnly(w, p) {
		return
	}
	var req struct {
		Ticket, Name string
		Credential   json.RawMessage
	}
	if !readJSON(w, r, &req) {
		return
	}
	c := a.passkeyCer.take(req.Ticket, "register", a.now())
	if c == nil || c.userID != p.User.ID {
		writeErr(w, http.StatusBadRequest, "that took too long; try again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the browser's answer couldn't be read: "+webauthnMsg(err))
		return
	}
	rp, err := newRP(c.rpID, c.origin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cred, err := rp.CreateCredential(waUser{u: p.User, rpID: c.rpID}, c.data, parsed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the passkey couldn't be checked: "+webauthnMsg(err))
		return
	}
	tr := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		tr[i] = string(t)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = deviceGuess(r.UserAgent())
	}
	pk := store.Passkey{
		ID: cred.ID, Name: name, PublicKey: cred.PublicKey, RPID: c.rpID, AAGUID: cred.Authenticator.AAGUID,
		SignCount: cred.Authenticator.SignCount, Transports: tr, Attachment: string(cred.Authenticator.Attachment),
		AttType: cred.AttestationType, AttFormat: cred.AttestationFormat,
		UV: cred.Flags.UserVerified, BE: cred.Flags.BackupEligible, BS: cred.Flags.BackupState,
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpPasskeyAdd, p.Actor(), store.PasskeyAdd{UserID: p.User.ID, Passkey: pk})); !ok {
		return
	}
	writeJSON(w, http.StatusCreated, passkeyView{ID: b64(pk.ID), Name: name, Domain: pk.RPID, Synced: pk.BE, Created: a.now()})
}

func pathCredID(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return nil, false
	}
	return id, true
}

func (a *API) renamePasskey(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !sessionOnly(w, p) {
		return
	}
	var req struct{ Name string }
	if !readJSON(w, r, &req) {
		return
	}
	id, ok := pathCredID(w, r)
	if !ok {
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpPasskeyRename, p.Actor(), store.PasskeyRef{UserID: p.User.ID, ID: id, Name: req.Name})); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deletePasskey(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !sessionOnly(w, p) {
		return
	}
	id, ok := pathCredID(w, r)
	if !ok {
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpPasskeyDelete, p.Actor(), store.PasskeyRef{UserID: p.User.ID, ID: id})); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- signing in ---

func (a *API) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ipKey := "ip:" + clientIP(r)
	if ok, wait := a.Throttle.Allowed(ipKey); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %s", wait.Round(time.Second)))
		return
	}
	origin, host, err := a.rpOrigin(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rpID := rpFor(a.Store.State(), nil, host)
	rp, err := newRP(rpID, origin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, data, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ticket, err := a.passkeyCer.put(&ceremony{kind: "login", rpID: rpID, origin: origin, data: *data}, a.now())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "options": opts.Response})
}

func (a *API) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket     string
		Credential json.RawMessage
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	ip := clientIP(r)
	ipKey := "ip:" + ip
	if ok, wait := a.Throttle.Allowed(ipKey); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %s", wait.Round(time.Second)))
		return
	}
	c := a.passkeyCer.take(req.Ticket, "login", a.now())
	if c == nil {
		writeErr(w, http.StatusBadRequest, "that took too long; try again")
		return
	}
	st := a.Store.State()
	u, pk, err := a.checkAssertion(c, req.Credential, func(rawID, handle []byte) (webauthn.User, error) {
		found := st.Users[string(handle)]
		if found == nil || found.PasskeyByID(rawID) == nil {
			return nil, errors.New("this passkey isn't registered here (it may have been removed)")
		}
		return waUser{u: found, rpID: c.rpID}, nil
	})
	if err == nil && (u.Disabled || !u.MFAEnrolled()) {
		err = errors.New("this account can't sign in")
	}
	if err != nil {
		a.Throttle.Fail(ipKey)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.Throttle.Succeed(ipKey)
	a.Throttle.Succeed("u:" + strings.ToLower(u.Username))
	a.passkeyUsed(u, pk)
	token, s := a.Sessions.Create(u.ID, auth.StageFull, ip, r.UserAgent())
	a.setCookie(w, r, token, auth.AbsoluteTTL)
	writeJSON(w, http.StatusOK, map[string]any{"stage": s.Stage, "csrf": s.CSRF})
}

func (a *API) passkeyMFABegin(w http.ResponseWriter, r *http.Request, p *Principal) {
	origin, host, err := a.rpOrigin(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rpID := rpFor(a.Store.State(), p.User, host)
	user := waUser{u: p.User, rpID: rpID}
	creds := user.WebAuthnCredentials()
	if len(creds) == 0 {
		writeErr(w, http.StatusNotFound, "you have no passkey for "+host+"; use your authenticator app")
		return
	}
	rp, err := newRP(rpID, origin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, data, err := rp.BeginLogin(user, webauthn.WithAllowedCredentials(descriptors(creds)), webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ticket, err := a.passkeyCer.put(&ceremony{kind: "mfa", userID: p.User.ID, rpID: rpID, origin: origin, data: *data}, a.now())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "options": opts.Response})
}

func (a *API) passkeyMFAFinish(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Ticket     string
		Credential json.RawMessage
	}
	if !readJSON(w, r, &req) {
		return
	}
	key := "mfa:" + p.User.ID
	if ok, wait := a.Throttle.Allowed(key); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed tries; try again in %s", wait.Round(time.Second)))
		return
	}
	c := a.passkeyCer.take(req.Ticket, "mfa", a.now())
	if c == nil || c.userID != p.User.ID {
		writeErr(w, http.StatusBadRequest, "that took too long; try again")
		return
	}
	u, pk, err := a.checkAssertion(c, req.Credential, nil)
	if err != nil || u.ID != p.User.ID {
		if err == nil {
			err = errors.New("that passkey belongs to someone else")
		}
		a.Throttle.Fail(key)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.Throttle.Succeed(key)
	a.Throttle.Succeed("u:" + strings.ToLower(u.Username))
	a.passkeyUsed(u, pk)
	a.finishSignIn(w, r)
}

// checkAssertion verifies a sign-in answer: against the ceremony's user,
// or (with handler) against whoever the passkey belongs to.
func (a *API) checkAssertion(c *ceremony, raw json.RawMessage, handler webauthn.DiscoverableUserHandler) (*store.User, *webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return nil, nil, errors.New("the browser's answer couldn't be read: " + webauthnMsg(err))
	}
	rp, err := newRP(c.rpID, c.origin)
	if err != nil {
		return nil, nil, err
	}
	var user *store.User
	var cred *webauthn.Credential
	if handler != nil {
		var wu webauthn.User
		wu, cred, err = rp.ValidatePasskeyLogin(handler, c.data, parsed)
		if err == nil {
			user = wu.(waUser).u
		}
	} else {
		user = a.Store.State().Users[c.userID]
		if user == nil {
			return nil, nil, errors.New("sign in again")
		}
		cred, err = rp.ValidateLogin(waUser{u: user, rpID: c.rpID}, c.data, parsed)
	}
	if err != nil {
		return nil, nil, errors.New("the passkey couldn't be checked: " + webauthnMsg(err))
	}
	if cred.Authenticator.CloneWarning {
		return nil, nil, errors.New("this passkey's counter went backwards, which can mean it was copied; remove it and add it again")
	}
	return user, cred, nil
}

// passkeyUsed records the sign-in. Like authenticator codes, a sign-in
// still works when the cluster can't take the change.
func (a *API) passkeyUsed(u *store.User, cred *webauthn.Credential) {
	_, err := a.Store.Apply(store.NewCommand(store.OpPasskeyUsed, u.Username, store.PasskeyUsed{
		UserID: u.ID, ID: cred.ID, SignCount: cred.Authenticator.SignCount, BackupState: cred.Flags.BackupState}))
	if err != nil && !errors.Is(err, store.ErrUnavailable) && a.Log != nil {
		a.Log.Warn("could not record passkey use", "user", u.Username, "err", err)
	}
}

// webauthnMsg gives the useful part of a library error.
func webauthnMsg(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return pe.DevInfo
	}
	return err.Error()
}

// deviceGuess names a passkey from the browser, for when none is given.
func deviceGuess(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "iPhone"
	case strings.Contains(ua, "iPad"):
		return "iPad"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Macintosh"):
		return "Mac"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return "Passkey"
}
