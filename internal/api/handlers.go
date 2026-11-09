package api

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/store"
	"rsc.io/qr"
)

// --- setup ---

func (a *API) getSetup(w http.ResponseWriter, r *http.Request) {
	st := a.Store.State()
	writeJSON(w, http.StatusOK, map[string]bool{"needed": len(st.Users) == 0, "done": st.SetupDone})
}

// postSetup creates the first admin. It needs the one-time code from the
// container log, and works only while no user exists.
func (a *API) postSetup(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code, Username, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
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
		writeErr(w, http.StatusConflict, "setup is already complete; sign in instead")
		return
	}
	if subtle.ConstantTimeCompare([]byte(auth.NormalizeSetupCode(req.Code)), []byte(auth.NormalizeSetupCode(a.setupCode))) != 1 {
		a.Throttle.Fail("setup:" + ip)
		writeErr(w, http.StatusForbidden, "that setup code doesn't match; check the container log (a restart prints a new one)")
		return
	}
	if err := auth.CheckPasswordStrength(req.Password, req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	id := auth.RandomID(9)
	if _, ok := a.apply(w, store.NewCommand(store.OpUserCreate, "setup", store.UserCreate{ID: id, Username: req.Username, Role: store.RoleAdmin, PasswordHash: hash})); !ok {
		return
	}
	a.setupCode = ""
	token, s := a.Sessions.Create(id, auth.StageEnroll, ip, r.UserAgent())
	a.setCookie(w, r, token, auth.PendingTTL)
	writeJSON(w, http.StatusCreated, map[string]any{"stage": s.Stage, "csrf": s.CSRF})
}

// checkSetupCode lets the wizard confirm the code before asking for an
// account. It is throttled like setup itself.
func (a *API) checkSetupCode(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	key := "setup:" + clientIP(r)
	if ok, wait := a.Throttle.Allowed(key); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	code := a.SetupCode()
	if code == "" {
		writeErr(w, http.StatusConflict, "setup is already complete; sign in instead")
		return
	}
	if subtle.ConstantTimeCompare([]byte(auth.NormalizeSetupCode(req.Code)), []byte(auth.NormalizeSetupCode(code))) != 1 {
		a.Throttle.Fail(key)
		writeErr(w, http.StatusForbidden, "that setup code doesn't match; check the container log (a restart prints a new one)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- sign-in ---

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.checkOrigin(r); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	ip := clientIP(r)
	userKey, ipKey := "u:"+strings.ToLower(req.Username), "ip:"+ip
	for _, k := range []string{userKey, ipKey} {
		if ok, wait := a.Throttle.Allowed(k); !ok {
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %s", wait.Round(time.Second)))
			return
		}
	}
	u := a.Store.State().UserByName(req.Username)
	if u == nil {
		auth.VerifyDummy(req.Password)
	}
	if u == nil || u.Disabled || !auth.VerifyPassword(u.PasswordHash, req.Password) {
		a.Throttle.Fail(userKey)
		a.Throttle.Fail(ipKey)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	a.Throttle.Succeed(ipKey)
	stage := auth.StageMFA
	if !u.MFAEnrolled() {
		stage = auth.StageEnroll
	}
	token, s := a.Sessions.Create(u.ID, stage, ip, r.UserAgent())
	a.setCookie(w, r, token, auth.PendingTTL)
	writeJSON(w, http.StatusOK, map[string]any{"stage": stage, "csrf": s.CSRF})
}

// mfa accepts an authenticator code or a recovery code.
func (a *API) mfa(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	key := "mfa:" + p.User.ID
	if ok, wait := a.Throttle.Allowed(key); !ok {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many wrong codes; try again in %s", wait.Round(time.Second)))
		return
	}
	u := p.User
	ok := false
	if step, valid := auth.VerifyTOTP(u.TOTPSecret, req.Code, a.now()); valid {
		// Recording the step rejects a replay of the same code.
		_, err := a.Store.Apply(store.NewCommand(store.OpTOTPUsed, u.Username, store.TOTPUsed{ID: u.ID, Step: step}))
		ok = err == nil
	} else if len(strings.TrimSpace(req.Code)) > 8 {
		h := auth.HashToken(auth.NormalizeRecovery(req.Code))
		_, err := a.Store.Apply(store.NewCommand(store.OpRecoveryUsed, u.Username, store.RecoveryUsed{ID: u.ID, Hash: h}))
		ok = err == nil
	}
	if !ok {
		a.Throttle.Fail(key)
		writeErr(w, http.StatusUnauthorized, "that code isn't valid")
		return
	}
	a.Throttle.Succeed(key)
	a.Throttle.Succeed("u:" + strings.ToLower(u.Username))
	a.finishSignIn(w, r)
}

func (a *API) finishSignIn(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(CookieName)
	token, s, ok := a.Sessions.Promote(c.Value, auth.StageFull)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "session expired; sign in again")
		return
	}
	a.setCookie(w, r, token, auth.AbsoluteTTL)
	writeJSON(w, http.StatusOK, map[string]any{"stage": s.Stage, "csrf": s.CSRF})
}

func (a *API) totpBegin(w http.ResponseWriter, r *http.Request, p *Principal) {
	secret := auth.NewTOTPSecret()
	if _, ok := a.apply(w, store.NewCommand(store.OpTOTPBegin, p.User.Username, store.TOTPBegin{ID: p.User.ID, Secret: secret})); !ok {
		return
	}
	u := auth.TOTPURL(secret, p.User.Username, Issuer)
	out := map[string]string{"secret": secret, "otpauth_url": u}
	if code, err := qr.Encode(u, qr.M); err == nil {
		code.Scale = 6
		out["qr_png"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	writeJSON(w, http.StatusOK, out)
}

// totpConfirm finishes enrollment with a code from the app, returns the
// recovery codes (shown once) and completes sign-in.
func (a *API) totpConfirm(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	u := p.User
	if u.TOTPPending == "" {
		writeErr(w, http.StatusBadRequest, "start enrollment first")
		return
	}
	step, ok := auth.VerifyTOTP(u.TOTPPending, req.Code, a.now())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "that code doesn't match; check the app's clock and try the next code")
		return
	}
	codes, hashes := auth.NewRecoveryCodes(10)
	if _, ok := a.apply(w, store.NewCommand(store.OpTOTPConfirm, u.Username, store.TOTPConfirm{ID: u.ID, Step: step, RecoveryHashes: hashes})); !ok {
		return
	}
	c, _ := r.Cookie(CookieName)
	token, s, ok := a.Sessions.Promote(c.Value, auth.StageFull)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "session expired; sign in again")
		return
	}
	a.setCookie(w, r, token, auth.AbsoluteTTL)
	writeJSON(w, http.StatusOK, map[string]any{"stage": s.Stage, "csrf": s.CSRF, "recovery_codes": codes})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		if s := a.Sessions.Get(c.Value); s != nil {
			if err := a.checkCSRF(r, s); err != nil {
				writeErr(w, http.StatusForbidden, err.Error())
				return
			}
		}
		a.Sessions.Delete(c.Value)
	}
	a.setCookie(w, r, "", -time.Second)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	st := a.Store.State()
	if p, _, _ := a.principal(r); p != nil && p.Token != nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": p.User.Public(), "token": p.Token.Name, "perms": p.Token.Perms})
		return
	}
	s, u := a.session(r, st)
	if s == nil {
		writeJSON(w, http.StatusOK, map[string]any{"signed_in": false, "setup_needed": len(st.Users) == 0})
		return
	}
	perms := []string{}
	for _, pm := range store.AllPerms {
		if u.Has(pm) {
			perms = append(perms, pm)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_in": s.Stage == auth.StageFull, "stage": s.Stage, "csrf": s.CSRF, "session_id": s.ID, "user": u.Public(), "perms": perms})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "API tokens can't change passwords")
		return
	}
	var req struct{ Current, New string }
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.VerifyPassword(p.User.PasswordHash, req.Current) {
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return
	}
	if err := auth.CheckPasswordStrength(req.New, p.User.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpUserPassword, p.Actor(), store.UserPassword{ID: p.User.ID, PasswordHash: hash})); !ok {
		return
	}
	// Other sessions end; this one gets a fresh token.
	a.Sessions.RevokeUser(p.User.ID, p.Session.ID)
	a.finishSignIn(w, r)
}

func (a *API) mySessions(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, a.Sessions.List(p.User.ID))
}

func (a *API) revokeMySession(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !a.Sessions.Revoke(r.PathValue("id"), p.User.ID) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- users ---

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, p *Principal) {
	st := a.Store.State()
	out := make([]store.PublicUser, 0, len(st.Users))
	for _, u := range st.Users {
		out = append(out, u.Public())
	}
	slices.SortFunc(out, func(x, y store.PublicUser) int {
		return strings.Compare(strings.ToLower(x.Username), strings.ToLower(y.Username))
	})
	writeJSON(w, http.StatusOK, out)
}

// createUser adds an account with a temporary password. The new user must
// enroll MFA at first sign-in.
func (a *API) createUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Username, Password, Role string
		Perms                    []string
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := auth.CheckPasswordStrength(req.Password, req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	id := auth.RandomID(9)
	if _, ok := a.apply(w, store.NewCommand(store.OpUserCreate, p.Actor(), store.UserCreate{ID: id, Username: req.Username, Role: req.Role, Perms: req.Perms, PasswordHash: hash})); !ok {
		return
	}
	writeJSON(w, http.StatusCreated, a.Store.State().Users[id].Public())
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Role     *string
		Perms    *[]string
		Disabled *bool
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if _, ok := a.apply(w, store.NewCommand(store.OpUserUpdate, p.Actor(), store.UserUpdate{ID: id, Role: req.Role, Perms: req.Perms, Disabled: req.Disabled})); !ok {
		return
	}
	if req.Disabled != nil && *req.Disabled {
		a.Sessions.RevokeUser(id, "")
	}
	writeJSON(w, http.StatusOK, a.Store.State().Users[id].Public())
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if _, ok := a.apply(w, store.NewCommand(store.OpUserDelete, p.Actor(), store.IDOnly{ID: id})); !ok {
		return
	}
	a.Sessions.RevokeUser(id, "")
	w.WriteHeader(http.StatusNoContent)
}

// setUserPassword lets an admin set a temporary password; the user's
// sessions end.
func (a *API) setUserPassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	u, ok := a.Store.State().Users[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := auth.CheckPasswordStrength(req.Password, u.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpUserPassword, p.Actor(), store.UserPassword{ID: id, PasswordHash: hash})); !ok {
		return
	}
	a.Sessions.RevokeUser(id, "")
	w.WriteHeader(http.StatusNoContent)
}

// resetMFA clears a user's second factor (lost phone); they enroll again
// at next sign-in.
func (a *API) resetMFA(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if _, ok := a.apply(w, store.NewCommand(store.OpMFAReset, p.Actor(), store.IDOnly{ID: id})); !ok {
		return
	}
	a.Sessions.RevokeUser(id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) allSessions(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, a.Sessions.List(""))
}

func (a *API) revokeAnySession(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !a.Sessions.Revoke(r.PathValue("id"), "") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- API tokens ---

type tokenView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	UserID    string    `json:"user_id"`
	Perms     []string  `json:"perms"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request, p *Principal) {
	all := p.Can(store.PermUsers)
	out := []tokenView{}
	for _, t := range a.Store.State().Tokens {
		if all || t.UserID == p.User.ID {
			out = append(out, tokenView{t.ID, t.Name, t.UserID, t.Perms, t.CreatedAt, t.ExpiresAt})
		}
	}
	slices.SortFunc(out, func(x, y tokenView) int { return x.CreatedAt.Compare(y.CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// createToken issues a token limited to perms (which must be a subset of
// the creator's). The secret is shown once.
func (a *API) createToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "API tokens can't create tokens")
		return
	}
	var req struct {
		Name        string
		Perms       []string
		ExpiresDays int `json:"expires_days"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Perms) == 0 {
		writeErr(w, http.StatusBadRequest, "choose at least one permission")
		return
	}
	for _, pm := range req.Perms {
		if !p.Can(pm) {
			writeErr(w, http.StatusForbidden, "you can't grant "+pm)
			return
		}
	}
	id, secret := auth.RandomID(9), auth.RandomID(32)
	t := store.Token{ID: id, Name: req.Name, UserID: p.User.ID, Perms: req.Perms, Hash: auth.HashToken(secret)}
	if req.ExpiresDays > 0 {
		t.ExpiresAt = a.now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).UTC()
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpTokenCreate, p.Actor(), t)); !ok {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "token": "dns_" + id + "." + secret, "note": "copy this token now; it won't be shown again"})
}

func (a *API) revokeToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	t, ok := a.Store.State().Tokens[id]
	if !ok || (t.UserID != p.User.ID && !p.Can(store.PermUsers)) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpTokenRevoke, p.Actor(), store.IDOnly{ID: id})); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- settings ---

func (a *API) getSettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	eff := a.Effective()
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":     a.Store.State().Settings, // fields set from the UI
		"effective": eff,
	})
}

// patchSettings saves changed fields after checking the caller may change
// each area and that the result is a valid configuration.
func (a *API) patchSettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	var patch store.Settings
	if !readJSON(w, r, &patch) {
		return
	}
	up, nw, lists, rules := patch.Touches()
	for _, need := range []struct {
		touched bool
		perm    string
	}{{up, store.PermUpstream}, {nw, store.PermNetwork}, {lists, store.PermLists}, {rules, store.PermRules}} {
		if need.touched && !p.Can(need.perm) {
			writeErr(w, http.StatusForbidden, "you don't have permission to change "+need.perm)
			return
		}
	}
	if !(up || nw || lists || rules) {
		writeErr(w, http.StatusBadRequest, "nothing to change")
		return
	}
	if patch.Rules != nil {
		for _, rule := range *patch.Rules {
			if _, ok, _ := filter.ParseLine(rule); !ok {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("rule %q isn't supported", rule))
				return
			}
		}
	}
	next := a.Store.State().Settings
	next.Merge(patch)
	if err := next.Overlay(a.Base).Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpSettingsUpdate, p.Actor(), patch)); !ok {
		return
	}
	a.getSettings(w, r, p)
}

func (a *API) resetSettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Fields []string }
	if !readJSON(w, r, &req) {
		return
	}
	if !p.Can(store.PermUsers) { // resetting is an admin action
		writeErr(w, http.StatusForbidden, "only admins can reset settings")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpSettingsReset, p.Actor(), store.SettingsReset{Fields: req.Fields})); !ok {
		return
	}
	a.getSettings(w, r, p)
}

// domainAction is the dashboard's one-click block / allow / clear for a
// domain and its subdomains. It edits the custom rules.
func (a *API) domainAction(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Domain, Action string }
	if !readJSON(w, r, &req) {
		return
	}
	d := filter.Normalize(strings.TrimSpace(req.Domain))
	if rules, ok, _ := filter.ParseLine(d); !ok || len(rules) != 1 || rules[0].Domain != d {
		writeErr(w, http.StatusBadRequest, "not a valid domain")
		return
	}
	block, allow := "||"+d+"^", "@@||"+d+"^"
	cur := a.Effective().Filtering.Rules
	next := slices.DeleteFunc(slices.Clone(cur), func(s string) bool { s = strings.TrimSpace(s); return s == block || s == allow })
	switch req.Action {
	case "block":
		next = append(next, block)
	case "allow":
		next = append(next, allow)
	case "clear":
	default:
		writeErr(w, http.StatusBadRequest, "action must be block, allow or clear")
		return
	}
	if _, ok := a.apply(w, store.NewCommand(store.OpSettingsUpdate, p.Actor(), store.Settings{Rules: &next})); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": next})
}

// --- status and audit ---

func (a *API) status(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.Status == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, a.Status())
}

func (a *API) audit(w http.ResponseWriter, r *http.Request, p *Principal) {
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, store.MaxAudit)
	}
	log := a.Store.State().Audit
	out := make([]store.AuditEntry, 0, min(limit, len(log)))
	for i := len(log) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, log[i])
	}
	writeJSON(w, http.StatusOK, out)
}

// sessionWithPassword checks that the caller is a person (not a token)
// who just re-entered their password, for changes to their second factor.
func (a *API) sessionWithPassword(w http.ResponseWriter, r *http.Request, p *Principal, password string) bool {
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "API tokens can't change sign-in settings")
		return false
	}
	if !auth.VerifyPassword(p.User.PasswordHash, password) {
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return false
	}
	return true
}

// newRecoveryCodes replaces the caller's recovery codes.
func (a *API) newRecoveryCodes(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Password string }
	if !readJSON(w, r, &req) || !a.sessionWithPassword(w, r, p, req.Password) {
		return
	}
	codes, hashes := auth.NewRecoveryCodes(10)
	if _, ok := a.apply(w, store.NewCommand(store.OpRecoveryReset, p.Actor(), store.RecoveryReset{ID: p.User.ID, Hashes: hashes})); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// replaceTOTPBegin starts moving the caller to a new authenticator. The
// old one keeps working until the new one is confirmed.
func (a *API) replaceTOTPBegin(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct{ Password string }
	if !readJSON(w, r, &req) || !a.sessionWithPassword(w, r, p, req.Password) {
		return
	}
	a.totpBegin(w, r, p)
}

func (a *API) replaceTOTPConfirm(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Session == nil {
		writeErr(w, http.StatusForbidden, "API tokens can't change sign-in settings")
		return
	}
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	u := p.User
	if u.TOTPPending == "" {
		writeErr(w, http.StatusBadRequest, "start again: no new authenticator is being set up")
		return
	}
	step, ok := auth.VerifyTOTP(u.TOTPPending, req.Code, a.now())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "that code doesn't match; check the app's clock and try the next code")
		return
	}
	codes, hashes := auth.NewRecoveryCodes(10)
	if _, ok := a.apply(w, store.NewCommand(store.OpTOTPConfirm, p.Actor(), store.TOTPConfirm{ID: u.ID, Step: step, RecoveryHashes: hashes})); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (a *API) updateLists(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.UpdateLists == nil {
		writeErr(w, http.StatusServiceUnavailable, "list updates aren't available on this node")
		return
	}
	a.UpdateLists()
	w.WriteHeader(http.StatusAccepted)
}
