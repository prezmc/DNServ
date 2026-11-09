package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Roles.
const (
	RoleAdmin  = "admin"
	RolePower  = "power"
	RoleViewer = "viewer"
)

// Permissions. Admins have all of them. Power users have the ones an
// admin ticks for them, from PowerPerms. Viewers have PermDashboard only,
// plus PermQueryLog if an admin allows it.
const (
	PermDashboard  = "dashboard.view"     // dashboards and analytics
	PermQueryLog   = "querylog.view"      // raw per-device query logs
	PermExport     = "data.export"        // export logs and stats
	PermAllowBlock = "domains.allowblock" // one-click block/allow of a domain
	PermRules      = "rules.edit"         // edit custom rules
	PermLists      = "lists.manage"       // blocklists, allowlists, block mode, bypass
	PermDevices    = "devices.manage"     // devices and groups (step 1d)
	PermUpstream   = "upstream.manage"    // resolution mode, servers, tunnel
	PermNetwork    = "network.manage"     // allowed client networks
	PermUsers      = "users.manage"       // admin only
	PermCluster    = "cluster.manage"     // admin only (step 2)
	PermBackups    = "backups.manage"     // admin only (step 2)
	PermAudit      = "audit.view"         // admin only
)

// AllPerms lists every permission.
var AllPerms = []string{PermDashboard, PermQueryLog, PermExport, PermAllowBlock, PermRules, PermLists, PermDevices, PermUpstream, PermNetwork, PermUsers, PermCluster, PermBackups, PermAudit}

// PowerPerms are the permissions an admin may grant a power user.
var PowerPerms = []string{PermDashboard, PermQueryLog, PermExport, PermAllowBlock, PermRules, PermLists, PermDevices, PermUpstream, PermNetwork}

// ViewerPerms are the permissions a viewer may have.
var ViewerPerms = []string{PermDashboard, PermQueryLog}

// Has reports whether u holds perm.
func (u *User) Has(perm string) bool {
	if u == nil || u.Disabled {
		return false
	}
	if u.Role == RoleAdmin {
		return true
	}
	if perm == PermDashboard {
		return true
	}
	return slices.Contains(u.Perms, perm)
}

// Command is one change to the state.
type Command struct {
	Op    string          `json:"op"`
	Actor string          `json:"actor"`
	Time  time.Time       `json:"time"`
	Data  json.RawMessage `json:"data"`
}

// NewCommand builds a command with JSON data.
func NewCommand(op, actor string, data any) Command {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return Command{Op: op, Actor: actor, Data: b}
}

// Command ops and their data.
const (
	OpUserCreate     = "user.create"        // UserCreate
	OpUserUpdate     = "user.update"        // UserUpdate
	OpUserDelete     = "user.delete"        // IDOnly
	OpUserPassword   = "user.password"      // UserPassword
	OpTOTPBegin      = "user.totp_begin"    // TOTPBegin
	OpTOTPConfirm    = "user.totp_confirm"  // TOTPConfirm
	OpTOTPUsed       = "user.totp_used"     // TOTPUsed
	OpRecoveryUsed   = "user.recovery_used" // RecoveryUsed
	OpMFAReset       = "user.mfa_reset"     // IDOnly
	OpTokenCreate    = "token.create"       // Token
	OpTokenRevoke    = "token.revoke"       // IDOnly
	OpSettingsUpdate = "settings.update"    // Settings
	OpSettingsReset  = "settings.reset"     // SettingsReset
	OpDeviceSave     = "device.save"        // Device (creates or replaces)
	OpDeviceDelete   = "device.delete"      // IDOnly
)

type UserCreate struct {
	ID, Username, Role string
	Perms              []string
	PasswordHash       string
}
type UserUpdate struct {
	ID       string
	Role     *string
	Perms    *[]string
	Disabled *bool
}
type UserPassword struct{ ID, PasswordHash string }
type IDOnly struct{ ID string }
type TOTPBegin struct{ ID, Secret string }
type TOTPConfirm struct {
	ID             string
	Step           int64
	RecoveryHashes []string
}
type TOTPUsed struct {
	ID   string
	Step int64
}
type RecoveryUsed struct{ ID, Hash string }

// SettingsReset clears the named fields so the file/env/default applies.
type SettingsReset struct{ Fields []string }

var (
	ErrNotFound  = errors.New("not found")
	ErrLastAdmin = errors.New("there must be at least one enabled admin")
)

// apply mutates st (a private copy). It must be deterministic: the same
// command on the same state gives the same result on every node.
func apply(st *State, c Command) (any, *AuditEntry, error) {
	dec := func(v any) error {
		if err := json.Unmarshal(c.Data, v); err != nil {
			return fmt.Errorf("%s: bad data: %w", c.Op, err)
		}
		return nil
	}
	switch c.Op {
	case OpUserCreate:
		var d UserCreate
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if err := validUsername(d.Username); err != nil {
			return nil, nil, err
		}
		if st.UserByName(d.Username) != nil {
			return nil, nil, fmt.Errorf("username %q is taken", d.Username)
		}
		if _, ok := st.Users[d.ID]; ok || d.ID == "" {
			return nil, nil, errors.New("bad user id")
		}
		perms, err := validRole(d.Role, d.Perms)
		if err != nil {
			return nil, nil, err
		}
		if d.PasswordHash == "" {
			return nil, nil, errors.New("password required")
		}
		st.Users[d.ID] = &User{
			ID: d.ID, Username: d.Username, Role: d.Role, Perms: perms,
			PasswordHash: d.PasswordHash, PasswordChangedAt: c.Time, CreatedAt: c.Time, CreatedBy: c.Actor,
		}
		return d.ID, audit(fmt.Sprintf("created %s %q", d.Role, d.Username), nil, publicUser(st.Users[d.ID])), nil

	case OpUserUpdate:
		var d UserUpdate
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		before := publicUser(u)
		wasAdmin := u.Role == RoleAdmin && !u.Disabled
		role, perms := u.Role, u.Perms
		if d.Role != nil {
			role = *d.Role
		}
		if d.Perms != nil {
			perms = *d.Perms
		}
		perms, err := validRole(role, perms)
		if err != nil {
			return nil, nil, err
		}
		u.Role, u.Perms = role, perms
		if d.Disabled != nil {
			u.Disabled = *d.Disabled
		}
		if wasAdmin && !(u.Role == RoleAdmin && !u.Disabled) && st.Admins() == 0 {
			return nil, nil, ErrLastAdmin
		}
		return nil, audit(fmt.Sprintf("updated user %q", u.Username), before, publicUser(u)), nil

	case OpUserDelete:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		delete(st.Users, d.ID)
		if st.Admins() == 0 {
			return nil, nil, ErrLastAdmin
		}
		for id, t := range st.Tokens {
			if t.UserID == d.ID {
				delete(st.Tokens, id)
			}
		}
		return nil, audit(fmt.Sprintf("deleted user %q", u.Username), publicUser(u), nil), nil

	case OpUserPassword:
		var d UserPassword
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		u.PasswordHash, u.PasswordChangedAt = d.PasswordHash, c.Time
		return nil, audit(fmt.Sprintf("changed password for %q", u.Username), nil, nil), nil

	case OpTOTPBegin:
		var d TOTPBegin
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		u.TOTPPending = d.Secret
		return nil, nil, nil // not audited: nothing is enabled yet

	case OpTOTPConfirm:
		var d TOTPConfirm
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		if u.TOTPPending == "" {
			return nil, nil, errors.New("no authenticator enrollment in progress")
		}
		u.TOTPSecret, u.TOTPPending, u.TOTPLastStep = u.TOTPPending, "", d.Step
		u.RecoveryHashes = d.RecoveryHashes
		if u.Role == RoleAdmin {
			st.SetupDone = true
		}
		return nil, audit(fmt.Sprintf("enrolled authenticator app for %q", u.Username), nil, nil), nil

	case OpTOTPUsed:
		var d TOTPUsed
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		if d.Step <= u.TOTPLastStep {
			return nil, nil, errors.New("code already used")
		}
		u.TOTPLastStep = d.Step
		return nil, nil, nil

	case OpRecoveryUsed:
		var d RecoveryUsed
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		i := slices.Index(u.RecoveryHashes, d.Hash)
		if i < 0 {
			return nil, nil, errors.New("recovery code not valid")
		}
		u.RecoveryHashes = slices.Delete(u.RecoveryHashes, i, i+1)
		return nil, audit(fmt.Sprintf("%q signed in with a recovery code (%d left)", u.Username, len(u.RecoveryHashes)), nil, nil), nil

	case OpMFAReset:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		u.TOTPSecret, u.TOTPPending, u.RecoveryHashes, u.MFAResetAt = "", "", nil, c.Time
		return nil, audit(fmt.Sprintf("reset MFA for %q; they must enroll again at next sign-in", u.Username), nil, nil), nil

	case OpTokenCreate:
		var d Token
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if _, ok := st.Users[d.UserID]; !ok {
			return nil, nil, ErrNotFound
		}
		if d.ID == "" || d.Hash == "" || strings.TrimSpace(d.Name) == "" {
			return nil, nil, errors.New("token needs an id, name and secret")
		}
		d.CreatedAt = c.Time
		st.Tokens[d.ID] = &d
		pub := d
		pub.Hash = ""
		return d.ID, audit(fmt.Sprintf("created API token %q", d.Name), nil, pub), nil

	case OpTokenRevoke:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		t, ok := st.Tokens[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		delete(st.Tokens, d.ID)
		return nil, audit(fmt.Sprintf("revoked API token %q", t.Name), nil, nil), nil

	case OpSettingsUpdate:
		var d Settings
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		before := st.Settings
		st.Settings.Merge(d)
		return nil, audit("changed settings: "+strings.Join(changedFields(d), ", "), before, st.Settings), nil

	case OpDeviceSave:
		var d Device
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		d.Name = strings.TrimSpace(d.Name)
		if d.ID == "" || d.Name == "" || utf8.RuneCountInString(d.Name) > 64 {
			return nil, nil, errors.New("a device needs a name of 1 to 64 characters")
		}
		if len(d.Addrs) == 0 {
			return nil, nil, errors.New("a device needs at least one IP address")
		}
		for i, a := range d.Addrs {
			ip, err := netip.ParseAddr(strings.TrimSpace(a))
			if err != nil {
				return nil, nil, fmt.Errorf("%q is not an IP address", a)
			}
			d.Addrs[i] = ip.Unmap().String()
			if other := st.DeviceByAddr(d.Addrs[i]); other != nil && other.ID != d.ID {
				return nil, nil, fmt.Errorf("%s already belongs to %q", d.Addrs[i], other.Name)
			}
		}
		old, existed := st.Devices[d.ID]
		if existed {
			d.CreatedAt = old.CreatedAt
		} else {
			d.CreatedAt = c.Time
		}
		st.Devices[d.ID] = &d
		var before any
		verb := "added"
		if existed {
			before, verb = old, "updated"
		}
		return d.ID, audit(fmt.Sprintf("%s device %q", verb, d.Name), before, d), nil

	case OpDeviceDelete:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		old, ok := st.Devices[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		delete(st.Devices, d.ID)
		return nil, audit(fmt.Sprintf("removed device %q", old.Name), old, nil), nil

	case OpSettingsReset:
		var d SettingsReset
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		before := st.Settings
		for _, f := range d.Fields {
			if err := clearField(&st.Settings, f); err != nil {
				return nil, nil, err
			}
		}
		return nil, audit("reset settings to defaults: "+strings.Join(d.Fields, ", "), before, st.Settings), nil
	}
	return nil, nil, fmt.Errorf("unknown command %q", c.Op)
}

func audit(summary string, before, after any) *AuditEntry {
	e := &AuditEntry{Summary: summary}
	if before != nil {
		e.Before, _ = json.Marshal(before)
	}
	if after != nil {
		e.After, _ = json.Marshal(after)
	}
	return e
}

// PublicUser is a user without secrets, for the API and the audit log.
type PublicUser struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Perms       []string  `json:"perms"`
	Disabled    bool      `json:"disabled"`
	MFAEnrolled bool      `json:"mfa_enrolled"`
	Recovery    int       `json:"recovery_codes_left"`
	CreatedAt   time.Time `json:"created_at"`
}

func publicUser(u *User) PublicUser {
	p := PublicUser{ID: u.ID, Username: u.Username, Role: u.Role, Perms: u.Perms, Disabled: u.Disabled,
		MFAEnrolled: u.MFAEnrolled(), Recovery: len(u.RecoveryHashes), CreatedAt: u.CreatedAt}
	if p.Role == RoleAdmin {
		p.Perms = AllPerms
	}
	if p.Perms == nil {
		p.Perms = []string{}
	}
	return p
}

// Public returns the user without secrets.
func (u *User) Public() PublicUser { return publicUser(u) }

func validUsername(n string) error {
	if l := utf8.RuneCountInString(n); l < 2 || l > 64 {
		return errors.New("username must be 2-64 characters")
	}
	for _, r := range n {
		if r <= ' ' || r == '\u007f' {
			return errors.New("username may not contain spaces or control characters")
		}
	}
	return nil
}

func validRole(role string, perms []string) ([]string, error) {
	var allowed []string
	switch role {
	case RoleAdmin:
		return nil, nil
	case RolePower:
		allowed = PowerPerms
	case RoleViewer:
		allowed = ViewerPerms
	default:
		return nil, fmt.Errorf("unknown role %q (admin, power or viewer)", role)
	}
	out := []string{}
	for _, p := range perms {
		if !slices.Contains(allowed, p) {
			return nil, fmt.Errorf("permission %q can't be given to a %s user", p, role)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

func changedFields(p Settings) []string {
	b, _ := json.Marshal(p)
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func clearField(s *Settings, f string) error {
	switch f {
	case "upstream_mode":
		s.UpstreamMode = nil
	case "upstream_servers":
		s.UpstreamServers = nil
	case "tunnel_interface":
		s.TunnelInterface = nil
	case "tunnel_expected_egress":
		s.TunnelExpectedEgress = nil
	case "tunnel_on_down":
		s.TunnelOnDown = nil
	case "allowed_nets":
		s.AllowedNets = nil
	case "local_dns":
		s.LocalDNS = nil
	case "filtering_enabled":
		s.FilteringEnabled = nil
	case "block_mode":
		s.BlockMode = nil
	case "block_bypass":
		s.BlockBypass = nil
	case "lists":
		s.Lists = nil
	case "allowlists":
		s.Allowlists = nil
	case "rules":
		s.Rules = nil
	default:
		return fmt.Errorf("unknown setting %q", f)
	}
	return nil
}

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
