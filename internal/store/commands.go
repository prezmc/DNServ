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
	PermPause      = "filtering.pause"    // pause filtering for a while (implied by lists.manage)
	PermDevices    = "devices.manage"     // devices and groups (step 1d)
	PermUpstream   = "upstream.manage"    // resolution mode, servers, tunnel
	PermNetwork    = "network.manage"     // allowed client networks
	PermUsers      = "users.manage"       // admin only
	PermCluster    = "cluster.manage"     // admin only (step 2)
	PermBackups    = "backups.manage"     // admin only (step 2)
	PermAudit      = "audit.view"         // admin only
)

// AllPerms lists every permission.
var AllPerms = []string{PermDashboard, PermQueryLog, PermExport, PermAllowBlock, PermRules, PermLists, PermPause, PermDevices, PermUpstream, PermNetwork, PermUsers, PermCluster, PermBackups, PermAudit}

// PowerPerms are the permissions an admin may grant a power user.
var PowerPerms = []string{PermDashboard, PermQueryLog, PermExport, PermAllowBlock, PermRules, PermLists, PermPause, PermDevices, PermUpstream, PermNetwork}

// ViewerPerms are the permissions a viewer may have.
var ViewerPerms = []string{PermDashboard, PermQueryLog, PermPause}

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
	return HasPerm(u.Perms, perm)
}

// HasPerm reports whether a list of granted permissions covers perm.
// Whoever manages the blocklists can also pause filtering.
func HasPerm(perms []string, perm string) bool {
	if slices.Contains(perms, perm) {
		return true
	}
	return perm == PermPause && slices.Contains(perms, PermLists)
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
	OpUserCreate     = "user.create"         // UserCreate
	OpUserUpdate     = "user.update"         // UserUpdate
	OpUserDelete     = "user.delete"         // IDOnly
	OpUserPassword   = "user.password"       // UserPassword
	OpTOTPBegin      = "user.totp_begin"     // TOTPBegin
	OpTOTPConfirm    = "user.totp_confirm"   // TOTPConfirm
	OpTOTPUsed       = "user.totp_used"      // TOTPUsed
	OpRecoveryUsed   = "user.recovery_used"  // RecoveryUsed
	OpRecoveryReset  = "user.recovery_reset" // RecoveryReset
	OpMFAReset       = "user.mfa_reset"      // IDOnly
	OpUserDashboard  = "user.dashboard"      // UserDashboard
	OpTokenCreate    = "token.create"        // Token
	OpTokenRevoke    = "token.revoke"        // IDOnly
	OpSettingsUpdate = "settings.update"     // Settings
	OpSettingsReset  = "settings.reset"      // SettingsReset
	OpDeviceSave     = "device.save"         // Device (creates or replaces)
	OpDeviceDelete   = "device.delete"       // IDOnly
	OpGroupSave      = "group.save"          // Group (creates or replaces)
	OpGroupDelete    = "group.delete"        // IDOnly
	OpVirusTotalKey  = "virustotal.key"      // VirusTotalKey
	OpAbuseCHKey     = "abusech.key"         // AbuseCHKey
	OpFilterPause    = "filtering.pause"     // FilterPause
	OpFilterResume   = "filtering.resume"    // FilterResume
	OpHistoryClear   = "history.clear"       // HistoryClear (audit record only)
	OpRiskDismiss    = "risk.dismiss"        // RiskDismiss
)

// VirusTotalKey sets (or, empty, removes) the VirusTotal API key. It is
// kept apart from Settings so it never shows in settings, their history
// or the audit log.
type VirusTotalKey struct {
	Key string `json:"key"`
}

// AbuseCHKey sets (or, empty, removes) the abuse.ch Auth-Key. Like the
// VirusTotal key, it is kept apart from Settings.
type AbuseCHKey struct {
	Key string `json:"key"`
}

// HistoryClear records that query history was deleted on some servers.
// The deleting itself happens on each node, outside the replicated state;
// this only puts it in the audit log.
type HistoryClear struct {
	What    string   `json:"what"` // a key of HistoryClearWhat
	Servers []string `json:"servers"`
}

// HistoryClearWhat names what can be cleared, for the audit log.
var HistoryClearWhat = map[string]string{
	"performance": "performance stats",
	"history":     "all query history and stats",
}

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
type UserDashboard struct {
	ID     string
	Layout []string
}
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
type RecoveryReset struct {
	ID     string
	Hashes []string
}

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

	case OpUserDashboard:
		var d UserDashboard
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		if err := validLayout(d.Layout); err != nil {
			return nil, nil, err
		}
		u.Dashboard = d.Layout
		return nil, nil, nil // a personal preference, not audited

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
		verb := "enrolled"
		if u.TOTPSecret != "" {
			verb = "replaced"
		}
		u.TOTPSecret, u.TOTPPending, u.TOTPLastStep = u.TOTPPending, "", d.Step
		u.RecoveryHashes = d.RecoveryHashes
		if u.Role == RoleAdmin {
			st.SetupDone = true
		}
		return nil, audit(fmt.Sprintf("%s authenticator app for %q", verb, u.Username), nil, nil), nil

	case OpRecoveryReset:
		var d RecoveryReset
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		u, ok := st.Users[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		u.RecoveryHashes = d.Hashes
		return nil, audit(fmt.Sprintf("made new recovery codes for %q", u.Username), nil, nil), nil

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
		if d.Group != "" && st.Groups[d.Group] == nil {
			return nil, nil, errors.New("that group doesn't exist")
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

	case OpGroupSave:
		var g Group
		if err := dec(&g); err != nil {
			return nil, nil, err
		}
		if err := g.normalize(); err != nil {
			return nil, nil, err
		}
		if g.ID == "" {
			return nil, nil, errors.New("missing group id")
		}
		for _, o := range st.Groups {
			if o.ID != g.ID && strings.EqualFold(o.Name, g.Name) {
				return nil, nil, fmt.Errorf("there is already a group called %q", o.Name)
			}
		}
		old, existed := st.Groups[g.ID]
		if existed {
			g.CreatedAt = old.CreatedAt
		} else {
			g.CreatedAt = c.Time
		}
		st.Groups[g.ID] = &g
		var before any
		verb := "added"
		if existed {
			before, verb = old, "updated"
		}
		return g.ID, audit(fmt.Sprintf("%s group %q", verb, g.Name), before, g), nil

	case OpGroupDelete:
		var d IDOnly
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		old, ok := st.Groups[d.ID]
		if !ok {
			return nil, nil, ErrNotFound
		}
		delete(st.Groups, d.ID)
		for _, dev := range st.Devices {
			if dev.Group == d.ID {
				dev.Group = ""
			}
		}
		return nil, audit(fmt.Sprintf("removed group %q", old.Name), old, nil), nil

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
	if strings.HasPrefix(c.Op, opClusterPrefix) {
		return applyCluster(st, c, dec)
	}
	switch c.Op {
	case OpConfigRestore:
		return applyConfigRestore(st, c, dec)
	case OpBackupConfig, OpBackupRestore:
		return applyBackup(st, c, dec)
	case OpHTTPSConfig, OpHTTPSCert:
		return applyHTTPS(st, c, dec)

	case OpFilterPause:
		var d FilterPause
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		return applyPause(st, c, d)

	case OpFilterResume:
		var d FilterResume
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		return applyResume(st, c, d)

	case OpHistoryClear:
		var d HistoryClear
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		what, ok := HistoryClearWhat[d.What]
		if !ok {
			return nil, nil, fmt.Errorf("unknown history %q", d.What)
		}
		return nil, audit("cleared "+what+" on "+strings.Join(d.Servers, ", "), nil, d), nil

	case OpRiskDismiss:
		var d RiskDismiss
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		return applyDismiss(st, c, d)

	case OpVirusTotalKey:
		var d VirusTotalKey
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		st.VirusTotalKey = strings.TrimSpace(d.Key)
		if st.VirusTotalKey == "" {
			return nil, audit("removed the VirusTotal key", nil, nil), nil
		}
		return nil, audit("set the VirusTotal key", nil, nil), nil

	case OpAbuseCHKey:
		var d AbuseCHKey
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		st.AbuseCHKey = strings.TrimSpace(d.Key)
		if st.AbuseCHKey == "" {
			return nil, audit("removed the abuse.ch key", nil, nil), nil
		}
		return nil, audit("set the abuse.ch key", nil, nil), nil
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

// validLayout checks a dashboard layout: card names made of lowercase
// letters, digits and hyphens, each optionally hidden with a leading "-"
// or sized with a trailing ":s", ":m", ":l" or ":f".
func validLayout(l []string) error {
	if len(l) > 40 {
		return errors.New("too many dashboard cards")
	}
	for _, c := range l {
		name := strings.TrimPrefix(c, "-")
		if name == "" || len(name) > 32 {
			return fmt.Errorf("bad dashboard card %q", c)
		}
		for _, r := range name {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != ':' {
				return fmt.Errorf("bad dashboard card %q", c)
			}
		}
	}
	return nil
}

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
	case "risk_scoring":
		s.RiskScoring = nil
	case "upstream_mode":
		s.UpstreamMode = nil
	case "upstream_servers":
		s.UpstreamServers = nil
	case "upstream_strategy":
		s.UpstreamStrategy = nil
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
	case "time_zone":
		s.TimeZone = nil
	case "records":
		s.Records = nil
	case "filtering_enabled":
		s.FilteringEnabled = nil
	case "block_mode":
		s.BlockMode = nil
	case "block_bypass":
		s.BlockBypass = nil
	case "blocked_services":
		s.BlockedServices = nil
	case "safe_search":
		s.SafeSearch = nil
	case "lists":
		s.Lists = nil
	case "allowlists":
		s.Allowlists = nil
	case "rules":
		s.Rules = nil
	case "cache_size":
		s.CacheSize = nil
	case "history_days":
		s.HistoryDays = nil
	case "stats_days":
		s.StatsDays = nil
	case "threat_feeds":
		s.ThreatFeeds = nil
	case "trusted_domains":
		s.TrustedDomains = nil
	default:
		return fmt.Errorf("unknown setting %q", f)
	}
	return nil
}

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
