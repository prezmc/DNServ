// Package store holds the node's managed state: users, API tokens,
// settings changed in the UI, and the audit log.
//
// Every change is a Command applied by a deterministic function, the same
// shape a Raft state machine needs. Step 2 puts Raft in front of Apply so
// commands are replicated to every node; today they are applied locally
// and the state is saved to disk after each change.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxAudit is how many audit entries are kept.
const MaxAudit = 10_000

// State is the whole managed state. It is replaced, never mutated in
// place, so readers can hold a snapshot without locks.
type State struct {
	Version  uint64             `json:"version"`
	Users    map[string]*User   `json:"users"`
	Tokens   map[string]*Token  `json:"tokens"`
	Settings Settings           `json:"settings"`
	Devices  map[string]*Device `json:"devices"`
	Groups   map[string]*Group  `json:"groups"`
	Audit    []AuditEntry       `json:"audit"`
	// SetupDone is set when the first admin finishes MFA enrollment.
	SetupDone bool `json:"setup_done"`
}

// Device is a named client on the network, recognized by its addresses.
// Groups and policies attach to devices.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Addrs     []string  `json:"addrs"`
	Group     string    `json:"group,omitempty"` // group id; empty = household defaults
	CreatedAt time.Time `json:"created_at"`
}

// Group gives a set of devices their own filtering policy.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// SkipBlocklists lets the group's devices bypass the shared blocklists
	// (custom rules and the group's own rules still apply).
	SkipBlocklists bool `json:"skip_blocklists"`
	// Rules are extra rules for this group, in the custom rule syntax.
	Rules     []string   `json:"rules"`
	Schedules []Schedule `json:"schedules"`
	CreatedAt time.Time  `json:"created_at"`
}

// Schedule tightens a group's filtering at set times, in the node's time
// zone (TZ). A window whose end is before its start runs past midnight;
// Days are the days it starts on (0 = Sunday).
type Schedule struct {
	Name  string `json:"name"`
	Days  []int  `json:"days"`
	Start string `json:"start"` // "HH:MM"
	End   string `json:"end"`
	// BlockAll pauses the internet for the group (allow rules still
	// work); otherwise Rules are blocked during the window.
	BlockAll bool     `json:"block_all"`
	Rules    []string `json:"rules"`
}

// DeviceByAddr returns the device that owns addr, if any.
func (st *State) DeviceByAddr(addr string) *Device {
	for _, d := range st.Devices {
		for _, a := range d.Addrs {
			if a == addr {
				return d
			}
		}
	}
	return nil
}

// User is a dashboard account.
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Role     string   `json:"role"` // admin, power, viewer
	Perms    []string `json:"perms,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`

	PasswordHash      string    `json:"password_hash"`
	PasswordChangedAt time.Time `json:"password_changed_at"`

	// TOTP. The secret is pending until confirmed with a valid code.
	TOTPSecret     string    `json:"totp_secret,omitempty"`
	TOTPPending    string    `json:"totp_pending,omitempty"`
	TOTPLastStep   int64     `json:"totp_last_step,omitempty"`
	RecoveryHashes []string  `json:"recovery_hashes,omitempty"`
	MFAResetAt     time.Time `json:"mfa_reset_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by,omitempty"`
}

// MFAEnrolled reports whether the user has a confirmed second factor.
func (u *User) MFAEnrolled() bool { return u.TOTPSecret != "" }

// Token is an API token. Only a hash of the secret is stored.
type Token struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	UserID    string    `json:"user_id"`
	Perms     []string  `json:"perms"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// AuditEntry records one change.
type AuditEntry struct {
	Time    time.Time       `json:"time"`
	Actor   string          `json:"actor"` // username, "token:<name>" or "system"
	Op      string          `json:"op"`
	Summary string          `json:"summary"`
	Before  json.RawMessage `json:"before,omitempty"`
	After   json.RawMessage `json:"after,omitempty"`
}

// Store applies commands and persists state.
type Store struct {
	path string
	mu   sync.Mutex // serializes Apply
	cur  *State
	subs []func(old, new *State)
	now  func() time.Time
}

// Open loads state from dir/state.json, or starts empty.
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "state.json"), now: time.Now}
	st := &State{Users: map[string]*User{}, Tokens: map[string]*Token{}, Devices: map[string]*Device{}, Groups: map[string]*Group{}}
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, st); err != nil {
			return nil, fmt.Errorf("read %s: %w", s.path, err)
		}
		if st.Users == nil {
			st.Users = map[string]*User{}
		}
		if st.Tokens == nil {
			st.Tokens = map[string]*Token{}
		}
		if st.Groups == nil {
			st.Groups = map[string]*Group{}
		}
		if st.Devices == nil {
			st.Devices = map[string]*Device{}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	s.cur = st
	return s, nil
}

// State returns the current snapshot. Callers must not modify it.
func (s *Store) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Subscribe registers fn to run after each applied change, outside the
// store lock.
func (s *Store) Subscribe(fn func(old, new *State)) {
	s.mu.Lock()
	s.subs = append(s.subs, fn)
	s.mu.Unlock()
}

// Apply validates and applies a command, saves the new state and notifies
// subscribers. It returns the command's result (for example a new ID).
func (s *Store) Apply(c Command) (any, error) {
	s.mu.Lock()
	if c.Time.IsZero() {
		c.Time = s.now().UTC()
	}
	next := s.cur.clone()
	res, entry, err := apply(next, c)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	next.Version++
	if entry != nil {
		entry.Time, entry.Actor, entry.Op = c.Time, c.Actor, c.Op
		next.Audit = append(next.Audit, *entry)
		if over := len(next.Audit) - MaxAudit; over > 0 {
			next.Audit = append([]AuditEntry(nil), next.Audit[over:]...)
		}
	}
	if err := s.save(next); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	old := s.cur
	s.cur = next
	subs := append([]func(old, new *State){}, s.subs...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(old, next)
	}
	return res, nil
}

func (s *Store) save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// clone deep-copies the state through JSON. State is small (users,
// tokens, settings, a bounded audit log), and a deep copy keeps every
// published snapshot immutable.
func (st *State) clone() *State {
	b, err := json.Marshal(st)
	if err != nil {
		panic(err)
	}
	out := &State{}
	if err := json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	if out.Users == nil {
		out.Users = map[string]*User{}
	}
	if out.Tokens == nil {
		out.Tokens = map[string]*Token{}
	}
	if out.Devices == nil {
		out.Devices = map[string]*Device{}
	}
	if out.Groups == nil {
		out.Groups = map[string]*Group{}
	}
	return out
}

// UserByName finds a user by username (case-insensitive).
func (st *State) UserByName(name string) *User {
	for _, u := range st.Users {
		if equalFold(u.Username, name) {
			return u
		}
	}
	return nil
}

// Admins counts enabled admins.
func (st *State) Admins() int {
	n := 0
	for _, u := range st.Users {
		if u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}
