package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session stages.
const (
	// StageMFA: password accepted, waiting for a second-factor code.
	StageMFA = "mfa"
	// StageEnroll: password accepted, the user has no second factor yet
	// and may only enroll one.
	StageEnroll = "enroll"
	// StageFull: fully signed in.
	StageFull = "full"
)

// Lifetimes.
const (
	PendingTTL  = 10 * time.Minute   // to finish MFA or enrollment
	IdleTTL     = 12 * time.Hour     // signed out after this long unused
	AbsoluteTTL = 7 * 24 * time.Hour // signed out after this long regardless
)

// Session is a browser login. Only the hash of its token is kept.
type Session struct {
	ID        string    `json:"id"` // public id, for listing and revoking
	Hash      string    `json:"hash"`
	UserID    string    `json:"user_id"`
	Stage     string    `json:"stage"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CSRF      string    `json:"csrf"`
}

// Sessions are local to the node for now; step 2 replicates them so a
// login works on any node.
type Sessions struct {
	path  string
	mu    sync.Mutex
	byID  map[string]*Session // keyed by token hash
	now   func() time.Time
	dirty bool
}

// OpenSessions loads saved sessions from dir/sessions.json.
func OpenSessions(dir string) (*Sessions, error) {
	s := &Sessions{path: filepath.Join(dir, "sessions.json"), byID: map[string]*Session{}, now: time.Now}
	b, err := os.ReadFile(s.path)
	if err == nil {
		var list []*Session
		if json.Unmarshal(b, &list) == nil {
			for _, x := range list {
				s.byID[x.Hash] = x
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Create starts a session and returns its secret token.
func (s *Sessions) Create(userID, stage, ip, ua string) (string, *Session) {
	token := RandomID(32)
	now := s.now()
	x := &Session{ID: RandomID(9), Hash: HashToken(token), UserID: userID, Stage: stage,
		Created: now, LastSeen: now, IP: ip, UserAgent: truncate(ua, 200), CSRF: RandomID(18)}
	s.mu.Lock()
	s.byID[x.Hash] = x
	s.dirty = true
	cp := *x
	s.mu.Unlock()
	s.Save()
	return token, &cp
}

// Get returns a live session for token, refreshing its idle timer.
func (s *Sessions) Get(token string) *Session {
	if token == "" {
		return nil
	}
	h := HashToken(token)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[h]
	if !ok {
		return nil
	}
	ttl := IdleTTL
	if x.Stage != StageFull {
		ttl = PendingTTL
	}
	if now.Sub(x.LastSeen) > ttl || now.Sub(x.Created) > AbsoluteTTL {
		delete(s.byID, h)
		s.dirty = true
		return nil
	}
	if now.Sub(x.LastSeen) > time.Minute {
		x.LastSeen = now
		s.dirty = true
	}
	cp := *x
	return &cp
}

// Promote moves a session to a new stage and rotates its token, so a
// token seen before MFA can't be used after it.
func (s *Sessions) Promote(old string, stage string) (string, *Session, bool) {
	h := HashToken(old)
	s.mu.Lock()
	x, ok := s.byID[h]
	if !ok {
		s.mu.Unlock()
		return "", nil, false
	}
	delete(s.byID, h)
	token := RandomID(32)
	x.Hash, x.Stage, x.LastSeen, x.CSRF = HashToken(token), stage, s.now(), RandomID(18)
	if stage == StageFull {
		x.Created = s.now()
	}
	s.byID[x.Hash] = x
	s.dirty = true
	cp := *x
	s.mu.Unlock()
	s.Save()
	return token, &cp, true
}

// Delete ends the session with this token.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	delete(s.byID, HashToken(token))
	s.dirty = true
	s.mu.Unlock()
	s.Save()
}

// Revoke ends a session by public id, if it belongs to userID (or any
// user when userID is empty).
func (s *Sessions) Revoke(id, userID string) bool {
	s.mu.Lock()
	found := false
	for h, x := range s.byID {
		if x.ID == id && (userID == "" || x.UserID == userID) {
			delete(s.byID, h)
			found = true
		}
	}
	s.dirty = s.dirty || found
	s.mu.Unlock()
	s.Save()
	return found
}

// RevokeUser ends every session of a user, except keepID.
func (s *Sessions) RevokeUser(userID, keepID string) int {
	s.mu.Lock()
	n := 0
	for h, x := range s.byID {
		if x.UserID == userID && x.ID != keepID {
			delete(s.byID, h)
			n++
		}
	}
	s.dirty = s.dirty || n > 0
	s.mu.Unlock()
	s.Save()
	return n
}

// List returns a user's sessions (all users when userID is empty).
func (s *Sessions) List(userID string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, x := range s.byID {
		if userID == "" || x.UserID == userID {
			cp := *x
			cp.Hash, cp.CSRF = "", ""
			out = append(out, cp)
		}
	}
	return out
}

// Save writes sessions to disk if they changed.
func (s *Sessions) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	list := make([]*Session, 0, len(s.byID))
	for _, x := range s.byID {
		list = append(list, x)
	}
	b, err := json.Marshal(list)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --- throttling ---

// Throttle slows down repeated failed logins per key (username and client
// IP are both used as keys): after 5 failures in 15 minutes each further
// attempt is refused for an exponentially growing delay, capped at 15
// minutes.
type Throttle struct {
	mu  sync.Mutex
	m   map[string]*attempts
	now func() time.Time
}

type attempts struct {
	fails   int
	first   time.Time
	blocked time.Time
}

// NewThrottle creates a throttle.
func NewThrottle() *Throttle { return &Throttle{m: map[string]*attempts{}, now: time.Now} }

// Allowed reports whether key may try now, and if not, for how long.
func (t *Throttle) Allowed(key string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.m[key]
	if !ok {
		return true, 0
	}
	if wait := a.blocked.Sub(t.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail records a failure.
func (t *Throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	a, ok := t.m[key]
	if !ok || now.Sub(a.first) > 15*time.Minute {
		a = &attempts{first: now}
		t.m[key] = a
	}
	a.fails++
	if a.fails >= 5 {
		d := time.Second << min(a.fails-5, 10)
		a.blocked = now.Add(min(d, 15*time.Minute))
	}
	if len(t.m) > 10_000 { // bound memory under a spray attack
		for k, v := range t.m {
			if now.Sub(v.first) > 15*time.Minute {
				delete(t.m, k)
			}
		}
	}
}

// Succeed clears a key.
func (t *Throttle) Succeed(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}
