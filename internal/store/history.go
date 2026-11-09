package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MaxVersions is how many versions of the settings are kept.
const MaxVersions = 50

// ConfigSnapshot is the restorable configuration: settings, devices and
// groups. Accounts aren't part of it, so restoring an old version can
// never bring back a deleted user or an old password.
type ConfigSnapshot struct {
	Settings Settings           `json:"settings"`
	Devices  map[string]*Device `json:"devices"`
	Groups   map[string]*Group  `json:"groups"`
}

// ConfigVersion is the configuration as it was after one change.
type ConfigVersion struct {
	ID      uint64         `json:"id"`
	Time    time.Time      `json:"time"`
	Actor   string         `json:"actor"`
	Summary string         `json:"summary"`
	Config  ConfigSnapshot `json:"config"`
}

// Ops that create versions or restore them.
const (
	OpConfigRestore = "config.restore" // VersionID
)

// VersionID names a version.
type VersionID struct {
	ID uint64 `json:"id"`
}

// configOps are the commands that can change the configuration.
var configOps = map[string]bool{
	OpSettingsUpdate: true, OpSettingsReset: true, OpDeviceSave: true, OpDeviceDelete: true,
	OpGroupSave: true, OpGroupDelete: true, OpConfigRestore: true, OpBackupRestore: true,
}

// ConfigSnapshot returns a deep copy of the current configuration.
func (st *State) ConfigSnapshot() ConfigSnapshot {
	cp := ConfigSnapshot{Settings: st.Settings, Devices: st.Devices, Groups: st.Groups}
	b, err := json.Marshal(cp)
	if err != nil {
		panic(err)
	}
	var out ConfigSnapshot
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	if out.Devices == nil {
		out.Devices = map[string]*Device{}
	}
	if out.Groups == nil {
		out.Groups = map[string]*Group{}
	}
	return out
}

func sameConfig(a, b ConfigSnapshot) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// recordVersion adds a version when c changed the configuration. The
// first one also keeps the configuration from before it, so the very
// first change can be undone too. It is deterministic, like apply.
func recordVersion(prev, next *State, c Command, summary string) {
	if !configOps[c.Op] {
		return
	}
	before, after := prev.ConfigSnapshot(), next.ConfigSnapshot()
	if sameConfig(before, after) {
		return
	}
	if len(next.ConfigVersions) == 0 {
		next.ConfigSeq++
		next.ConfigVersions = append(next.ConfigVersions, ConfigVersion{ID: next.ConfigSeq, Time: c.Time, Actor: "system", Summary: "before the first recorded change", Config: before})
	}
	if summary == "" {
		summary = c.Op
	}
	next.ConfigSeq++
	next.ConfigVersions = append(next.ConfigVersions, ConfigVersion{ID: next.ConfigSeq, Time: c.Time, Actor: c.Actor, Summary: summary, Config: after})
	if over := len(next.ConfigVersions) - MaxVersions; over > 0 {
		next.ConfigVersions = append([]ConfigVersion(nil), next.ConfigVersions[over:]...)
	}
}

// Version finds a version by ID.
func (st *State) VersionByID(id uint64) *ConfigVersion {
	for i := range st.ConfigVersions {
		if st.ConfigVersions[i].ID == id {
			return &st.ConfigVersions[i]
		}
	}
	return nil
}

func applyConfigRestore(st *State, c Command, dec func(any) error) (any, *AuditEntry, error) {
	var d VersionID
	if err := dec(&d); err != nil {
		return nil, nil, err
	}
	v := st.VersionByID(d.ID)
	if v == nil {
		return nil, nil, ErrNotFound
	}
	snap := v.Config
	b, _ := json.Marshal(snap)
	var cp ConfigSnapshot
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, nil, err
	}
	if cp.Devices == nil {
		cp.Devices = map[string]*Device{}
	}
	if cp.Groups == nil {
		cp.Groups = map[string]*Group{}
	}
	for _, dev := range cp.Devices {
		if dev.Group != "" && cp.Groups[dev.Group] == nil {
			return nil, nil, errors.New("that version is inconsistent (a device's group is missing)")
		}
	}
	st.Settings, st.Devices, st.Groups = cp.Settings, cp.Devices, cp.Groups
	return nil, audit(fmt.Sprintf("restored settings, devices and groups from version %d (%s)", v.ID, v.Time.UTC().Format("2006-01-02 15:04 MST")), nil, nil), nil
}
