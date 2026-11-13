package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// BackupConfig is how this cluster makes backups. Only the public half of
// the backup key is kept: nodes can encrypt backups but not read them, and
// the passphrase that reads them is never stored.
type BackupConfig struct {
	// PublicKey (X25519, base64) and Salt (base64) come from the
	// passphrase. Empty means backups aren't set up.
	PublicKey string `json:"public_key,omitempty"`
	Salt      string `json:"salt,omitempty"`
	// Every is "daily", "weekly" or "" (only on demand). At is "HH:MM" in
	// the node's time zone; weekly backups run on Sundays.
	Every string `json:"every,omitempty"`
	At    string `json:"at,omitempty"`
	// Keep is how many scheduled backups each node keeps.
	Keep int `json:"keep,omitempty"`
	// Offsite is a folder (for example a mounted network share) where the
	// leader also writes each scheduled backup. Empty: none.
	Offsite string `json:"offsite,omitempty"`
}

// Configured reports whether a backup key is set.
func (b BackupConfig) Configured() bool { return b.PublicKey != "" && b.Salt != "" }

// BackupData is what a backup holds: the accounts, configuration and
// settings history. The cluster's own setup (nodes, certificates) isn't
// in it, so a backup restores into any cluster.
type BackupData struct {
	Users          map[string]*User   `json:"users"`
	Tokens         map[string]*Token  `json:"tokens"`
	Settings       Settings           `json:"settings"`
	Devices        map[string]*Device `json:"devices"`
	Groups         map[string]*Group  `json:"groups"`
	ConfigVersions []ConfigVersion    `json:"config_versions,omitempty"`
	ConfigSeq      uint64             `json:"config_seq,omitempty"`
	SetupDone      bool               `json:"setup_done"`
	// Backup is the backup schedule and key. A restore uses it only where
	// backups aren't set up yet, such as a new node set up from a backup.
	Backup *BackupConfig `json:"backup,omitempty"`
}

// BackupRestore replaces the state with a backup's.
type BackupRestore struct {
	Data    BackupData `json:"data"`
	Created time.Time  `json:"created"`
	From    string     `json:"from"` // node that made it
}

// Backup ops.
const (
	OpBackupConfig  = "backup.config"  // BackupConfig
	OpBackupRestore = "backup.restore" // BackupRestore
	OpBackupS3      = "backup.s3"      // S3Target (empty Bucket: off)
)

// S3Target is an S3 or S3-compatible bucket (AWS, Backblaze B2,
// Cloudflare R2, Wasabi, MinIO and so on) that the leader uploads each
// scheduled backup to.
type S3Target struct {
	// Endpoint is the service's address, like "s3.eu-west-2.amazonaws.com"
	// or "https://minio.lan:9000". Empty means AWS for Region.
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix,omitempty"` // folder inside the bucket
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	// PathStyle puts the bucket in the path rather than the host name,
	// which MinIO and some NAS apps need.
	PathStyle bool `json:"path_style,omitempty"`
}

// Clean trims the fields and checks them.
func (t *S3Target) Clean() error {
	t.Endpoint = strings.TrimRight(strings.TrimSpace(t.Endpoint), "/")
	t.Region = strings.TrimSpace(t.Region)
	t.Bucket = strings.TrimSpace(t.Bucket)
	t.Prefix = strings.Trim(strings.TrimSpace(t.Prefix), "/")
	t.AccessKey = strings.TrimSpace(t.AccessKey)
	t.SecretKey = strings.TrimSpace(t.SecretKey)
	switch {
	case t.Bucket == "":
		return errors.New("enter the bucket name")
	case strings.ContainsAny(t.Bucket, "/ "):
		return errors.New("the bucket is just its name, without slashes; put a folder under Folder")
	case t.AccessKey == "" || t.SecretKey == "":
		return errors.New("enter the access key and secret key")
	case t.Endpoint == "" && t.Region == "":
		return errors.New("enter the region (for AWS) or the endpoint (for other services)")
	}
	if strings.Contains(t.Endpoint, "://") && !strings.HasPrefix(t.Endpoint, "https://") && !strings.HasPrefix(t.Endpoint, "http://") {
		return errors.New("the endpoint must start with https:// or http://, or be just a host name")
	}
	return nil
}

// BackupData returns a copy of what a backup holds.
func (st *State) BackupData() BackupData {
	cp := st.clone()
	return BackupData{Users: cp.Users, Tokens: cp.Tokens, Settings: cp.Settings, Devices: cp.Devices, Groups: cp.Groups,
		ConfigVersions: cp.ConfigVersions, ConfigSeq: cp.ConfigSeq, SetupDone: cp.SetupDone, Backup: &cp.Backup}
}

func validClock(s string) bool {
	_, err := time.Parse("15:04", s)
	return err == nil
}

func applyBackup(st *State, c Command, dec func(any) error) (any, *AuditEntry, error) {
	switch c.Op {
	case OpBackupConfig:
		var d BackupConfig
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		switch d.Every {
		case "", "daily", "weekly":
		default:
			return nil, nil, fmt.Errorf("unknown schedule %q (daily, weekly or empty)", d.Every)
		}
		if d.Every != "" && !validClock(d.At) {
			return nil, nil, errors.New("backup time must be HH:MM, like 03:00")
		}
		if d.Every != "" && !d.Configured() {
			return nil, nil, errors.New("set a backup passphrase first")
		}
		if d.Keep < 0 || d.Keep > 365 {
			return nil, nil, errors.New("keep 1 to 365 backups")
		}
		d.Offsite = strings.TrimSpace(d.Offsite)
		if d.Offsite != "" && !strings.HasPrefix(d.Offsite, "/") {
			return nil, nil, errors.New("the off-box folder must be an absolute path inside the container, like /backups")
		}
		oldKey := st.Backup.PublicKey
		before := st.Backup
		before.PublicKey, before.Salt = keyNote(before), ""
		st.Backup = d
		after := d
		after.PublicKey, after.Salt = keyNote(d), ""
		what := "changed backup settings"
		if d.PublicKey != "" && d.PublicKey != oldKey {
			what = "set a new backup passphrase"
		}
		return nil, audit(what, before, after), nil

	case OpBackupS3:
		var d S3Target
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(d.Bucket) == "" {
			st.BackupS3 = nil
			return nil, audit("turned off S3 backup uploads", nil, nil), nil
		}
		if err := d.Clean(); err != nil {
			return nil, nil, err
		}
		st.BackupS3 = &d
		// The audit log gets where, never the keys.
		return nil, audit("set the S3 backup bucket", nil, map[string]string{"endpoint": d.Endpoint, "region": d.Region, "bucket": d.Bucket, "folder": d.Prefix}), nil

	case OpBackupRestore:
		var d BackupRestore
		if err := dec(&d); err != nil {
			return nil, nil, err
		}
		b := d.Data
		tmp := &State{Users: b.Users}
		if tmp.Admins() == 0 {
			return nil, nil, errors.New("that backup has no enabled admin account")
		}
		st.Users, st.Tokens, st.Settings, st.Devices, st.Groups = b.Users, b.Tokens, b.Settings, b.Devices, b.Groups
		st.ConfigVersions, st.ConfigSeq, st.SetupDone = b.ConfigVersions, b.ConfigSeq, b.SetupDone
		if !st.Backup.Configured() && b.Backup != nil {
			st.Backup = *b.Backup
		}
		st.fillMaps()
		return nil, audit(fmt.Sprintf("restored a backup made on %s by %q", d.Created.UTC().Format("2006-01-02 15:04 MST"), d.From), nil, nil), nil
	}
	return nil, nil, fmt.Errorf("unknown command %q", c.Op)
}

// keyNote shows in the audit log whether a key is set, without the key.
func keyNote(b BackupConfig) string {
	if b.PublicKey == "" {
		return ""
	}
	return "set"
}
