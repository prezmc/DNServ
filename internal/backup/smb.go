package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/prezmc/dnserv/internal/store"
)

// SMB writes backups to a Windows or NAS share over SMB 2/3, without the
// share having to be mounted on the host.
type SMB struct {
	T store.SMBTarget
	// Dial opens the TCP connection (nil: a plain dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Where is the share as people write it, for messages.
func (c *SMB) Where() string {
	w := `\\` + c.T.Server + `\` + c.T.Share
	if c.T.Folder != "" {
		w += `\` + strings.ReplaceAll(c.T.Folder, "/", `\`)
	}
	return w
}

func (c *SMB) addr() string {
	if _, _, err := net.SplitHostPort(c.T.Server); err == nil {
		return c.T.Server
	}
	return net.JoinHostPort(strings.Trim(c.T.Server, "[]"), "445")
}

// with connects, mounts the share, runs fn and disconnects. Backups are
// rare, so each operation uses its own connection.
func (c *SMB) with(ctx context.Context, fn func(fs *smb2.Share) error) error {
	dial := c.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", c.addr())
	if err != nil {
		return fmt.Errorf("couldn't reach %s: %w", c.T.Server, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: c.T.User, Password: c.T.Password, Domain: c.T.Domain}}
	s, err := d.DialContext(ctx, conn)
	if err != nil {
		return smbError("signing in", err)
	}
	defer s.Logoff()
	fs, err := s.WithContext(ctx).Mount(c.T.Share)
	if err != nil {
		return smbError("opening the share", err)
	}
	defer fs.Umount()
	return fn(fs.WithContext(ctx))
}

// smbError makes an SMB failure readable and adds a hint to the common
// ones.
func smbError(doing string, err error) error {
	msg := strings.TrimPrefix(err.Error(), "response error: ")
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		switch re.Code {
		case 0xC000006D: // STATUS_LOGON_FAILURE
			msg = "the user name or password was refused"
		case 0xC00000CC: // STATUS_BAD_NETWORK_NAME
			msg = "there's no share by that name (check the share name)"
		case 0xC0000022: // STATUS_ACCESS_DENIED
			msg = "access denied (the user needs permission to read, write and delete in that folder)"
		}
	}
	return fmt.Errorf("%s: %s", doing, msg)
}

func (c *SMB) file(name string) string {
	if c.T.Folder == "" {
		return name
	}
	return path.Join(c.T.Folder, name)
}

// winPath turns a slash path into the backslash form SMB uses.
func winPath(p string) string { return strings.ReplaceAll(p, "/", `\`) }

// The share's folder listing isn't used: the SMB library's directory
// parsing can be crashed by a bad server (GO-2026-5051, no fix yet). An
// index file in the folder records the backups DNServ wrote instead, and
// each entry is checked with Stat when listed.
const smbIndex = ".dnserv-backups.json"

type smbEntry struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (c *SMB) readIndex(fs *smb2.Share) ([]smbEntry, error) {
	b, err := fs.ReadFile(winPath(c.file(smbIndex)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, smbError("reading the backup index", err)
	}
	var out []smbEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, nil // unreadable: start again
	}
	return out, nil
}

func (c *SMB) writeIndex(fs *smb2.Share, idx []smbEntry) error {
	b, _ := json.MarshalIndent(idx, "", "  ")
	if err := fs.WriteFile(winPath(c.file(smbIndex)), b, 0o600); err != nil {
		return smbError("writing the backup index", err)
	}
	return nil
}

// Put writes one file, through a temporary name so a half-written backup
// never looks like a real one.
func (c *SMB) Put(ctx context.Context, name string, b []byte) error {
	return c.with(ctx, func(fs *smb2.Share) error {
		if c.T.Folder != "" {
			if err := fs.MkdirAll(winPath(c.T.Folder), 0o700); err != nil {
				return smbError("creating the folder", err)
			}
		}
		tmp := winPath(c.file("." + name + ".tmp"))
		if err := fs.WriteFile(tmp, b, 0o600); err != nil {
			return smbError("writing", err)
		}
		dst := winPath(c.file(name))
		_ = fs.Remove(dst) // Rename doesn't replace on every server
		if err := fs.Rename(tmp, dst); err != nil {
			_ = fs.Remove(tmp)
			return smbError("renaming", err)
		}
		idx, err := c.readIndex(fs)
		if err != nil {
			return err
		}
		idx = slices.DeleteFunc(idx, func(e smbEntry) bool { return e.Name == name })
		idx = append(idx, smbEntry{Name: name, Size: int64(len(b)), Modified: time.Now().UTC()})
		return c.writeIndex(fs, idx)
	})
}

// Get reads one file.
func (c *SMB) Get(ctx context.Context, name string) (b []byte, err error) {
	err = c.with(ctx, func(fs *smb2.Share) error {
		info, err := fs.Stat(winPath(c.file(name)))
		if err != nil {
			return smbError("reading", err)
		}
		if info.Size() > maxObject {
			return errors.New("that file is too large to be a backup")
		}
		b, err = fs.ReadFile(winPath(c.file(name)))
		if err != nil {
			return smbError("reading", err)
		}
		return nil
	})
	return b, err
}

// Delete removes one file. One already gone counts as removed.
func (c *SMB) Delete(ctx context.Context, name string) error {
	return c.with(ctx, func(fs *smb2.Share) error {
		if err := fs.Remove(winPath(c.file(name))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return smbError("deleting", err)
		}
		idx, err := c.readIndex(fs)
		if err != nil {
			return err
		}
		n := len(idx)
		idx = slices.DeleteFunc(idx, func(e smbEntry) bool { return e.Name == name })
		if len(idx) == n {
			return nil
		}
		return c.writeIndex(fs, idx)
	})
}

// List returns the backups DNServ wrote to the folder that are still
// there. A folder that doesn't exist yet is empty.
func (c *SMB) List(ctx context.Context) (out []S3Object, err error) {
	err = c.with(ctx, func(fs *smb2.Share) error {
		idx, err := c.readIndex(fs)
		if err != nil {
			return err
		}
		for _, e := range idx {
			info, err := fs.Stat(winPath(c.file(e.Name)))
			if err != nil || info.IsDir() {
				continue // removed by hand
			}
			out = append(out, S3Object{Key: e.Name, Size: info.Size(), Modified: info.ModTime().UTC()})
		}
		return nil
	})
	return out, err
}

// Test checks DNServ can write, read and delete in the folder.
func (c *SMB) Test(ctx context.Context) error {
	name := ".dnserv-test-" + time.Now().UTC().Format("20060102-150405")
	data := []byte("DNServ checks it can write backups here. Safe to delete.\n")
	return c.with(ctx, func(fs *smb2.Share) error {
		if c.T.Folder != "" {
			if err := fs.MkdirAll(winPath(c.T.Folder), 0o700); err != nil {
				return smbError("creating the folder", err)
			}
		}
		p := winPath(c.file(name))
		if err := fs.WriteFile(p, data, 0o600); err != nil {
			return smbError("writing a test file", err)
		}
		defer fs.Remove(p)
		if _, err := c.readIndex(fs); err != nil {
			return err
		}
		got, err := fs.ReadFile(p)
		if err != nil {
			return smbError("reading the test file back", err)
		}
		if !bytes.Equal(got, data) {
			return errors.New("the test file came back different")
		}
		if err := fs.Remove(p); err != nil {
			return smbError("deleting the test file (old backups couldn't be removed)", err)
		}
		return nil
	})
}
