package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// The image's dnserv user and group. The updater talks to this ID only
// (see runUpdater), so the server always ends up running as it.
const appUID, appGID = 65532, 65532

// dropRoot runs when the container starts as root, which is the image's
// default. It makes sure the data folder belongs to the dnserv user, then
// switches to that user for good. That way a folder mounted from a NAS
// (Synology, Unraid, TrueNAS), which is usually owned by some other user,
// works without anyone having to change its permissions by hand.
//
// When the container is started as another user (docker run --user), or
// on a system that isn't root at all, it does nothing.
func dropRoot(log *slog.Logger, dirs ...string) {
	if os.Getuid() != 0 || os.Getenv("DNSERV_RUN_AS_ROOT") == "1" {
		return
	}
	for _, dir := range dirs {
		if err := ownTree(dir); err != nil {
			// Some network shares refuse chown even for root. Staying
			// root still works; it's just less tidy than the usual user.
			log.Warn("can't give the data folder to the dnserv user; carrying on as root", "dir", dir, "err", err)
			return
		}
	}
	if err := syscall.Setgroups([]int{appGID}); err != nil {
		log.Warn("can't drop root; carrying on as root", "err", err)
		return
	}
	if err := syscall.Setgid(appGID); err != nil {
		log.Warn("can't drop root; carrying on as root", "err", err)
		return
	}
	if err := syscall.Setuid(appUID); err != nil {
		log.Warn("can't drop root; carrying on as root", "err", err)
		return
	}
	os.Setenv("HOME", dirs[0])
}

// ownTree gives dir and everything in it to the dnserv user. A folder that
// already belongs to it is left alone, so normal restarts stay instant.
func ownTree(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if owned(dir) {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return os.Lchown(p, appUID, appGID)
		}
		return os.Chown(p, appUID, appGID)
	})
}

func owned(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == appUID && st.Gid == appGID
}
