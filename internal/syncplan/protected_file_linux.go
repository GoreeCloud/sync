//go:build linux || android

package syncplan

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openProtectedDirectory walks the entire absolute pathname from / with
// directory descriptors, refusing symlinks at *every* component, not merely
// at the final parent. No caller may replace a component with a symlink and
// redirect a subsequent openat through it.
func openProtectedDirectory(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if abs == "/" {
		return os.NewFile(uintptr(fd), abs), nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, errors.New("unsafe protected file path component")
		}
		child, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("protected parent path refuses symlinks: %w", openErr)
		}
		fd = child
	}
	return os.NewFile(uintptr(fd), abs), nil
}

func openProtectedRegularFile(path string) (*os.File, error) {
	if filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return nil, errors.New("invalid protected file name")
	}
	parent, err := openProtectedDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(path)
	// O_NONBLOCK makes a substituted FIFO/device fail without hanging.
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("protected input must be a regular file")
	}
	return file, nil
}

func uniquePrivateFileLink(stat os.FileInfo) bool {
	s, ok := stat.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}

func verifyPinnedPrivateParent(path string, pinned *os.File) error {
	current, err := openProtectedDirectory(path)
	if err != nil {
		return fmt.Errorf("protected directory no longer reachable: %w", err)
	}
	defer current.Close()
	original, err := pinned.Stat()
	if err != nil {
		return err
	}
	now, err := current.Stat()
	if err != nil || !os.SameFile(original, now) {
		return errors.New("protected directory moved or changed during export")
	}
	return nil
}

// privateNoOverwriteFile stages and publishes relative to one held parent
// directory descriptor, never reopening a pathname to write into a possibly
// substituted symlink. Final publication is an atomic no-overwrite hardlink.
// Hostile relocation between identity checks remains outside this guarantee.
func privateNoOverwriteFile(destination string, payload []byte) error {
	parentPath := filepath.Dir(destination)
	parent, err := openProtectedDirectory(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	base := filepath.Base(destination)
	if base == "" || base == "." || base == ".." {
		return errors.New("invalid destination name")
	}
	if err = verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return err
	}
	var stage string
	var stageFD int
	for attempt := 0; attempt < 5; attempt++ {
		var entropy [16]byte
		if _, err = rand.Read(entropy[:]); err != nil {
			return err
		}
		stage = ".gcsync-offline-inventory-" + hex.EncodeToString(entropy[:])
		stageFD, err = syscall.Openat(int(parent.Fd()), stage, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("cannot stage private artifact: %w", err)
	}
	defer func() { _ = syscall.Unlinkat(int(parent.Fd()), stage) }()
	staged := os.NewFile(uintptr(stageFD), stage)
	if _, err = staged.Write(payload); err != nil {
		staged.Close()
		return err
	}
	if err = staged.Sync(); err != nil {
		staged.Close()
		return err
	}
	if err = staged.Close(); err != nil {
		return err
	}
	if err = verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return err
	}
	if err = linkWithinDir(int(parent.Fd()), stage, base); err != nil {
		return fmt.Errorf("protected file already exists or cannot be committed: %w", err)
	}
	if err = verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return fmt.Errorf("protected file may have been committed before directory moved: %w", err)
	}
	return parent.Sync()
}
