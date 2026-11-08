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
	"unsafe"
)

// destinationDirFD walks from an anchored real root, refusing symlinks in
// every existing component. It creates only genuinely missing directories.
// A malicious process able to rename already-open directories can still move
// their inodes; this does not provide a filesystem snapshot or sandbox.
func destinationDirFD(root, rel string, initialRoot *syscall.Stat_t) (int, string, error) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == "." {
		return -1, "", errors.New("invalid destination relative path")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return -1, "", errors.New("unsafe destination component")
		}
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open destination root: %w", err)
	}
	if err := syscall.Fstat(fd, initialRoot); err != nil {
		syscall.Close(fd)
		return -1, "", fmt.Errorf("stat destination root: %w", err)
	}
	for _, part := range parts[:len(parts)-1] {
		child, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(fd, part, 0700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				syscall.Close(fd)
				return -1, "", fmt.Errorf("create destination directory: %w", mkdirErr)
			}
			child, openErr = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		syscall.Close(fd)
		if openErr != nil {
			return -1, "", fmt.Errorf("unsafe destination directory: %w", openErr)
		}
		fd = child
	}
	return fd, parts[len(parts)-1], nil
}

// verifyPinnedDestination refuses to publish into a directory that is no
// longer reachable at its originally selected path. It compares inode/device
// identities while walking from the original root with no symlink following.
// It is a fail-closed check, NOT an atomic rename-prevention primitive: another
// process can still relocate the pinned inode immediately after this check.
func verifyPinnedDestination(root, relative string, initialRoot syscall.Stat_t, pinnedDirfd int) error {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("destination root no longer available: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var currentRoot syscall.Stat_t
	if err := syscall.Fstat(fd, &currentRoot); err != nil {
		return err
	}
	if initialRoot.Dev != currentRoot.Dev || initialRoot.Ino != currentRoot.Ino {
		return errors.New("destination root identity changed during copy")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("destination directory path changed: %w", err)
		}
		_ = syscall.Close(fd)
		fd = next
	}
	var currentDir, pinnedDir syscall.Stat_t
	if err := syscall.Fstat(fd, &currentDir); err != nil {
		return err
	}
	if err := syscall.Fstat(pinnedDirfd, &pinnedDir); err != nil {
		return err
	}
	if currentDir.Dev != pinnedDir.Dev || currentDir.Ino != pinnedDir.Ino {
		return errors.New("destination directory was relocated or replaced during copy")
	}
	return nil
}

// linkWithinDir uses linkat against two names relative to the SAME anchored
// directory descriptor. os.Link(pathname,pathname) would reopen parents and
// allow a substituted symlink to redirect the final commit.
func linkWithinDir(dirfd int, staged, final string) error {
	oldName, err := syscall.BytePtrFromString(staged)
	if err != nil {
		return err
	}
	newName, err := syscall.BytePtrFromString(final)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(oldName)),
		uintptr(dirfd), uintptr(unsafe.Pointer(newName)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func newStagedTarget(root, relative string) (*stagedTarget, error) {
	var rootStat syscall.Stat_t
	dirfd, final, err := destinationDirFD(root, relative, &rootStat)
	if err != nil {
		return nil, err
	}
	// Preflight is only for a useful error; linkat(...,0) below is the
	// actual atomic no-overwrite check even if another process races here.
	if _, err := os.Lstat(filepath.Join(root, relative)); err == nil {
		syscall.Close(dirfd)
		return nil, fmt.Errorf("destination already exists: %s", relative)
	} else if !errors.Is(err, os.ErrNotExist) {
		syscall.Close(dirfd)
		return nil, err
	}

	var staged string
	var stagefd int
	for tries := 0; tries < 4; tries++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			syscall.Close(dirfd)
			return nil, err
		}
		staged = ".gcsync-stage-" + hex.EncodeToString(random[:])
		stagefd, err = syscall.Openat(dirfd, staged, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if !errors.Is(err, syscall.EEXIST) {
			break
		}
	}
	if err != nil {
		syscall.Close(dirfd)
		return nil, fmt.Errorf("create private destination staging file: %w", err)
	}
	stage := &stagedTarget{file: os.NewFile(uintptr(stagefd), staged)}
	stage.cleanup = func() {
		stage.file.Close() // harmless after explicit Close
		_ = syscall.Unlinkat(dirfd, staged)
		_ = syscall.Close(dirfd)
	}
	stage.commit = func() (bool, error) {
		if err := verifyPinnedDestination(root, relative, rootStat, dirfd); err != nil {
			return false, fmt.Errorf("destination moved before commit: %w", err)
		}
		if err := linkWithinDir(dirfd, staged, final); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return false, fmt.Errorf("destination already exists: %s", relative)
			}
			return false, fmt.Errorf("cannot commit new file %s: %w", relative, err)
		}
		if err := syscall.Fsync(dirfd); err != nil {
			return true, err
		}
		if err := verifyPinnedDestination(root, relative, rootStat, dirfd); err != nil {
			return true, fmt.Errorf("destination moved after commit; file may be in relocated directory: %w", err)
		}
		return true, nil
	}
	return stage, nil
}
