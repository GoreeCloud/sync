//go:build linux || android

package lansend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openSenderSource anchors every component of the source path to its parent's
// open directory descriptor and does not follow symlinks. A swapped pathname
// cannot redirect the read into an unrelated file after it has been opened.
// This does not stop a malicious process from modifying an already-open inode.
func openSenderSource(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	parts := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if absolute == string(filepath.Separator) || len(parts) == 0 {
		return nil, errors.New("source must be a regular file")
	}
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open source root: %w", err)
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, errors.New("unsafe source path component")
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("source path requires real directories and a non-symlink file: %w", openErr)
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), absolute)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("source must be a regular file")
	}
	return file, nil
}
