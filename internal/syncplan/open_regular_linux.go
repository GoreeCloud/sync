//go:build linux || android

package syncplan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openRegularWithinRoot anchors each component to a directory descriptor and
// refuses symbolic links. Unlike a path-based os.Open, a concurrent rename or
// symlink replacement cannot redirect this file read through an ancestor.
// This does not secure destination writes or defend against malicious mutation
// of an already-open regular file by another actor.
func openRegularWithinRoot(root, relative string) (*os.File, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) == "." || filepath.Clean(relative) != relative {
		return nil, errors.New("invalid relative file path")
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("unsafe file path component")
		}
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), filepath.Join(root, relative)), nil
}
