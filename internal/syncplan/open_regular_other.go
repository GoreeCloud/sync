//go:build !linux && !android

package syncplan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Portable fallback. Callers verify file identity with Lstat/Stat before and
// after hashing; parent-directory replacement remains a documented race on
// platforms without the Linux/Android descriptor-anchored implementation.
func openRegularWithinRoot(root, relative string) (*os.File, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) == "." || filepath.Clean(relative) != relative {
		return nil, errors.New("invalid relative file path")
	}
	dir := root
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("unsafe file path component")
		}
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symbolic link in source path")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("non-directory source path")
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, errors.New("non-regular source file")
		}
	}
	return os.Open(filepath.Join(root, relative))
}
