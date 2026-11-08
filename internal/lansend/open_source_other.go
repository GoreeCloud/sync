//go:build !linux && !android

package lansend

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Portable best-effort fallback. Unlike the Linux/Android directory-descriptor
// implementation, it cannot prevent a parent path replacement between checks.
func openSenderSource(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	current := filepath.VolumeName(absolute) + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, current)
	if relative == "" {
		return nil, errors.New("source must be a regular file")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("unsafe source path component")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) || (i == len(parts)-1 && !info.Mode().IsRegular()) {
			return nil, errors.New("source must contain only real directories and a regular file")
		}
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
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
