//go:build !linux && !android

package syncplan

import (
	"fmt"
	"os"
	"path/filepath"
)

// This guarded portability fallback rejects obvious symlinks but is weaker
// than Linux/Android descriptor-anchored component-by-component operations.
func openProtectedRegularFile(filename string) (*os.File, error) {
	stat, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("protected input must be a regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		file.Close()
		return nil, fmt.Errorf("protected input changed while opening")
	}
	return file, nil
}

func uniquePrivateFileLink(_ os.FileInfo) bool { return true }

func privateNoOverwriteFile(destination string, payload []byte) error {
	parentPath := filepath.Dir(destination)
	tmp, err := os.CreateTemp(parentPath, ".gcsync-offline-inventory-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), destination); err != nil {
		return fmt.Errorf("inventory not created (existing path or link unsupported): %w", err)
	}
	dir, err := os.Open(parentPath)
	if err != nil {
		return fmt.Errorf("inventory created but parent sync failed: %w", err)
	}
	defer dir.Close()
	return dir.Sync()
}
