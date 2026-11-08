//go:build !linux && !android

package lansend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Path-based fallback. Concurrent hostile parent renames are not covered.
func saveNewPrivate(root, name string, data []byte) error {
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return errors.New("receiver directory must be real and private (0700)")
	}
	target := filepath.Join(root, name)
	if _, err := os.Lstat(target); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(root, ".gcsend-stage-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Link(tmp.Name(), target); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return fmt.Errorf("file created, cannot sync directory: %w", err)
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return fmt.Errorf("file created, directory sync failed: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("file created, directory close failed: %w", closeErr)
	}
	return nil
}
