//go:build !linux && !android

package syncplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The fallback is only for trusted local folders on non-Linux platforms.
// Parent symlink checks are path-based and cannot exclude hostile races.
func newStagedTarget(root, relative string) (*stagedTarget, error) {
	if err := ensureDirs(root, filepath.Dir(relative)); err != nil {
		return nil, err
	}
	destination := filepath.Join(root, relative)
	if _, err := os.Lstat(destination); err == nil {
		return nil, fmt.Errorf("destination already exists: %s", relative)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".gcsync-stage-")
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	stage := &stagedTarget{file: tmp}
	stage.cleanup = func() { stage.file.Close(); _ = os.Remove(tmp.Name()) }
	stage.commit = func() (bool, error) {
		if err := os.Link(tmp.Name(), destination); err != nil {
			return false, fmt.Errorf("cannot commit new file %s: %w", relative, err)
		}
		dir, err := os.Open(filepath.Dir(destination))
		if err != nil {
			return true, err
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return true, syncErr
		}
		return true, closeErr
	}
	return stage, nil
}
