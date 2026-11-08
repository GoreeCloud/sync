//go:build !linux && !android

package deviceid

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Other systems retain the prior guarded path-based behavior. Atomic
// directory-fd operations have NOT been verified here.
func verifyDevicePrivateDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return errors.New("identity directory must be real and private (0700)")
	}
	return nil
}
func ensureDevicePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return verifyDevicePrivateDir(path)
}
func readDevicePrivateFile(path string, max int) ([]byte, error) {
	if err := verifyDevicePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > int64(max) {
		return nil, errors.New("identity/trust record is not a small regular private file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("identity/trust file changed while opening")
	}
	return io.ReadAll(io.LimitReader(f, int64(max)+1))
}
func writeDevicePrivateFile(dir, name string, content []byte) error {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return errors.New("invalid private record name")
	}
	if err := verifyDevicePrivateDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".gc-identity-stage-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("record created but directory cannot sync: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
func listDevicePrivateFileNames(dir string) ([]string, error) {
	if err := verifyDevicePrivateDir(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
func removeDevicePrivateFile(dir, name string) error {
	if err := verifyDevicePrivateDir(dir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("record removed but directory could not sync: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
