//go:build linux || android

package deviceid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// openDeviceDirectory opens each absolute path component relative to a pinned
// descriptor and refuses every symlink, not just a symlink at the leaf.
func openDeviceDirectory(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if abs != "/" {
		for _, name := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
			if !validDeviceComponent(name) {
				syscall.Close(fd)
				return nil, errors.New("invalid identity directory component")
			}
			next, e := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			syscall.Close(fd)
			if e != nil {
				return nil, fmt.Errorf("identity directory component refused: %w", e)
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), abs), nil
}

func validDeviceComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsRune(s, '/') && !strings.ContainsRune(s, 0)
}

func privateDeviceDirectory(path string) (*os.File, error) {
	dir, err := openDeviceDirectory(path)
	if err != nil {
		return nil, err
	}
	st, err := dir.Stat()
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		dir.Close()
		return nil, errors.New("identity directory must be a real private directory (0700)")
	}
	return dir, nil
}
func verifyDevicePrivateDir(path string) error {
	dir, err := privateDeviceDirectory(path)
	if err != nil {
		return err
	}
	return dir.Close()
}

// ensureDevicePrivateDir never follows a symlink while creating intermediate
// directories; only the final target is required to have private permissions.
func ensureDevicePrivateDir(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(dir) }()
	if abs != "/" {
		for _, name := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
			if !validDeviceComponent(name) {
				return errors.New("invalid identity directory component")
			}
			next, e := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if errors.Is(e, syscall.ENOENT) {
				if mk := syscall.Mkdirat(dir, name, 0700); mk != nil && !errors.Is(mk, syscall.EEXIST) {
					return mk
				}
				next, e = syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			}
			if e != nil {
				return fmt.Errorf("identity directory component refused: %w", e)
			}
			syscall.Close(dir)
			dir = next
		}
	}
	var st syscall.Stat_t
	if err = syscall.Fstat(dir, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0077 != 0 {
		return errors.New("identity directory must be a real private directory (0700)")
	}
	return nil
}

func verifyDevicePinnedDirectory(path string, pinned *os.File) error {
	current, err := privateDeviceDirectory(path)
	if err != nil {
		return err
	}
	defer current.Close()
	a, err := pinned.Stat()
	if err != nil {
		return err
	}
	b, err := current.Stat()
	if err != nil || !os.SameFile(a, b) {
		return errors.New("identity directory changed during operation")
	}
	return nil
}
func devicePrivateStat(st os.FileInfo, limit int64) error {
	if st == nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 0 || st.Size() > limit {
		return errors.New("identity/trust record is not a small regular private file (0600)")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink != 1 {
		return errors.New("identity/trust record must not have extra hardlinks")
	}
	return nil
}
func devicePrivateOpenAt(dir *os.File, name string, limit int64) (*os.File, os.FileInfo, error) {
	if !validDeviceComponent(name) {
		return nil, nil, errors.New("invalid identity filename")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err == nil {
		err = devicePrivateStat(st, limit)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}
func readDevicePrivateFile(path string, max int) ([]byte, error) {
	dirPath, name := filepath.Dir(path), filepath.Base(path)
	dir, err := privateDeviceDirectory(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, initial, err := devicePrivateOpenAt(dir, name, int64(max))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, errors.New("identity/trust record exceeds size limit")
	}
	final, err := f.Stat()
	if err != nil || !os.SameFile(initial, final) || final.Size() != initial.Size() {
		return nil, errors.New("identity/trust record changed during read")
	}
	if err := verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return nil, err
	}
	return b, nil
}
func deviceLinkAt(fd int, oldName, newName string) error {
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(fd), uintptr(unsafe.Pointer(old)), uintptr(fd), uintptr(unsafe.Pointer(next)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func writeDevicePrivateFile(dirPath, name string, content []byte) error {
	if !validDeviceComponent(name) {
		return errors.New("invalid identity record name")
	}
	dir, err := privateDeviceDirectory(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return err
	}
	var stage string
	var stageFD int
	for attempt := 0; attempt < 5; attempt++ {
		var entropy [16]byte
		if _, err = rand.Read(entropy[:]); err != nil {
			return err
		}
		stage = ".gc-identity-stage-" + hex.EncodeToString(entropy[:])
		stageFD, err = syscall.Openat(int(dir.Fd()), stage, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("cannot stage private identity record: %w", err)
	}
	stagePresent := true
	defer func() {
		if stagePresent {
			_ = syscall.Unlinkat(int(dir.Fd()), stage)
			_ = dir.Sync() // best-effort recovery cleanup after an error
		}
	}()
	f := os.NewFile(uintptr(stageFD), stage)
	if _, err = f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return err
	}
	if err = deviceLinkAt(int(dir.Fd()), stage, name); err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("identity record published but parent sync failed: %w", err)
	}
	// A completed operation must not leave an extra on-disk hardlink to its
	// private seed. Persist removal of the temporary name before success.
	if err = syscall.Unlinkat(int(dir.Fd()), stage); err != nil {
		return fmt.Errorf("identity record published but stage cleanup failed: %w", err)
	}
	stagePresent = false
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("identity record published but stage cleanup sync failed: %w", err)
	}
	if err = verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return fmt.Errorf("identity record may have been published before directory moved: %w", err)
	}
	return nil
}
func listDevicePrivateFileNames(path string) ([]string, error) {
	d, err := privateDeviceDirectory(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	if err := verifyDevicePinnedDirectory(path, d); err != nil {
		return nil, err
	}
	return names, nil
}
func removeDevicePrivateFile(dirPath, name string) error {
	if !validDeviceComponent(name) {
		return errors.New("invalid trusted record name")
	}
	dir, err := privateDeviceDirectory(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, pinned, err := devicePrivateOpenAt(dir, name, recordLimit)
	if err != nil {
		return err
	}
	f.Close()
	if err := verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return err
	}
	f, check, err := devicePrivateOpenAt(dir, name, recordLimit)
	if err != nil {
		return err
	}
	f.Close()
	if !os.SameFile(pinned, check) {
		return errors.New("trusted record replaced before removal")
	}
	if err = syscall.Unlinkat(int(dir.Fd()), name); err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("trust record removed but directory sync failed: %w", err)
	}
	if err = verifyDevicePinnedDirectory(dirPath, dir); err != nil {
		return fmt.Errorf("trust record removed but directory path changed: %w", err)
	}
	return nil
}
