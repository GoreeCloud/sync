//go:build linux || android || darwin || freebsd || openbsd || netbsd

package syncplan

import (
	"errors"
	"os"
	"syscall"
)

// The .lock inode is persistent to avoid unlock/relink races. flock releases
// automatically on process exit, including after a crash. The state itself
// can be atomically replaced without changing the lock's inode.
func lockDurableState(filename string) (func(), error) {
	lockPath := filename + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), lockPath)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("sync state lock must be a private 0600 regular file")
	}
	byName, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(info, byName) {
		file.Close()
		return nil, errors.New("sync lock file changed before locking")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another sync worker holds the state lock; refusing concurrent run")
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
