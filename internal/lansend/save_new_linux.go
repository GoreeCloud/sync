//go:build linux || android

package lansend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// receiverStage pins a private receiver directory by file descriptor. The
// caller must close it, even when writing, syncing or publishing fails.
type receiverStage struct {
	root     string
	dirfd    int
	rootStat syscall.Stat_t
	tempName string
	file     *os.File
}

func newReceiverStage(root string) (*receiverStage, error) {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open private receiver directory: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if st.Mode&077 != 0 {
		_ = syscall.Close(fd)
		return nil, errors.New("receiver directory must be private (0700)")
	}
	// Recheck against the pinned directory descriptor immediately before
	// staging. This catches residue even if the path was replaced between
	// the public audit and this open; no existing artifacts are removed.
	if err := refuseReceiverResidueFD(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	var name string
	for i := 0; i < 8; i++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			_ = syscall.Close(fd)
			return nil, err
		}
		name = ".gcsend-stage-" + hex.EncodeToString(nonce[:])
		stagefd, err := syscall.Openat(fd, name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			_ = syscall.Close(fd)
			return nil, err
		}
		return &receiverStage{root: root, dirfd: fd, rootStat: st, tempName: name, file: os.NewFile(uintptr(stagefd), name)}, nil
	}
	_ = syscall.Close(fd)
	return nil, errors.New("unable to allocate unique receiver stage")
}

func refuseReceiverResidueFD(fd int) error {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "receiver-directory-audit")
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(128)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), receiverStagePrefix) {
				return errors.New("receiver has crash staging artifact(s); inspect with -audit-receive-dir and reconcile manually")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("receiver directory preflight failed: %w", err)
		}
	}
}

func (s *receiverStage) close() {
	if s.file != nil {
		_ = s.file.Close()
	}
	_ = syscall.Unlinkat(s.dirfd, s.tempName)
	_ = syscall.Close(s.dirfd)
}

func (s *receiverStage) checkDir() error {
	fd, err := syscall.Open(s.root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("receiver directory moved: %w", err)
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Dev != s.rootStat.Dev || st.Ino != s.rootStat.Ino || st.Mode&077 != 0 {
		return errors.New("receiver directory identity or privacy changed")
	}
	return nil
}

func (s *receiverStage) commit(final string, data []byte) error {
	if n, err := s.file.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	if err := s.checkDir(); err != nil {
		return fmt.Errorf("receiver destination moved before commit: %w", err)
	}
	oldName, err := syscall.BytePtrFromString(s.tempName)
	if err != nil {
		return err
	}
	newName, err := syscall.BytePtrFromString(final)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(s.dirfd), uintptr(unsafe.Pointer(oldName)), uintptr(s.dirfd), uintptr(unsafe.Pointer(newName)), 0, 0)
	if errno != 0 {
		if errors.Is(errno, syscall.EEXIST) {
			return os.ErrExist
		}
		return fmt.Errorf("publish received file: %w", errno)
	}
	if err := syscall.Fsync(s.dirfd); err != nil {
		return fmt.Errorf("received file created but directory sync failed: %w", err)
	}
	if err := s.checkDir(); err != nil {
		return fmt.Errorf("received file created but receiver directory relocated: %w", err)
	}
	return nil
}

func saveNewPrivate(root, name string, data []byte) error {
	s, err := newReceiverStage(root)
	if err != nil {
		return err
	}
	defer s.close()
	return s.commit(name, data)
}
