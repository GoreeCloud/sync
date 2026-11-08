//go:build linux || android

package syncplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// consumeOneUseTicket publishes the one-winner .used marker under the SAME
// pinned, no-symlink private directory used for opening the ticket. It does
// not reopen a path to publish into a potentially substituted symlink.
// A same-account adversary who relocates already-open inodes between these
// checks is outside this fail-closed best-effort guarantee.
func consumeOneUseTicket(filename, expectedSHA string) error {
	base := filepath.Base(filename)
	if base == "" || base == "." || base == ".." {
		return errors.New("invalid one-use ticket filename")
	}
	parentPath := filepath.Dir(filename)
	parent, err := openProtectedDirectory(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()

	parentStat, err := parent.Stat()
	if err != nil || !parentStat.IsDir() || parentStat.Mode().Perm() != 0700 {
		return errors.New("one-use ticket parent must remain a private 0700 directory")
	}
	if err := verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return err
	}

	dirFD := int(parent.Fd())
	fd, err := syscall.Openat(dirFD, base, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot pin one-use ticket at commit: %w", err)
	}
	opened := os.NewFile(uintptr(fd), filename)
	defer opened.Close()
	pinnedStat, err := verifyTicketAtCommit(opened, expectedSHA)
	if err != nil {
		return err
	}

	// Reopen through the SAME pinned descriptor to refuse an obvious inode
	// swap between reading the ticket and publishing the spent hardlink.
	checkFD, err := syscall.Openat(dirFD, base, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("one-use ticket changed before commit: %w", err)
	}
	check := os.NewFile(uintptr(checkFD), base)
	currentStat, statErr := check.Stat()
	_ = check.Close()
	if statErr != nil || !os.SameFile(pinnedStat, currentStat) {
		return errors.New("one-use ticket inode replaced before commit")
	}
	if err := verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return err
	}

	// linkat with flags=0 links the source entry itself (no symlink follow).
	// Existing .used files/symlinks cause EEXIST, so concurrent consumers
	// cannot both publish a marker.
	if err := linkWithinDir(dirFD, base, base+".used"); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return errors.New("one-use inventory challenge ticket already spent")
		}
		return fmt.Errorf("cannot publish one-use challenge marker: %w", err)
	}
	// Make the marker durable BEFORE success; after a failed post-commit
	// check the marker is intentionally retained for manual review.
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("one-use marker created but directory sync failed: %w", err)
	}
	if err := verifyPinnedPrivateParent(parentPath, parent); err != nil {
		return fmt.Errorf("one-use marker may be in relocated directory; manual review required: %w", err)
	}

	markerFD, err := syscall.Openat(dirFD, base+".used", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("one-use marker created but cannot verify inode; manual review required: %w", err)
	}
	marker := os.NewFile(uintptr(markerFD), base+".used")
	markerStat, statErr := marker.Stat()
	_ = marker.Close()
	if statErr != nil || !os.SameFile(pinnedStat, markerStat) {
		return errors.New("one-use marker created but ticket identity changed; manual review required")
	}
	return nil
}
