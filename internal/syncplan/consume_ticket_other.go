//go:build !linux && !android

package syncplan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Guarded portability fallback. It does not guarantee component-anchored
// reads or writes when directories can be concurrently replaced.
func consumeOneUseTicket(ticketPath, expectedSHA string) error {
	before, err := os.Lstat(ticketPath)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("one-use ticket must be a regular file at commit")
	}
	f, err := openProtectedRegularFile(ticketPath)
	if err != nil {
		return err
	}
	pinnedStat, err := verifyTicketAtCommit(f, expectedSHA)
	_ = f.Close()
	if err != nil {
		return err
	}
	if !os.SameFile(before, pinnedStat) {
		return errors.New("one-use ticket changed at commit")
	}
	spent := ticketPath + ".used"
	if err := os.Link(ticketPath, spent); err != nil {
		return fmt.Errorf("one-use ticket already spent or unable to commit: %w", err)
	}
	issuedStat, e1 := os.Lstat(ticketPath)
	markerStat, e2 := os.Lstat(spent)
	if e1 != nil || e2 != nil || !os.SameFile(pinnedStat, issuedStat) || !os.SameFile(pinnedStat, markerStat) {
		return errors.New("one-use marker created but ticket identity changed; manual review required")
	}
	dir, err := os.Open(filepath.Dir(ticketPath))
	if err != nil {
		return fmt.Errorf("ticket spent but directory not durable: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("ticket spent but directory sync failed: %w", err)
	}
	return nil
}
