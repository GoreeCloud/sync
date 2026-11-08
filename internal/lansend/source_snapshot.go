package lansend

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

// readStableSenderSource double-reads a bounded regular source through the
// same pinned file descriptor. A same-length rewrite with a restored mtime
// between passes is detected by the content digest comparison. This is NOT
// an atomic snapshot: a concurrent writer can still change bytes before the
// first pass, after the second pass, or oscillate content between reads.
func readStableSenderSource(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > MaxFileBytes {
		return nil, errors.New("source must be a regular file of at most 20 MiB")
	}
	f, err := openSenderSource(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || !before.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("source changed before read")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes || int64(len(data)) != before.Size() {
		return nil, errors.New("source changed during first read")
	}
	if err := verifySourceSecondPass(f, data); err != nil {
		return nil, err
	}
	handle, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !handle.Mode().IsRegular() ||
		!os.SameFile(before, handle) || !os.SameFile(handle, after) ||
		after.Size() != before.Size() || handle.Size() != before.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(handle.ModTime()) {
		return nil, errors.New("source changed during verification")
	}
	return data, nil
}

// verifySourceSecondPass checks a second pass without reopening a pathname.
// The extra byte catches concurrent appends even if the first read completed
// before the append. A full second buffer is never allocated.
func verifySourceSecondPass(f *os.File, first []byte) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(f, int64(len(first))+1))
	if err != nil {
		return err
	}
	firstHash := sha256.Sum256(first)
	secondHash := digest.Sum(nil)
	if n != int64(len(first)) || !bytes.Equal(firstHash[:], secondHash) {
		return errors.New("source content changed between verification reads")
	}
	return nil
}
