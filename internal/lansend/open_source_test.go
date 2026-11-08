package lansend

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSenderSourceRejectsFinalSymlinkBeforeUpload(t *testing.T) {
	parent := privateDir(t)
	secret := filepath.Join(parent, "sensitive.txt")
	if err := os.WriteFile(secret, []byte("must-not-transfer"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	receiver, key, err := NewReceiver(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(receiver)
	defer server.Close()
	if _, err := SendFile(context.Background(), server.URL+"/send", key, link); err == nil {
		t.Fatal("sender followed final symbolic link")
	}
	select {
	case <-receiver.Done():
		t.Fatal("receiver accepted an uploaded linked source")
	default:
	}
}

func TestSenderSourceRejectsParentSymlink(t *testing.T) {
	parent := privateDir(t)
	realDir := filepath.Join(parent, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(realDir, "file.txt")
	if err := os.WriteFile(source, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(parent, "linked")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	f, err := openSenderSource(filepath.Join(linkDir, "file.txt"))
	if f != nil {
		f.Close()
	}
	if err == nil {
		t.Fatal("sender opened source through linked parent")
	}
}

func TestSenderSourcePinsRegularInode(t *testing.T) {
	dir := privateDir(t)
	source := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openSenderSource(source)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	moved := filepath.Join(dir, "moved.txt")
	if err := os.Rename(source, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, source); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("held file descriptor lost original regular inode: %v", err)
	}
	before, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, info) {
		t.Fatal("symbolic link alias identified as opened original inode")
	}
}

func TestSenderSourceRejectsDirectoryAndMissingFile(t *testing.T) {
	dir := privateDir(t)
	f, err := openSenderSource(dir)
	if f != nil {
		f.Close()
	}
	if err == nil {
		t.Fatal("accepted directory as sender file")
	}
	_, err = openSenderSource(filepath.Join(dir, "missing.txt"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file unexpectedly accepted: %v", err)
	}
}
