//go:build linux || android

package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newProtectedPrivateFolder(t *testing.T) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	return folder
}

func TestProtectedPrivateFileRefusesSymlinkedAncestor(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	key := filepath.Join(folder, "key.hex")
	if err := NewPrivateInventoryKeyFile(key); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(folder), "linked-private")
	if err := os.Symlink(folder, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInventoryKey(filepath.Join(alias, "key.hex")); err == nil {
		t.Fatal("key was read through a symlinked ancestor")
	}
	if _, err := openProtectedRegularFile(filepath.Join(alias, "key.hex")); err == nil {
		t.Fatal("opened private key through a symlinked ancestor")
	}
	if err := privateNoOverwriteFile(filepath.Join(alias, "should-not-exist.json"), []byte("private metadata")); err == nil {
		t.Fatal("published into a symlinked ancestor")
	}
	if _, err := os.Stat(filepath.Join(folder, "should-not-exist.json")); !os.IsNotExist(err) {
		t.Fatal("write escaped into the real folder", err)
	}
}

func TestProtectedPrivateFileNoOverwriteAndCleanup(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	name := filepath.Join(folder, "inventory.json")
	if err := privateNoOverwriteFile(name, []byte("first")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(name)
	if err != nil || st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
		t.Fatal("published file not private regular", err)
	}
	if err = privateNoOverwriteFile(name, []byte("second")); err == nil {
		t.Fatal("overwrote existing private artifact")
	}
	if content, err := os.ReadFile(name); err != nil || string(content) != "first" {
		t.Fatal("private artifact content changed", err)
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "inventory.json" {
		t.Fatalf("staged artifacts were not removed: %+v", entries)
	}
}

func TestProtectedPrivateFileRejectsSymlinkDestination(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	original := filepath.Join(folder, "keep.txt")
	if err := os.WriteFile(original, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(folder, "output")
	if err := os.Symlink(original, linked); err != nil {
		t.Fatal(err)
	}
	if err := privateNoOverwriteFile(linked, []byte("new")); err == nil {
		t.Fatal("overwrote symlink destination")
	}
	if content, err := os.ReadFile(original); err != nil || string(content) != "original" {
		t.Fatal("modified original through symlink", err)
	}
}

func TestProtectedPrivateKeyRejectsHardlinks(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	key := filepath.Join(folder, "key.hex")
	if err := NewPrivateInventoryKeyFile(key); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(folder, "hardlink.hex")
	if err := os.Link(key, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInventoryKey(key); err == nil || !strings.Contains(err.Error(), "hardlinks") {
		t.Fatal("hard-linked symmetric key accepted", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInventoryKey(key); err != nil {
		t.Fatal("original single-linked symmetric key rejected", err)
	}
}

func TestProtectedRegularFileRejectsFIFOWithoutBlocking(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	fifo := filepath.Join(folder, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := openProtectedRegularFile(fifo); err == nil {
		file.Close()
		t.Fatal("FIFO accepted as private regular file")
	}
}

func TestProtectedInputInventoryRejectsLinkedAncestors(t *testing.T) {
	folder := newProtectedPrivateFolder(t)
	realFile := filepath.Join(folder, "signed.json")
	if err := os.WriteFile(realFile, []byte(strings.Repeat("x", 100)), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(folder), "linked-private")
	if err := os.Symlink(folder, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readOfflineBytes(filepath.Join(alias, "signed.json"), 4096); err == nil {
		t.Fatal("encrypted envelope read through symlinked ancestor")
	}
}
