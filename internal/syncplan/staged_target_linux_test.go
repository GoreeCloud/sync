//go:build linux || android

package syncplan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A forged destination parent must not be followed, even when the test
// calls the staging implementation directly rather than through inventory.
func TestStagedDestinationRejectsSymlinkComponents(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := newStagedTarget(root, "escape/secret.bin"); err == nil {
		t.Fatal("symlinked directory was accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "secret.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected outside file: %v", err)
	}
	rootLink := filepath.Join(t.TempDir(), "target-link")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := newStagedTarget(rootLink, "secret.bin"); err == nil {
		t.Fatal("symlinked destination root was accepted")
	}
	for _, bad := range []string{"../escape", "", "a//file", "a/../file", "/absolute", "./file"} {
		if _, err := newStagedTarget(root, bad); err == nil {
			t.Fatalf("unsafe destination %q accepted", bad)
		}
	}
}

// The no-replace operation must not overwrite an existing final path that
// appears AFTER we have created a private stage file.
func TestStagedDestinationRefusesFinalNameRace(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedTarget(root, "nested/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if _, err := stage.file.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "nested", "file.txt")
	if err := os.WriteFile(final, []byte("must stay"), 0600); err != nil {
		t.Fatal(err)
	}
	committed, err := stage.commit()
	if err == nil || committed || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwriting destination was not refused: committed=%v err=%v", committed, err)
	}
	b, err := os.ReadFile(final)
	if err != nil || string(b) != "must stay" {
		t.Fatalf("existing bytes changed: %q %v", b, err)
	}
}

// A symlink substituted at the ORIGINAL pathname after opening a directory
// must not redirect the already-anchored stage or no-overwrite commit.
// A hostile rename of the OPEN directory itself is still outside our trust
// model; this test does not make the copier an adversarial sandbox.
func TestStagedDestinationRefusesRelocatedDirectoryAfterSymlinkSwap(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	stage, err := newStagedTarget(root, "nested/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if _, err := stage.file.Write([]byte("anchored")); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "nested"), filepath.Join(root, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nested")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	committed, err := stage.commit()
	if err == nil || committed {
		t.Fatalf("commit into relocated inode should fail: committed=%v err=%v", committed, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "renamed", "file.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file published into relocated inode: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "file.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink redirected destination: %v", err)
	}
}

// Moving a parent directory while staging must not publish into the old inode.
func TestStagedDestinationRefusesMovedAncestor(t *testing.T) {
	root := t.TempDir()
	stage, err := newStagedTarget(root, "a/b/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if _, err := stage.file.Write([]byte("private")); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "old-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a", "b"), 0700); err != nil {
		t.Fatal(err)
	}
	committed, err := stage.commit()
	if err == nil || committed {
		t.Fatalf("moved ancestor was accepted: %v %v", committed, err)
	}
	for _, path := range []string{filepath.Join(root, "a", "b", "file.txt"), filepath.Join(root, "old-a", "b", "file.txt")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file wrongly published at %s: %v", path, err)
		}
	}
}

// Root replacement must be detected even if the same relative directory path
// exists below the replacement root.
func TestStagedDestinationRefusesReplacedRoot(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stage, err := newStagedTarget(root, "x/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cleanup()
	if _, err := stage.file.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, filepath.Join(top, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "x"), 0700); err != nil {
		t.Fatal(err)
	}
	committed, err := stage.commit()
	if err == nil || committed {
		t.Fatalf("replaced root accepted: %v %v", committed, err)
	}
	for _, path := range []string{filepath.Join(root, "x", "file.txt"), filepath.Join(top, "renamed", "x", "file.txt")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("wrongly committed %s: %v", path, err)
		}
	}
}

func TestStagedDestinationNoGarbageAfterCopyFailure(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	write(t, from, "a/b.txt", "original")
	plan, err := Compare(from, to)
	if err != nil {
		t.Fatal(err)
	}
	write(t, from, "a/b.txt", "tampered")
	if _, committed, err := copyOneAtomic(from, to, plan.Changes[0]); err == nil || committed {
		t.Fatalf("stale hash accepted: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(to, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("stale staging artifacts: %v", entries)
	}
}
