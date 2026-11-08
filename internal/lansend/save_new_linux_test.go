//go:build linux || android

package lansend

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReceiverStageFailsClosedWhenRootRelocated(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "receiver")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	stage, err := newReceiverStage(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.close()
	moved := filepath.Join(parent, "receiver-moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := stage.commit("document.txt", []byte("secret")); err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("relocated destination was accepted: %v", err)
	}
	for _, dir := range []string{outside, moved} {
		if _, err := os.Lstat(filepath.Join(dir, "document.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("unexpected file in %s: %v", dir, err)
		}
	}
}

func TestReceiverStageRefusesFinalNameRace(t *testing.T) {
	root := privateDir(t)
	stage, err := newReceiverStage(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.close()
	target := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit("existing.txt", []byte("overwrite")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("existing file altered: %q, %v", data, err)
	}
}

func TestReceiverStageRefusesRootIdentityReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "receiver")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stage, err := newReceiverStage(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.close()
	if err := os.Rename(root, filepath.Join(parent, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := stage.commit("secret.txt", []byte("data")); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("root replacement was accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "secret.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replaced root received file: %v", err)
	}
}

func TestReceiverRejectsUnsafeDirAndCleansStage(t *testing.T) {
	root := privateDir(t)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := SaveNew(root, "safe.txt", []byte("x")); err == nil {
		t.Fatal("accepted nonprivate receiver directory")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveNew(root, "safe.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "safe.txt" {
		t.Fatalf("staging residue remained: %+v", entries)
	}
}

// The directory-FD preflight is a second independent check after receiver
// startup; direct staging must not bypass crash-residue detection.
func TestReceiverStagePinnedDirectoryRejectsCrashResidue(t *testing.T) {
	root := privateDir(t)
	stagePath := filepath.Join(root, ".gcsend-stage-left-after-crash")
	if err := os.WriteFile(stagePath, []byte("plaintext"), 0600); err != nil {
		t.Fatal(err)
	}
	stage, err := newReceiverStage(root)
	if stage != nil {
		stage.close()
	}
	if err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("directory-FD stage preflight accepted crash residue: %v", err)
	}
	bytes, err := os.ReadFile(stagePath)
	if err != nil || string(bytes) != "plaintext" {
		t.Fatalf("crash-stage contents altered during preflight: %v", err)
	}
}
