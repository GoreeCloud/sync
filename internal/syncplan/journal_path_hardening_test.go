package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchoredSourceReadRejectsSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "good.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "private.txt"), []byte("confidential"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "private.txt"), filepath.Join(root, "final-link")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"linkdir/private.txt", "final-link", "../private.txt", "safe/../../private.txt", "", "."} {
		handle, err := openRegularWithinRoot(root, rel)
		if handle != nil {
			handle.Close()
		}
		if err == nil {
			t.Fatalf("unsafe source path %q accepted", rel)
		}
	}
	f, err := openRegularWithinRoot(root, "safe/good.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2)
	if n, err := f.Read(buf); err != nil || n != 2 || string(buf) != "ok" {
		t.Fatalf("unexpected safe file: %d %q %v", n, buf, err)
	}
}

func TestDurableExactJournalPlanRejectsUnplannedAdditions(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(left, "planned.txt"), []byte("planned"), 0600); err != nil {
		t.Fatal(err)
	}
	reviewed, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent new file appears AFTER the pending journal was prepared.
	if err := os.WriteFile(filepath.Join(left, "new-after-review.txt"), []byte("later"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := applyBidirectionalPlan(left, right, reviewed)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RightCreated) != 1 || result.RightCreated[0] != "planned.txt" {
		t.Fatalf("copied wrong files: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(right, "new-after-review.txt")); !os.IsNotExist(err) {
		t.Fatalf("new unjournaled file copied: %v", err)
	}
	after, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCopiedFiles(reviewed, after); err == nil {
		t.Fatal("expected fail closed for unjournaled addition")
	}
}

func TestDurableExactJournalPlanRejectsChangedIdenticalFile(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	for _, root := range []string{left, right} {
		if err := os.WriteFile(filepath.Join(root, "known.txt"), []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reviewed, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{left, right} {
		if err := os.WriteFile(filepath.Join(root, "known.txt"), []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyCopiedFiles(reviewed, after)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("undetected previously identical file modification: %v", err)
	}
}
