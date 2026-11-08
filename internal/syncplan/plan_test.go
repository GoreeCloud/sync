package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, file, text string) {
	t.Helper()
	p := filepath.Join(root, file)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestCompareDetectsNestedDifferencesAndPreservesFiles(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "nested/match.txt", "same")
	write(t, right, "nested/match.txt", "same")
	write(t, left, "different.txt", "AAAA")
	write(t, right, "different.txt", "BBBB")
	write(t, left, "source-only.txt", "source")
	write(t, right, "target-only.txt", "target")
	before, _ := os.ReadFile(filepath.Join(right, "different.txt"))
	p, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ReadOnly || p.SourceFiles != 3 || p.TargetFiles != 3 || p.Identical != 1 || p.SourceOnly != 1 || p.TargetOnly != 1 || p.Different != 1 {
		t.Fatalf("unexpected plan: %+v", p)
	}
	want := []string{"different.txt", "nested/match.txt", "source-only.txt", "target-only.txt"}
	for i, x := range want {
		if p.Changes[i].Path != x {
			t.Fatalf("non-deterministic ordering: %+v", p.Changes)
		}
	}
	after, _ := os.ReadFile(filepath.Join(right, "different.txt"))
	if string(before) != string(after) {
		t.Fatal("comparison modified target data")
	}
	if p.Changes[0].Source.SHA256 == p.Changes[0].Target.SHA256 {
		t.Fatal("same-size different content falsely matched")
	}
}
func TestCompareRejectsSymlinkAndSpecialPaths(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "data.txt", "sample")
	if err := os.Symlink(filepath.Join(left, "data.txt"), filepath.Join(right, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := Compare(left, right)
	if err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("expected symlink rejection: %v", err)
	}
	_, err = Compare(filepath.Join(right, "link.txt"), left)
	if err == nil {
		t.Fatal("symlink root should not be traversed")
	}
}
func TestCompareEmptyAndInvalidRoots(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	p, err := Compare(left, right)
	if err != nil || !p.ReadOnly || len(p.Changes) != 0 {
		t.Fatalf("empty compare: %+v err=%v", p, err)
	}
	if _, err := Compare(left, filepath.Join(right, "does-not-exist")); err == nil {
		t.Fatal("nonexistent target accepted")
	}
}
