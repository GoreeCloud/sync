package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A stage inode created before a crash is never a user-requested source file.
// The caller must inspect it rather than accidentally propagating it.
func TestStagingResidueBlocksInventoryAndCopy(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(from, "folder"), 0700); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(from, "folder", ".gcsync-stage-0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(expected, []byte("interrupted private ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(from, "valid.txt"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, excludes := range [][]string{nil, {"*.gcsync-stage-*"}} {
		_, err := CompareFiltered(from, to, excludes)
		if err == nil || !strings.Contains(err.Error(), "staging artifact") {
			t.Fatalf("residue hidden by exclusion %q: %v", excludes, err)
		}
		_, err = ApplyAdditionsFiltered(from, to, excludes)
		if err == nil || !strings.Contains(err.Error(), "staging artifact") {
			t.Fatalf("residue propagated under exclusion %q: %v", excludes, err)
		}
		if entries, err := os.ReadDir(to); err != nil || len(entries) != 0 {
			t.Fatalf("copy made mutations: %v %v", entries, err)
		}
	}
	if err := os.Remove(expected); err != nil {
		t.Fatal(err)
	}
	plan, err := Compare(from, to)
	if err != nil || plan.SourceOnly != 1 {
		t.Fatalf("valid inventory unavailable after manual residue removal: %+v %v", plan, err)
	}
}
