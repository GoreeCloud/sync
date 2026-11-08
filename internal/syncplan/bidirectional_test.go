package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBidirectionalAddsWithoutOverwritingEitherSide(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "deep/left.txt", "from left")
	write(t, right, "deep/right.txt", "from right")
	write(t, left, "same.txt", "equal")
	write(t, right, "same.txt", "equal")
	write(t, left, "ignored.tmp", "left ignored")
	write(t, right, "ignored.tmp", "right ignored")
	beforeLeft, _ := os.Stat(filepath.Join(left, "same.txt"))
	beforeRight, _ := os.Stat(filepath.Join(right, "same.txt"))
	got, err := ApplyBidirectionalAdditionsFiltered(left, right, []string{"*.tmp"})
	if err != nil || !got.Applied || got.Unchanged != 1 || got.Conflicts != 0 || got.BytesWritten != int64(len("from left")+len("from right")) || len(got.LeftCreated) != 1 || got.LeftCreated[0] != "deep/right.txt" || len(got.RightCreated) != 1 || got.RightCreated[0] != "deep/left.txt" {
		t.Fatalf("bad two-way result %+v %v", got, err)
	}
	for _, tc := range []struct{ root, name, want string }{{left, "deep/right.txt", "from right"}, {right, "deep/left.txt", "from left"}, {left, "ignored.tmp", "left ignored"}, {right, "ignored.tmp", "right ignored"}} {
		data, err := os.ReadFile(filepath.Join(tc.root, tc.name))
		if err != nil || string(data) != tc.want {
			t.Errorf("wrong %s: %q %v", tc.name, data, err)
		}
	}
	afterLeft, _ := os.Stat(filepath.Join(left, "same.txt"))
	afterRight, _ := os.Stat(filepath.Join(right, "same.txt"))
	if !os.SameFile(beforeLeft, afterLeft) || !os.SameFile(beforeRight, afterRight) {
		t.Fatal("existing equal data was replaced")
	}
	repeat, err := ApplyBidirectionalAdditionsFiltered(left, right, []string{"*.tmp"})
	if err != nil || !repeat.Applied || len(repeat.LeftCreated) != 0 || len(repeat.RightCreated) != 0 || repeat.Unchanged != 3 {
		t.Fatalf("repeat not idempotent %+v %v", repeat, err)
	}
}
func TestBidirectionalConflictAbortsBeforeEitherDirection(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "new-left.txt", "L")
	write(t, right, "new-right.txt", "R")
	write(t, left, "conflict.txt", "original left")
	write(t, right, "conflict.txt", "original right")
	result, err := ApplyBidirectionalAdditionsFiltered(left, right, nil)
	if err == nil || !strings.Contains(err.Error(), "divergent") || result.Applied || result.Conflicts != 1 || len(result.LeftCreated) != 0 || len(result.RightCreated) != 0 {
		t.Fatalf("conflicting plan copied %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(left, "new-right.txt")); !os.IsNotExist(err) {
		t.Fatal("copied into left despite conflict")
	}
	if _, err := os.Stat(filepath.Join(right, "new-left.txt")); !os.IsNotExist(err) {
		t.Fatal("copied into right despite conflict")
	}
}
func TestBidirectionalPartialFailureReportsCommittedDirection(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "a.txt", "left")
	write(t, right, "z.txt", "right")
	if err := os.Mkdir(filepath.Join(left, "z.txt"), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := ApplyBidirectionalAdditionsFiltered(left, right, nil)
	if err == nil || result.Applied || len(result.RightCreated) != 1 || result.RightCreated[0] != "a.txt" || len(result.LeftCreated) != 0 {
		t.Fatalf("partial result unclear %+v %v", result, err)
	}
	contents, err := os.ReadFile(filepath.Join(right, "a.txt"))
	if err != nil || string(contents) != "left" {
		t.Fatal("successful file not reported")
	}
	info, err := os.Stat(filepath.Join(left, "z.txt"))
	if err != nil || !info.IsDir() {
		t.Fatal("pre-existing directory damaged")
	}
}
func TestBidirectionalCombinedFileLimitAndOverlap(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	if _, err := ApplyBidirectionalAdditionsFiltered(left, left, nil); err == nil {
		t.Fatal("accepted overlapping roots")
	}
	for i := 0; i < MaxAdditions/2+1; i++ {
		name := filepath.Join("batch", strings.Repeat("x", 6)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26)))
		write(t, left, name, "L")
		write(t, right, filepath.Join("other", filepath.Base(name)), "R")
	}
	res, err := ApplyBidirectionalAdditionsFiltered(left, right, nil)
	if err == nil || !strings.Contains(err.Error(), "safety limit") || res.Applied || len(res.LeftCreated)+len(res.RightCreated) != 0 {
		t.Fatalf("combined cap bypass %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(right, "batch")); !os.IsNotExist(err) {
		t.Fatal("partial copy before file-count guard")
	}
}
func TestBidirectionalRejectsSpecialFiles(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	write(t, left, "new.txt", "test")
	if err := os.Symlink(filepath.Join(left, "new.txt"), filepath.Join(right, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	res, err := ApplyBidirectionalAdditionsFiltered(left, right, nil)
	if err == nil || res.Applied {
		t.Fatalf("accepted symlink %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(right, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("committed file despite preflight rejection")
	}
}
