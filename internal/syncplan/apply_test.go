package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyAdditionsCopiesNewFilesWithoutChangingExistingData(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "new/nested/report.txt", "new content")
	write(t, source, "unchanged.txt", "do not rewrite")
	write(t, target, "unchanged.txt", "do not rewrite")
	write(t, target, "target-only.txt", "preserve target data")
	orig, err := os.Stat(filepath.Join(target, "unchanged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := ApplyAdditions(source, target)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Applied || len(outcome.Created) != 1 || outcome.Created[0] != "new/nested/report.txt" || outcome.BytesWritten != int64(len("new content")) || outcome.Unchanged != 1 || outcome.TargetOnly != 1 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	got, err := os.ReadFile(filepath.Join(target, "new", "nested", "report.txt"))
	if err != nil || string(got) != "new content" {
		t.Fatalf("copy: %s %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(target, "new", "nested", "report.txt"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("new file permissions: %v %v", fi, err)
	}
	got, err = os.ReadFile(filepath.Join(target, "target-only.txt"))
	if err != nil || string(got) != "preserve target data" {
		t.Fatal("target-only data modified")
	}
	after, _ := os.Stat(filepath.Join(target, "unchanged.txt"))
	if !os.SameFile(orig, after) {
		t.Fatal("identical file unexpectedly replaced")
	}
	repeat, err := ApplyAdditions(source, target)
	if err != nil || !repeat.Applied || len(repeat.Created) != 0 || repeat.Unchanged != 2 {
		t.Fatalf("idempotent rerun failed: %+v %v", repeat, err)
	}
	files, _ := os.ReadDir(filepath.Join(target, "new", "nested"))
	if len(files) != 1 || files[0].Name() != "report.txt" {
		t.Fatalf("staging artifacts remained: %v", files)
	}
}

func TestApplyAdditionsRejectsDivergentFilesBeforeWriting(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "a-new.txt", "should not copy")
	write(t, source, "conflict.txt", "source")
	write(t, target, "conflict.txt", "target")
	report, err := ApplyAdditions(source, target)
	if err == nil || !strings.Contains(err.Error(), "divergent") || report.Applied || report.Conflicts != 1 || len(report.Created) != 0 {
		t.Fatalf("conflicting batch unexpectedly accepted %+v %v", report, err)
	}
	if _, err := os.Lstat(filepath.Join(target, "a-new.txt")); !os.IsNotExist(err) {
		t.Fatal("partial copy occurred despite preflight conflict")
	}
	got, _ := os.ReadFile(filepath.Join(target, "conflict.txt"))
	if string(got) != "target" {
		t.Fatal("overwrote target")
	}
}

func TestApplyAdditionsRejectsOverlapAndSymlinks(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "sample.txt", "value")
	if _, err := ApplyAdditions(source, source); err == nil {
		t.Fatal("identical roots allowed")
	}
	nested := filepath.Join(source, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyAdditions(source, nested); err == nil {
		t.Fatal("nested target allowed")
	}
	if _, err := ApplyAdditions(nested, source); err == nil {
		t.Fatal("nested source allowed")
	}
	if err := os.Symlink(source, filepath.Join(target, "symbolic")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := ApplyAdditions(source, target); err == nil {
		t.Fatal("symlink target allowed")
	}
}

func TestCopyOneAtomicRejectsChangedHashAndExistingTarget(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "item.txt", "original")
	p, err := Compare(source, target)
	if err != nil {
		t.Fatal(err)
	}
	write(t, source, "item.txt", "tampered") // same byte count, but different hash
	if _, _, err := copyOneAtomic(source, target, p.Changes[0]); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("stale content accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "item.txt")); !os.IsNotExist(err) {
		t.Fatal("failed copy left data")
	}
	files, _ := os.ReadDir(target)
	if len(files) != 0 {
		t.Fatalf("staging file left after checksum failure: %v", files)
	}
	write(t, target, "item.txt", "important target data")
	if _, _, err := copyOneAtomic(source, target, p.Changes[0]); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrote existing target: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "item.txt"))
	if string(got) != "important target data" {
		t.Fatal("existing file corrupted")
	}
}

func TestApplyAdditionsEmptyFileAndLimit(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "empty.bin", "")
	out, err := ApplyAdditions(source, target)
	if err != nil || !out.Applied || len(out.Created) != 1 || out.BytesWritten != 0 {
		t.Fatalf("empty file: %+v %v", out, err)
	}
	info, err := os.Stat(filepath.Join(target, "empty.bin"))
	if err != nil || info.Size() != 0 {
		t.Fatal("empty file not copied")
	}
	for i := 0; i <= MaxAdditions; i++ { // keep the limit test bounded and deterministic
		write(t, source, filepath.Join("bulk", strings.Repeat("x", 6)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/(26*26))%26))), "")
	}
	out, err = ApplyAdditions(source, target)
	if err == nil || !strings.Contains(err.Error(), "too many additions") || len(out.Created) != 0 {
		t.Fatalf("limit bypass: created=%d err=%v", len(out.Created), err)
	}
}

func TestApplyAdditionsPartialFailureReportsCommittedFiles(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "a-first.txt", "first")
	write(t, source, "z-directory-conflict", "second")
	// The target has a directory where source has a regular file. The
	// inventory does not count empty directories as files, so apply must
	// detect the collision and report the preceding successful copy.
	if err := os.Mkdir(filepath.Join(target, "z-directory-conflict"), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := ApplyAdditions(source, target)
	if err == nil || result.Applied || len(result.Created) != 1 || result.Created[0] != "a-first.txt" || result.BytesWritten != 5 {
		t.Fatalf("partial status not honest: %+v %v", result, err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "a-first.txt"))
	if string(got) != "first" {
		t.Fatal("partial commit missing")
	}
	st, err := os.Stat(filepath.Join(target, "z-directory-conflict"))
	if err != nil || !st.IsDir() {
		t.Fatal("destination directory damaged")
	}
}

func TestCopyOneAtomicRejectsTraversalFromUntrustedPlan(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	for _, name := range []string{"../escape.txt", "/tmp/absolute.txt", "../../outside"} {
		change := Change{Path: name, Status: "source-only", Source: &File{Size: 0}}
		_, committed, err := copyOneAtomic(source, target, change)
		if err == nil || committed {
			t.Fatalf("unsafe path %q was accepted: %v", name, err)
		}
	}
}
