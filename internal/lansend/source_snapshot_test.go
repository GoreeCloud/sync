package lansend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceSecondPassRejectsRestoredMtimeRewrite(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "payload.txt")
	old := []byte("original payload")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := openSenderSource(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	replacement := []byte("replaced payload")
	if len(replacement) != len(old) {
		t.Fatal("test requires equal size")
	}
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if stat, err := os.Stat(path); err != nil || !stat.ModTime().Equal(info.ModTime()) {
		t.Fatalf("mtime restore failed: %v", err)
	}
	if err := verifySourceSecondPass(f, old); err == nil || !strings.Contains(err.Error(), "source content changed") {
		t.Fatalf("mutated bytes accepted: %v", err)
	}
}

func TestSourceSecondPassRejectsAppendAndTruncate(t *testing.T) {
	for _, extra := range []struct{ name, content string }{{"appended", "abcdefghi"}, {"truncated", "abc"}} {
		t.Run(extra.name, func(t *testing.T) {
			dir := privateDir(t)
			p := filepath.Join(dir, "file.txt")
			if err := os.WriteFile(p, []byte("abcdef"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := openSenderSource(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := os.WriteFile(p, []byte(extra.content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifySourceSecondPass(f, []byte("abcdef")); err == nil {
				t.Fatal("changed length accepted")
			}
		})
	}
}

func TestStableSenderSourceRegularAndEmpty(t *testing.T) {
	for _, content := range []string{"", "stable sender contents"} {
		dir := privateDir(t)
		p := filepath.Join(dir, "normal.txt")
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		actual, err := readStableSenderSource(p)
		if err != nil || string(actual) != content {
			t.Fatalf("stable read failed: %v %q", err, actual)
		}
	}
}

func TestStableSenderSourceRejectsSymlink(t *testing.T) {
	dir := privateDir(t)
	src := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(src, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(src, link); err != nil {
		t.Skip(err)
	}
	if _, err := readStableSenderSource(link); err == nil {
		t.Fatal("symlink read succeeded")
	}
}

func TestSourceSecondPassAcceptsUnchangedFile(t *testing.T) {
	// A regular source can be hashed twice through the pinned descriptor.
	dir := privateDir(t)
	p := filepath.Join(dir, "small.bin")
	if err := os.WriteFile(p, []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openSenderSource(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := verifySourceSecondPass(f, []byte("small")); err != nil {
		t.Fatal(err)
	}
}
