package syncplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareFilteredExplicitAndSymmetric(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "secrets/credentials.txt", "never copy")
	write(t, source, "cache/log.tmp", "skip")
	write(t, source, "notes/a.txt", "include")
	write(t, target, "secrets/credentials.txt", "existing-but-different")
	write(t, target, "cache/log.tmp", "existing-but-different")
	unfiltered, err := Compare(source, target)
	if err != nil || unfiltered.Different != 2 || unfiltered.SourceOnly != 1 {
		t.Fatalf("unexpected unfiltered plan: %+v %v", unfiltered, err)
	}
	excluded := []string{"secrets/**", "*.tmp"}
	plan, err := CompareFiltered(source, target, excluded)
	if err != nil || plan.Different != 0 || plan.SourceOnly != 1 || len(plan.Changes) != 1 || plan.Changes[0].Path != "notes/a.txt" {
		t.Fatalf("unexpected filtered plan: %+v %v", plan, err)
	}
	done, err := ApplyAdditionsFiltered(source, target, excluded)
	if err != nil || !done.Applied || len(done.Created) != 1 || done.Created[0] != "notes/a.txt" {
		t.Fatalf("unexpected filtered application: %+v %v", done, err)
	}
	for _, file := range []string{"secrets/credentials.txt", "cache/log.tmp"} {
		data, err := os.ReadFile(filepath.Join(target, file))
		if err != nil || string(data) != "existing-but-different" {
			t.Fatalf("excluded target changed: %s %v", file, err)
		}
	}
}

func TestExcludeGrammarAndValidation(t *testing.T) {
	good := []string{"*.tmp", "private/**", "build/*.o", "notes.txt", ".git", "backup-??.zip"}
	for _, p := range good {
		if err := ValidateExclude(p); err != nil {
			t.Fatalf("valid pattern %q: %v", p, err)
		}
	}
	bad := []string{"", ".", "../data", "a/../b", "/absolute", "a\\b", "a//b", "a/**/b", "**", "a/[", "a/", "./b", "a/./b", "a["}
	for _, p := range bad {
		if err := ValidateExclude(p); err == nil {
			t.Fatalf("invalid pattern accepted: %q", p)
		}
	}
	source, target := t.TempDir(), t.TempDir()
	_, err := ApplyAdditionsFiltered(source, target, []string{"../unsafe"})
	if err == nil {
		t.Fatal("invalid pattern must abort before copying")
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = "*.tmp"
	}
	if _, err := CompareFiltered(source, target, tooMany); err == nil {
		t.Fatal("pattern count limit was bypassed")
	}
}

func TestExcludeDoesNotFollowIgnoredSymlink(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	write(t, source, "publish.txt", "safe")
	if err := os.Symlink("/outside", filepath.Join(source, "secret-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Compare(source, target); err == nil {
		t.Fatal("unfiltered symlink unexpectedly accepted")
	}
	plan, err := CompareFiltered(source, target, []string{"secret-link"})
	if err != nil || plan.SourceOnly != 1 || !strings.EqualFold(plan.Changes[0].Path, "publish.txt") {
		t.Fatalf("excluded symlink should not be copied/traversed: %+v %v", plan, err)
	}
}
