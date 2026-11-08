package syncplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestHistoricalDetectsEditsDeletionsAndConflicts(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "source"), filepath.Join(root, "target")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dst, 0700); err != nil {
		t.Fatal(err)
	}
	orig := []string{"unchanged.txt", "converged.txt", "src-mod.txt", "dst-mod.txt", "both-deleted.txt", "src-deleted.txt", "dst-deleted.txt", "mod-mod.txt", "mod-del-1.txt", "mod-del-2.txt"}
	for _, p := range orig {
		write(t, src, p, "old")
		write(t, dst, p, "old")
	}
	bpath := filepath.Join(root, "baseline.json")
	b, err := CaptureBaseline(src, dst, bpath, nil)
	if err != nil || b.Version != 2 || len(b.Files) != len(orig) {
		t.Fatalf("capture: %+v %v", b, err)
	}
	loaded, err := LoadBaseline(bpath)
	if err != nil || !reflect.DeepEqual(b, loaded) {
		t.Fatalf("roundtrip: %v", err)
	}
	if fi, err := os.Stat(bpath); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("baseline should be private")
	}
	write(t, src, "converged.txt", "same new")
	write(t, dst, "converged.txt", "same new")
	write(t, src, "src-mod.txt", "source new")
	write(t, dst, "dst-mod.txt", "target new")
	for _, p := range []string{"both-deleted.txt", "src-deleted.txt", "mod-del-2.txt"} {
		os.Remove(filepath.Join(src, p))
	}
	for _, p := range []string{"both-deleted.txt", "dst-deleted.txt", "mod-del-1.txt"} {
		os.Remove(filepath.Join(dst, p))
	}
	write(t, src, "mod-mod.txt", "source changed")
	write(t, dst, "mod-mod.txt", "target changed")
	write(t, src, "mod-del-1.txt", "source changed before target deletion")
	write(t, dst, "mod-del-2.txt", "target changed before source deletion")
	write(t, src, "source-add.txt", "alone")
	write(t, dst, "target-add.txt", "alone")
	write(t, src, "same-add.txt", "new same")
	write(t, dst, "same-add.txt", "new same")
	write(t, src, "conflict-add.txt", "left")
	write(t, dst, "conflict-add.txt", "right")
	plan, err := CompareHistorical(src, dst, bpath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadOnly || plan.Conflicts != 4 || plan.BaselineFiles != len(orig) || plan.SourceFiles != 10 || plan.TargetFiles != 10 {
		t.Fatalf("unexpected summary: %+v", plan)
	}
	expected := map[string]string{
		"unchanged.txt": "unchanged", "converged.txt": "converged", "src-mod.txt": "source-modified", "dst-mod.txt": "target-modified",
		"both-deleted.txt": "deleted-both", "src-deleted.txt": "source-deleted", "dst-deleted.txt": "target-deleted",
		"mod-mod.txt": "conflict-modify-modify", "mod-del-1.txt": "conflict-modify-delete", "mod-del-2.txt": "conflict-modify-delete",
		"source-add.txt": "source-added", "target-add.txt": "target-added", "same-add.txt": "converged", "conflict-add.txt": "conflict-add-add",
	}
	if len(plan.Changes) != len(expected) {
		t.Fatalf("got %d changes, want %d", len(plan.Changes), len(expected))
	}
	prev := ""
	for _, c := range plan.Changes {
		if c.Path <= prev || c.Status != expected[c.Path] {
			t.Errorf("misclassified or unsorted: %+v", c)
		}
		prev = c.Path
	}
	for status, count := range map[string]int{"converged": 2, "conflict-modify-delete": 2, "unchanged": 1, "deleted-both": 1, "source-modified": 1, "target-modified": 1, "source-deleted": 1, "target-deleted": 1, "source-added": 1, "target-added": 1, "conflict-add-add": 1, "conflict-modify-modify": 1} {
		if plan.Counts[status] != count {
			t.Errorf("status %q count %d want %d", status, plan.Counts[status], count)
		}
	}
	after, err := os.ReadFile(bpath)
	if err != nil || !bytes.Contains(after, []byte("\"version\": 2")) {
		t.Fatal("baseline altered")
	}
	if _, err := CaptureBaseline(src, dst, filepath.Join(root, "rebaseline.json"), nil); err == nil {
		t.Fatal("captured baseline from divergent pair")
	}
	if _, err := CaptureBaseline(src, dst, bpath, nil); err == nil {
		t.Fatal("overwrote baseline")
	}
}

func TestHistoricalFiltersAndCanonicalExclusions(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "source"), filepath.Join(root, "target")
	os.Mkdir(src, 0700)
	os.Mkdir(dst, 0700)
	write(t, src, "data.txt", "equal")
	write(t, dst, "data.txt", "equal")
	write(t, src, "private/x.txt", "secret one")
	write(t, dst, "private/x.txt", "secret two")
	write(t, src, "cache.tmp", "a")
	write(t, dst, "cache.tmp", "b")
	bfile := filepath.Join(root, "baseline.json")
	b, err := CaptureBaseline(src, dst, bfile, []string{"private/**", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 1 || !sort.StringsAreSorted(b.Excludes) {
		t.Fatal("filter not normalized")
	}
	plan, err := CompareHistorical(src, dst, bfile, []string{"*.tmp", "private/**"})
	if err != nil || len(plan.Changes) != 1 || plan.Changes[0].Status != "unchanged" {
		t.Fatalf("unexpected plan: %+v, %v", plan, err)
	}
	if _, err := CompareHistorical(src, dst, bfile, nil); err == nil {
		t.Fatal("accepted changed exclusions")
	}
	if _, err := CaptureBaseline(src, dst, filepath.Join(root, "bad.json"), []string{"private/**", "private/**"}); err == nil {
		t.Fatal("accepted duplicate excludes")
	}
}

func TestBaselineRejectsUnsafeFilesAndUnexpectedFields(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "source"), filepath.Join(root, "target")
	os.Mkdir(src, 0700)
	os.Mkdir(dst, 0700)
	write(t, src, "safe.txt", "ok")
	write(t, dst, "safe.txt", "ok")
	// Cannot save the checkpoint inside an inventoried tree.
	if _, err := CaptureBaseline(src, dst, filepath.Join(src, "manifest.json"), nil); err == nil {
		t.Fatal("allowed baseline inside source")
	}
	if _, err := CaptureBaseline(src, dst, filepath.Join(dst, "manifest.json"), nil); err == nil {
		t.Fatal("allowed baseline inside target")
	}
	p := filepath.Join(root, "baseline.json")
	b, err := CaptureBaseline(src, dst, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureBaseline(src, dst, p, nil); err == nil {
		t.Fatal("overwrote existing checkpoint")
	}
	orig, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "symlink.json")
	if err := os.Symlink(p, link); err == nil {
		if _, err := LoadBaseline(link); err == nil {
			t.Fatal("followed symlink checkpoint")
		}
	}
	for _, body := range [][]byte{append(append([]byte{}, orig...), []byte("{}")...), []byte(`{"version": 2, "excludes": [], "files": [], "surprise": true}`), []byte(`{"version": 500, "excludes": [], "files": []}`), []byte(`not json`)} {
		testPath := filepath.Join(root, "bad.json")
		os.WriteFile(testPath, body, 0600)
		if _, err := LoadBaseline(testPath); err == nil {
			t.Fatalf("accepted invalid baseline %s", body)
		}
	}
	// An untrusted baseline must never be interpreted as a traversal path.
	for _, path := range []string{"../out", "/etc/passwd", "./x", "a//b", "a/../b", "a\\b", ""} {
		mutated := b
		mutated.Files = []BaselineEntry{{Path: path, Size: 1, SHA256: strings.Repeat("a", 64)}}
		body, _ := json.Marshal(mutated)
		os.WriteFile(filepath.Join(root, "bad.json"), body, 0600)
		if _, err := LoadBaseline(filepath.Join(root, "bad.json")); err == nil {
			t.Errorf("accepted unsafe baseline path %q", path)
		}
	}
	badPerm := filepath.Join(root, "open.json")
	if err := os.WriteFile(badPerm, orig, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(badPerm); err == nil {
		t.Fatal("accepted non-private baseline")
	}
}

func TestHistoricalEmptyAndMissingBaseline(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "source"), filepath.Join(root, "target")
	os.Mkdir(src, 0700)
	os.Mkdir(dst, 0700)
	p := filepath.Join(root, "baseline.json")
	if _, err := CompareHistorical(src, dst, p, nil); err == nil {
		t.Fatal("accepted missing baseline")
	}
	if _, err := CaptureBaseline(src, dst, p, nil); err != nil {
		t.Fatal(err)
	}
	plan, err := CompareHistorical(src, dst, p, nil)
	if err != nil || !plan.ReadOnly || len(plan.Changes) != 0 || plan.BaselineFiles != 0 {
		t.Fatalf("bad empty history %+v: %v", plan, err)
	}
}

// Historical classifications are meaningful only for the exact original pair
// of folders. Swapping the sides reverses deletion semantics; using an old
// checkpoint on unrelated data could incorrectly suggest destructive action.
func TestHistoricalRefusesSwappedOrDifferentRoots(t *testing.T) {
	root := t.TempDir()
	src, dst, other := filepath.Join(root, "source"), filepath.Join(root, "target"), filepath.Join(root, "other")
	for _, dir := range []string{src, dst, other} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		write(t, dir, "example.txt", "same")
	}
	baseline := filepath.Join(root, "history.json")
	if _, err := CaptureBaseline(src, dst, baseline, nil); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{dst, src}, {src, other}, {other, dst}} {
		if _, err := CompareHistorical(pair[0], pair[1], baseline, nil); err == nil || !strings.Contains(err.Error(), "differ from") {
			t.Errorf("accepted wrong baseline root pairing %q %q: %v", pair[0], pair[1], err)
		}
	}
	if _, err := CompareHistorical(src, dst, baseline, nil); err != nil {
		t.Fatal(err)
	}
	// A checkpoint with removed or relative path identity cannot be trusted.
	b, err := LoadBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalidRoot := range []string{"", "relative/root", "../source"} {
		modified := b
		modified.SourceRoot = invalidRoot
		data, _ := json.Marshal(modified)
		p := filepath.Join(root, "invalid.json")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBaseline(p); err == nil {
			t.Errorf("accepted invalid baseline root %q", invalidRoot)
		}
	}
}
