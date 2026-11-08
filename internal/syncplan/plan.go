// Package syncplan implements a deterministic, strictly read-only local
// directory comparison. It is not network synchronization or a backup engine.
package syncplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type File struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Change struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Source *File  `json:"source,omitempty"`
	Target *File  `json:"target,omitempty"`
}

type Plan struct {
	ReadOnly    bool     `json:"readOnly"`
	SourceFiles int      `json:"sourceFiles"`
	TargetFiles int      `json:"targetFiles"`
	Identical   int      `json:"identical"`
	SourceOnly  int      `json:"sourceOnly"`
	TargetOnly  int      `json:"targetOnly"`
	Different   int      `json:"different"`
	Changes     []Change `json:"changes"`
}

func inventory(root string, excludes []string) (map[string]File, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("root must be a real directory: %s", root)
	}
	files := make(map[string]File)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		// An interrupted no-overwrite copy may leave a private staging inode.
		// This namespace is reserved: never copy a crash residue as user data,
		// even if an exclusion pattern would otherwise hide it. Require manual
		// inspection and cleanup instead of silently propagating it.
		if rel != "." && strings.HasPrefix(entry.Name(), ".gcsync-stage-") {
			return fmt.Errorf("possible interrupted Sync staging artifact requires manual review: %s", path)
		}
		if rel != "." && shouldExclude(filepath.ToSlash(rel), excludes) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("special file unsupported: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		before, err := entry.Info()
		if err != nil {
			return err
		}
		f, err := openRegularWithinRoot(root, rel)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, readErr := io.Copy(h, f)
		openedInfo, statErr := f.Stat()
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if statErr != nil {
			return statErr
		}
		after, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(before, openedInfo) || !os.SameFile(openedInfo, after) || !after.Mode().IsRegular() || n != before.Size() || n != after.Size() || !before.ModTime().Equal(after.ModTime()) || !openedInfo.ModTime().Equal(after.ModTime()) {
			return fmt.Errorf("file changed during comparison: %s", path)
		}
		files[filepath.ToSlash(rel)] = File{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
		return nil
	})
	return files, err
}

// Compare summarizes two local directories without writing to either.
// No automatic decision is made about divergent contents or deletions.
func Compare(source, target string) (Plan, error) {
	return CompareFiltered(source, target, nil)
}

// CompareFiltered excludes only user-specified glob patterns from both
// inventories. It never writes files. No patterns are enabled by default.
func CompareFiltered(source, target string, excludes []string) (Plan, error) {
	plan := Plan{ReadOnly: true, Changes: []Change{}}
	if err := checkExcludes(excludes); err != nil {
		return plan, err
	}
	a, err := inventory(source, excludes)
	if err != nil {
		return plan, fmt.Errorf("source inventory: %w", err)
	}
	b, err := inventory(target, excludes)
	if err != nil {
		return plan, fmt.Errorf("target inventory: %w", err)
	}
	plan.SourceFiles, plan.TargetFiles = len(a), len(b)
	keys := make([]string, 0, len(a)+len(b))
	seen := make(map[string]bool)
	for name := range a {
		keys = append(keys, name)
		seen[name] = true
	}
	for name := range b {
		if !seen[name] {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	for _, name := range keys {
		left, hasLeft := a[name]
		right, hasRight := b[name]
		change := Change{Path: name}
		switch {
		case !hasLeft:
			change.Status = "target-only"
			change.Target = &right
			plan.TargetOnly++
		case !hasRight:
			change.Status = "source-only"
			change.Source = &left
			plan.SourceOnly++
		case left.Size == right.Size && left.SHA256 == right.SHA256:
			change.Status = "identical"
			change.Source = &left
			change.Target = &right
			plan.Identical++
		default:
			change.Status = "different"
			change.Source = &left
			change.Target = &right
			plan.Different++
		}
		plan.Changes = append(plan.Changes, change)
	}
	return plan, nil
}
