package syncplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The initial additive copy mode is intentionally small and bounded. It does
// not implement two-way synchronization, overwrite, deletion or versioning.
const (
	MaxAdditions           = 1024
	MaxAdditionBytes int64 = 1 << 30
)

// ApplyResult describes the changes that were actually committed to the
// destination. In a partial failure, Created may contain already-added files;
// existing target files are never intentionally overwritten or removed.
type ApplyResult struct {
	Mode         string   `json:"mode"`
	Applied      bool     `json:"applied"`
	Created      []string `json:"created"`
	BytesWritten int64    `json:"bytesWritten"`
	Unchanged    int      `json:"unchanged"`
	TargetOnly   int      `json:"targetOnly"`
	Conflicts    int      `json:"conflicts"`
}

// isolatedRoots rejects a source equal to or nested in the target, and vice
// versa. This avoids recursively copying into the source or from the target.
func isolatedRoots(source, target string) error {
	a, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	b, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	a, err = filepath.EvalSymlinks(a)
	if err != nil {
		return err
	}
	b, err = filepath.EvalSymlinks(b)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
			return fmt.Errorf("source and target directories must not overlap")
		}
	}
	return nil
}

// ensureDirs creates only absent directories with 0700 permissions and never
// deliberately traverses an existing symlink. Caller must use a source-verified
// relative path. As with most portable path-based APIs, this does not protect
// against an attacker who can concurrently modify parent directories.
func ensureDirs(root, relativeDir string) error {
	dir := root
	if relativeDir == "." || relativeDir == "" {
		return nil
	}
	for _, part := range strings.Split(relativeDir, string(filepath.Separator)) {
		if part == "." || part == ".." || part == "" {
			return errors.New("invalid path component")
		}
		dir = filepath.Join(dir, part)
		fi, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			fi, err = os.Lstat(dir)
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe destination directory: %s", dir)
		}
	}
	return nil
}

func verifySourceHandle(src *os.File, name string, initial os.FileInfo) error {
	handle, err := src.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !initial.Mode().IsRegular() || !handle.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(initial, handle) || !os.SameFile(handle, current) ||
		initial.Size() != handle.Size() || !initial.ModTime().Equal(handle.ModTime()) ||
		handle.Size() != current.Size() || !handle.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("source changed while copying: %s", name)
	}
	return nil
}

// copyOneAtomic stages a previously inventoried regular source file and
// publishes it with a no-overwrite hardlink. Linux/Android destinations use
// descriptor-relative operations; other OSes have a path-based fallback.
// It never intentionally deletes or overwrites user files. An adversary able
// to rename already-open directories is still outside the trust model.
func copyOneAtomic(source, target string, change Change) (int64, bool, error) {
	if change.Source == nil || change.Status != "source-only" {
		return 0, false, errors.New("not a source-only addition")
	}
	rel := filepath.FromSlash(change.Path)
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return 0, false, errors.New("unsafe relative path")
	}
	from := filepath.Join(source, rel)
	// Read-time verification prevents publishing a stale plan if a file was
	// replaced, modified, truncated, or had its pathname turned into a link.
	initial, err := os.Lstat(from)
	if err != nil {
		return 0, false, err
	}
	if !initial.Mode().IsRegular() || initial.Size() != change.Source.Size {
		return 0, false, fmt.Errorf("source type/size changed: %s", change.Path)
	}
	src, err := openRegularWithinRoot(source, rel)
	if err != nil {
		return 0, false, err
	}
	defer src.Close()
	if err := verifySourceHandle(src, from, initial); err != nil {
		return 0, false, err
	}
	stage, err := newStagedTarget(target, rel)
	if err != nil {
		return 0, false, err
	}
	defer stage.cleanup()
	h := sha256.New()
	n, cpErr := io.Copy(io.MultiWriter(stage.file, h), src)
	if cpErr == nil && (n != change.Source.Size || hex.EncodeToString(h.Sum(nil)) != change.Source.SHA256) {
		cpErr = fmt.Errorf("source checksum changed while copying: %s", change.Path)
	}
	if cpErr == nil {
		cpErr = verifySourceHandle(src, from, initial)
	}
	if cpErr == nil {
		cpErr = stage.file.Sync()
	}
	if closeErr := stage.file.Close(); cpErr == nil {
		cpErr = closeErr
	}
	if cpErr != nil {
		return 0, false, cpErr
	}
	// The destination implementation owns the staging directory descriptor.
	// Commit is always an atomic no-replace hardlink, never os.Rename.
	committed, commitErr := stage.commit()
	if commitErr != nil {
		if committed {
			return n, true, fmt.Errorf("file created but final directory sync failed: %w", commitErr)
		}
		return 0, false, commitErr
	}
	return n, true, nil
}

// ApplyAdditions performs explicit, conflict-blocking, additions-only local
// replication. Every existing target path is preserved. It does not perform
// deletions, conflict resolution, network replication or continuous syncing.
// If an error occurs after some additions, the Created result is partial.
func ApplyAdditions(source, target string) (ApplyResult, error) {
	return ApplyAdditionsFiltered(source, target, nil)
}

// ApplyAdditionsFiltered applies only files included by the validated patterns.
// Excludes are explicit and shared by both source and destination inventories.
func ApplyAdditionsFiltered(source, target string, excludes []string) (ApplyResult, error) {
	result := ApplyResult{Mode: "additions-only", Applied: false, Created: []string{}}
	if err := isolatedRoots(source, target); err != nil {
		return result, err
	}
	plan, err := CompareFiltered(source, target, excludes)
	if err != nil {
		return result, err
	}
	result.Unchanged, result.TargetOnly, result.Conflicts = plan.Identical, plan.TargetOnly, plan.Different
	// Any same-path difference requires an explicit conflict decision. Abort
	// the full batch BEFORE creating new files or directories.
	if plan.Different != 0 {
		return result, fmt.Errorf("refusing to apply additions while %d divergent paths exist", plan.Different)
	}
	if plan.SourceOnly > MaxAdditions {
		return result, fmt.Errorf("too many additions: %d (maximum %d)", plan.SourceOnly, MaxAdditions)
	}
	var bytes int64
	for _, change := range plan.Changes {
		if change.Status != "source-only" {
			continue
		}
		if change.Source.Size > MaxAdditionBytes-bytes {
			return result, fmt.Errorf("additions exceed %d-byte safety limit", MaxAdditionBytes)
		}
		bytes += change.Source.Size
	}
	for _, change := range plan.Changes {
		if change.Status != "source-only" {
			continue
		}
		n, committed, err := copyOneAtomic(source, target, change)
		if committed {
			result.BytesWritten += n
			result.Created = append(result.Created, change.Path)
		}
		if err != nil {
			return result, err
		}
	}
	result.Applied = true
	return result, nil
}
