package syncplan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Baselines record previously matching file content on two trusted local
// directories. They are immutable checkpoints, not a backup, transfer log,
// deletion authorization or an atomic filesystem snapshot.
const (
	BaselineVersion  = 2
	MaxBaselineFiles = 100000
	MaxBaselineBytes = 16 << 20
)

type BaselineEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Baseline struct {
	Version    int             `json:"version"`
	SourceRoot string          `json:"sourceRoot"`
	TargetRoot string          `json:"targetRoot"`
	Excludes   []string        `json:"excludes"`
	Files      []BaselineEntry `json:"files"`
}

type HistoricalChange struct {
	Path     string `json:"path"`
	Status   string `json:"status"`
	Baseline *File  `json:"baseline,omitempty"`
	Source   *File  `json:"source,omitempty"`
	Target   *File  `json:"target,omitempty"`
}

type HistoricalPlan struct {
	ReadOnly        bool               `json:"readOnly"`
	BaselineVersion int                `json:"baselineVersion"`
	Excludes        []string           `json:"excludes"`
	BaselineFiles   int                `json:"baselineFiles"`
	SourceFiles     int                `json:"sourceFiles"`
	TargetFiles     int                `json:"targetFiles"`
	Conflicts       int                `json:"conflicts"`
	Counts          map[string]int     `json:"counts"`
	Changes         []HistoricalChange `json:"changes"`
}

func normalizedExcludes(excludes []string) ([]string, error) {
	if err := checkExcludes(excludes); err != nil {
		return nil, err
	}
	sorted := append([]string{}, excludes...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, fmt.Errorf("duplicate exclude pattern %q", sorted[i])
		}
	}
	return sorted, nil
}

func validBaselinePath(p string) bool {
	if p == "" || p == "." || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") || !utf8.ValidString(p) || path.Clean(p) != p {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	return true
}

// resolvedRoot identifies the exact local directory path to which a
// historical checkpoint belongs. This is not a stable cross-device identity;
// intentionally moving either root requires a fresh, matching baseline.
func resolvedRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

func validateBaseline(b Baseline) error {
	if b.Version != BaselineVersion {
		return fmt.Errorf("unsupported baseline version %d", b.Version)
	}
	if b.SourceRoot == "" || b.TargetRoot == "" || !filepath.IsAbs(b.SourceRoot) || !filepath.IsAbs(b.TargetRoot) ||
		filepath.Clean(b.SourceRoot) != b.SourceRoot || filepath.Clean(b.TargetRoot) != b.TargetRoot ||
		b.SourceRoot == b.TargetRoot {
		return errors.New("baseline must bind to two distinct canonical absolute folder roots")
	}
	excludes, err := normalizedExcludes(b.Excludes)
	if err != nil {
		return err
	}
	for i := range excludes {
		if b.Excludes[i] != excludes[i] {
			return errors.New("baseline exclusions are not canonical")
		}
	}
	if len(b.Files) > MaxBaselineFiles {
		return fmt.Errorf("baseline exceeds %d files", MaxBaselineFiles)
	}
	prev := ""
	for _, e := range b.Files {
		if !validBaselinePath(e.Path) || e.Path <= prev || e.Size < 0 || len(e.SHA256) != 64 {
			return fmt.Errorf("invalid, unsorted, or duplicated baseline entry %q", e.Path)
		}
		raw, err := hex.DecodeString(e.SHA256)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != e.SHA256 {
			return fmt.Errorf("invalid SHA-256 for %q", e.Path)
		}
		if shouldExclude(e.Path, b.Excludes) {
			return fmt.Errorf("excluded path recorded in baseline %q", e.Path)
		}
		prev = e.Path
	}
	return nil
}

// ensureBaselineOutside prevents a file inside either scanned directory from
// being mistaken for content to synchronize. Output parent must already exist.
func ensureBaselineOutside(source, target, filename string) error {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	actual := filepath.Join(parent, filepath.Base(absolute))
	for _, root := range []string{source, target} {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		rootResolved, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootResolved, actual)
		if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
			return errors.New("baseline file must be stored outside both compared directories")
		}
	}
	return nil
}

// CaptureBaseline captures only a matching pair of complete inventories.
// The snapshot is saved as a 0600 new file, never overwriting a prior baseline.
func CaptureBaseline(source, target, filename string, excludes []string) (Baseline, error) {
	empty := Baseline{}
	if filename == "" {
		return empty, errors.New("baseline output path is required")
	}
	if err := isolatedRoots(source, target); err != nil {
		return empty, err
	}
	sortedExcludes, err := normalizedExcludes(excludes)
	if err != nil {
		return empty, err
	}
	if err := ensureBaselineOutside(source, target, filename); err != nil {
		return empty, err
	}
	plan, err := CompareFiltered(source, target, sortedExcludes)
	if err != nil {
		return empty, err
	}
	if plan.SourceOnly != 0 || plan.TargetOnly != 0 || plan.Different != 0 {
		return empty, errors.New("cannot capture baseline: source and target are not identical")
	}
	if plan.Identical > MaxBaselineFiles {
		return empty, errors.New("baseline file count exceeds limit")
	}
	sourceRoot, err := resolvedRoot(source)
	if err != nil {
		return empty, err
	}
	targetRoot, err := resolvedRoot(target)
	if err != nil {
		return empty, err
	}
	b := Baseline{Version: BaselineVersion, SourceRoot: sourceRoot, TargetRoot: targetRoot, Excludes: sortedExcludes, Files: make([]BaselineEntry, 0, plan.Identical)}
	for _, c := range plan.Changes {
		b.Files = append(b.Files, BaselineEntry{Path: c.Path, Size: c.Source.Size, SHA256: c.Source.SHA256})
	}
	if err := validateBaseline(b); err != nil {
		return empty, err
	}
	payload, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return empty, err
	}
	payload = append(payload, '\n')
	if len(payload) > MaxBaselineBytes {
		return empty, errors.New("baseline JSON exceeds size limit")
	}
	// Hardlinking a private staging file into place avoids overwriting an
	// existing baseline. Link support is required, as in additions-only mode.
	parent := filepath.Dir(filename)
	tmp, err := os.CreateTemp(parent, ".gcsync-baseline-")
	if err != nil {
		return empty, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return empty, err
	}
	_, err = tmp.Write(payload)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return empty, err
	}
	// Never follow a target symbolic link or replace an existing file.
	if err := os.Link(tmp.Name(), filename); err != nil {
		return empty, fmt.Errorf("baseline not created (existing file or unsupported link): %w", err)
	}
	dir, err := os.Open(parent)
	if err != nil {
		return b, fmt.Errorf("baseline created; directory sync unavailable: %w", err)
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return b, fmt.Errorf("baseline created; directory persistence uncertain: %w", err)
	}
	return b, nil
}

func LoadBaseline(filename string) (Baseline, error) {
	var empty Baseline
	info, err := os.Lstat(filename)
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBaselineBytes || info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("baseline must be a private regular file (0600) within size limit")
	}
	f, err := os.Open(filename)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	handle, err := f.Stat()
	if err != nil || !os.SameFile(info, handle) {
		return empty, errors.New("baseline changed before read")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBaselineBytes+1))
	if err != nil {
		return empty, err
	}
	if len(data) > MaxBaselineBytes {
		return empty, errors.New("baseline exceeds size limit")
	}
	after, err := os.Lstat(filename)
	if err != nil || !os.SameFile(handle, after) || !after.Mode().IsRegular() || !after.ModTime().Equal(info.ModTime()) || int64(len(data)) != info.Size() {
		return empty, errors.New("baseline changed during read")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return empty, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return empty, errors.New("baseline has trailing JSON data")
	}
	if err := validateBaseline(b); err != nil {
		return empty, err
	}
	return b, nil
}

func sameFile(a, b File) bool { return a.Size == b.Size && a.SHA256 == b.SHA256 }

// CompareHistorical is a read-only three-way comparison. It is deliberately
// unable to propagate deletion, overwrite files, merge or apply conflicts.
func CompareHistorical(source, target, baselineFile string, excludes []string) (HistoricalPlan, error) {
	result := HistoricalPlan{ReadOnly: true, Counts: map[string]int{}, Changes: []HistoricalChange{}}
	if err := isolatedRoots(source, target); err != nil {
		return result, err
	}
	sorted, err := normalizedExcludes(excludes)
	if err != nil {
		return result, err
	}
	if err := ensureBaselineOutside(source, target, baselineFile); err != nil {
		return result, err
	}
	b, err := LoadBaseline(baselineFile)
	if err != nil {
		return result, err
	}
	sourceRoot, err := resolvedRoot(source)
	if err != nil {
		return result, err
	}
	targetRoot, err := resolvedRoot(target)
	if err != nil {
		return result, err
	}
	if sourceRoot != b.SourceRoot || targetRoot != b.TargetRoot {
		return result, errors.New("folder roots or their orientation differ from the immutable baseline")
	}
	if len(sorted) != len(b.Excludes) {
		return result, errors.New("exclusion patterns differ from saved baseline; refusing misleading comparison")
	}
	for i := range sorted {
		if sorted[i] != b.Excludes[i] {
			return result, errors.New("exclusion patterns differ from saved baseline; refusing misleading comparison")
		}
	}
	src, err := inventory(source, sorted)
	if err != nil {
		return result, fmt.Errorf("source inventory: %w", err)
	}
	dst, err := inventory(target, sorted)
	if err != nil {
		return result, fmt.Errorf("target inventory: %w", err)
	}
	result.BaselineVersion = BaselineVersion
	result.Excludes = sorted
	result.SourceFiles = len(src)
	result.TargetFiles = len(dst)
	result.BaselineFiles = len(b.Files)
	old := make(map[string]File, len(b.Files))
	keys := make(map[string]struct{}, len(b.Files)+len(src)+len(dst))
	for _, entry := range b.Files {
		old[entry.Path] = File{Size: entry.Size, SHA256: entry.SHA256}
		keys[entry.Path] = struct{}{}
	}
	for p := range src {
		keys[p] = struct{}{}
	}
	for p := range dst {
		keys[p] = struct{}{}
	}
	sortedKeys := make([]string, 0, len(keys))
	for p := range keys {
		sortedKeys = append(sortedKeys, p)
	}
	sort.Strings(sortedKeys)
	for _, p := range sortedKeys {
		base, hasBase := old[p]
		left, hasLeft := src[p]
		right, hasRight := dst[p]
		c := HistoricalChange{Path: p}
		if hasBase {
			c.Baseline = &base
		}
		if hasLeft {
			c.Source = &left
		}
		if hasRight {
			c.Target = &right
		}
		switch {
		case !hasLeft && !hasRight:
			c.Status = "deleted-both"
		case hasLeft && hasRight && sameFile(left, right):
			if hasBase && sameFile(left, base) {
				c.Status = "unchanged"
			} else {
				c.Status = "converged"
			}
		case !hasBase && hasLeft && hasRight:
			c.Status = "conflict-add-add"
		case !hasBase && hasLeft:
			c.Status = "source-added"
		case !hasBase:
			c.Status = "target-added"
		case hasLeft && hasRight:
			if sameFile(left, base) {
				c.Status = "target-modified"
			} else if sameFile(right, base) {
				c.Status = "source-modified"
			} else {
				c.Status = "conflict-modify-modify"
			}
		case hasLeft:
			if sameFile(left, base) {
				c.Status = "target-deleted"
			} else {
				c.Status = "conflict-modify-delete"
			}
		default:
			if sameFile(right, base) {
				c.Status = "source-deleted"
			} else {
				c.Status = "conflict-modify-delete"
			}
		}
		if strings.HasPrefix(c.Status, "conflict-") {
			result.Conflicts++
		}
		result.Counts[c.Status]++
		result.Changes = append(result.Changes, c)
	}
	return result, nil
}
