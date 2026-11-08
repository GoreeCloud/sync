package syncplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

// ContinuousAdditionsEvent records an initial local snapshot, an applied
// no-overwrite batch, or a fail-closed stop. Only durable foreground Sync
// emits these events in the current CLI implementation.
type ContinuousAdditionsEvent struct {
	Type          string                       `json:"type"`
	Sequence      uint64                       `json:"sequence"`
	ObservedAt    time.Time                    `json:"observedAt"`
	Mode          string                       `json:"mode"`
	AdditionsOnly bool                         `json:"additionsOnly"`
	Result        BidirectionalAdditionsResult `json:"result"`
	Error         string                       `json:"error,omitempty"`
}

// DurableVersion is the experimental, local-only, fail-closed journal format.
// States do not authorize deletion, overwrite, merge, or remote replication.
const DurableVersion = 2

// DurableState is an integrity-checked, versioned checkpoint. The checksum
// detects accidental corruption, NOT a malicious local user who can edit it.
// The same canonical root pair and exclusion rules must be used on every run.
// A pending phase is intentionally NOT auto-recovered: it may indicate a
// partial filesystem batch or loss of the final state write after a crash.
// PendingCopy is the immutable, content-addressed intent written BEFORE any
// filesystem copy. It is sufficient to verify that every intended addition
// was completed, but never authorizes copying a missing file during recovery.
type PendingCopy struct {
	Path      string `json:"path"`
	Direction string `json:"direction"` // source-to-target or target-to-source
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

type DurableState struct {
	Version    int             `json:"version"`
	SourceRoot string          `json:"sourceRoot"`
	TargetRoot string          `json:"targetRoot"`
	Excludes   []string        `json:"excludes"`
	Generation uint64          `json:"generation"`
	Phase      string          `json:"phase"` // ready or pending
	Files      []BaselineEntry `json:"files"`
	Pending    []PendingCopy   `json:"pending"`
	Checksum   string          `json:"checksum"`
}

func stateDigest(s DurableState) (string, error) {
	s.Checksum = ""
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func finalizeState(s *DurableState) error {
	d, err := stateDigest(*s)
	if err != nil {
		return err
	}
	s.Checksum = d
	return nil
}

func validateState(s DurableState) error {
	if s.Version != DurableVersion || s.Generation == 0 || (s.Phase != "ready" && s.Phase != "pending") {
		return errors.New("unsupported or malformed sync state version, generation, or phase")
	}
	if (s.Phase == "ready" && len(s.Pending) != 0) || (s.Phase == "pending" && len(s.Pending) == 0) || len(s.Pending) > MaxAdditions {
		return errors.New("sync state pending paths do not match its phase")
	}
	b := Baseline{Version: BaselineVersion, SourceRoot: s.SourceRoot, TargetRoot: s.TargetRoot, Excludes: s.Excludes, Files: s.Files}
	if err := validateBaseline(b); err != nil {
		return fmt.Errorf("invalid sync state inventory: %w", err)
	}
	prev := ""
	var total int64
	known := make(map[string]bool, len(s.Files))
	for _, f := range s.Files {
		known[f.Path] = true
	}
	for _, item := range s.Pending {
		if !validBaselinePath(item.Path) || item.Path <= prev || shouldExclude(item.Path, s.Excludes) || known[item.Path] {
			return fmt.Errorf("invalid, duplicate, previously known or excluded pending path %q", item.Path)
		}
		if item.Direction != "source-to-target" && item.Direction != "target-to-source" {
			return fmt.Errorf("invalid pending direction for %q", item.Path)
		}
		if item.Size < 0 || item.Size > MaxAdditionBytes-total {
			return errors.New("pending bytes exceed safe addition limit")
		}
		if len(item.SHA256) != 64 {
			return fmt.Errorf("invalid pending sha256 for %q", item.Path)
		}
		raw, err := hex.DecodeString(item.SHA256)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != item.SHA256 {
			return fmt.Errorf("invalid pending SHA-256 for %q", item.Path)
		}
		total += item.Size
		prev = item.Path
	}
	want, err := stateDigest(s)
	if err != nil {
		return err
	}
	if s.Checksum != want {
		return errors.New("sync state checksum mismatch: possible corruption or modification")
	}
	return nil
}

func stateJSON(s DurableState) ([]byte, error) {
	if err := finalizeState(&s); err != nil {
		return nil, err
	}
	if err := validateState(s); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxBaselineBytes {
		return nil, fmt.Errorf("sync state exceeds %d-byte bound", MaxBaselineBytes)
	}
	return data, nil
}

// LoadDurableState rejects symlinks, unexpected permissions, non-canonical
// entries, unknown fields and trailing data. The caller must independently
// validate both roots and their ordered orientation before using the state.
func LoadDurableState(filename string) (DurableState, error) {
	var empty DurableState
	info, err := os.Lstat(filename)
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxBaselineBytes {
		return empty, errors.New("sync state must be a 0600 regular file within the size limit")
	}
	f, err := os.Open(filename)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !os.SameFile(info, before) {
		return empty, errors.New("sync state changed before read")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBaselineBytes+1))
	if err != nil || len(data) > MaxBaselineBytes {
		return empty, errors.New("sync state could not be read within size limit")
	}
	after, err := os.Lstat(filename)
	if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(info.ModTime()) || int64(len(data)) != info.Size() {
		return empty, errors.New("sync state changed during read")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state DurableState
	if err := dec.Decode(&state); err != nil {
		return empty, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return empty, errors.New("sync state contains trailing data")
	}
	if err := validateState(state); err != nil {
		return empty, err
	}
	return state, nil
}

func stateMatchesRoots(s DurableState, left, right string, excludes []string) error {
	leftRoot, err := resolvedRoot(left)
	if err != nil {
		return err
	}
	rightRoot, err := resolvedRoot(right)
	if err != nil {
		return err
	}
	sorted, err := normalizedExcludes(excludes)
	if err != nil {
		return err
	}
	if s.SourceRoot != leftRoot || s.TargetRoot != rightRoot || !reflect.DeepEqual(s.Excludes, sorted) {
		return errors.New("sync state belongs to different roots, orientation, or exclusions")
	}
	return nil
}

func syncParent(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// InitDurableState is an explicit one-time enrollment that requires two
// identical inventories. It never overwrites an existing state file.
func InitDurableState(left, right, filename string, excludes []string) (DurableState, error) {
	var empty DurableState
	if filename == "" {
		return empty, errors.New("-sync-state path is required")
	}
	if err := isolatedRoots(left, right); err != nil {
		return empty, err
	}
	if err := ensureBaselineOutside(left, right, filename); err != nil {
		return empty, err
	}
	sorted, err := normalizedExcludes(excludes)
	if err != nil {
		return empty, err
	}
	plan, err := CompareFiltered(left, right, sorted)
	if err != nil {
		return empty, err
	}
	if plan.SourceOnly != 0 || plan.TargetOnly != 0 || plan.Different != 0 {
		return empty, errors.New("sync state initialization requires two identical filtered folder inventories")
	}
	lr, err := resolvedRoot(left)
	if err != nil {
		return empty, err
	}
	rr, err := resolvedRoot(right)
	if err != nil {
		return empty, err
	}
	files, err := sharedEntries(plan)
	if err != nil {
		return empty, err
	}
	s := DurableState{Version: DurableVersion, SourceRoot: lr, TargetRoot: rr, Excludes: sorted, Generation: 1, Phase: "ready", Files: files, Pending: []PendingCopy{}}
	data, err := stateJSON(s)
	if err != nil {
		return empty, err
	}
	if err := finalizeState(&s); err != nil {
		return empty, err
	}
	// A private temporary inode is linked in without replacing an existing
	// state. This is deliberately similar to immutable baseline creation.
	tmp, err := os.CreateTemp(filepath.Dir(filename), ".gcsync-journal-")
	if err != nil {
		return empty, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return empty, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return empty, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return empty, err
	}
	if err := tmp.Close(); err != nil {
		return empty, err
	}
	// Re-inventory just before publishing the state. This reduces accidental
	// enrollment of concurrently edited directories; it is NOT a filesystem
	// snapshot or a guarantee against later mutations.
	latest, err := CompareFiltered(left, right, sorted)
	if err != nil || !reflect.DeepEqual(plan, latest) {
		return empty, errors.New("folder inventories changed during sync state initialization")
	}
	if err := os.Link(tmp.Name(), filename); err != nil {
		return empty, fmt.Errorf("sync state not created (already exists or hardlinks unsupported): %w", err)
	}
	if err := syncParent(filename); err != nil {
		return empty, fmt.Errorf("sync state created but persistence uncertain: %w", err)
	}
	return s, nil
}

func sharedEntries(plan Plan) ([]BaselineEntry, error) {
	entries := make([]BaselineEntry, 0, plan.Identical)
	for _, c := range plan.Changes {
		if c.Status == "identical" && c.Source != nil {
			entries = append(entries, BaselineEntry{Path: c.Path, Size: c.Source.Size, SHA256: c.Source.SHA256})
		}
	}
	if len(entries) > MaxBaselineFiles {
		return nil, errors.New("sync state inventory exceeds file limit")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// ValidateDurableState checks a loaded state against the filesystem pair.
// This read-only operation does NOT mark pending states safe to resume.
func ValidateDurableState(left, right, filename string, excludes []string) (DurableState, error) {
	var empty DurableState
	if err := isolatedRoots(left, right); err != nil {
		return empty, err
	}
	if err := ensureBaselineOutside(left, right, filename); err != nil {
		return empty, err
	}
	s, err := LoadDurableState(filename)
	if err != nil {
		return empty, err
	}
	if err := stateMatchesRoots(s, left, right, excludes); err != nil {
		return empty, err
	}
	return s, nil
}

// updateDurableState uses write+sync+atomic rename+parent sync. It is called
// only while the stable adjacent .lock inode is held. A checksum comparison
// makes external edits to the prior state fail closed. State is written before
// any file copies, marking pending first (write-ahead intent).
func updateDurableState(filename string, old, next DurableState) (DurableState, error) {
	current, err := LoadDurableState(filename)
	if err != nil {
		return old, err
	}
	if current.Checksum != old.Checksum {
		return old, errors.New("sync state changed externally; refusing update")
	}
	if old.Generation == ^uint64(0) || next.Generation != old.Generation+1 {
		return old, errors.New("invalid sync state generation transition")
	}
	data, err := stateJSON(next)
	if err != nil {
		return old, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(filename), ".gcsync-journal-")
	if err != nil {
		return old, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return old, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return old, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return old, err
	}
	if err := tmp.Close(); err != nil {
		return old, err
	}
	if err := os.Rename(tmp.Name(), filename); err != nil {
		return old, err
	}
	if err := syncParent(filename); err != nil {
		return old, fmt.Errorf("state updated but directory persistence uncertain; STOP and inspect: %w", err)
	}
	if err := finalizeState(&next); err != nil {
		return old, err
	}
	return next, nil
}

// verifyKnownFiles rejects any deletion (including removal from BOTH sides)
// and ANY changed hash for a previously shared path. There is no automatic
// conflict resolution, even when both sides were manually edited equally.
func verifyKnownFiles(s DurableState, p Plan) error {
	changes := make(map[string]Change, len(p.Changes))
	for _, c := range p.Changes {
		changes[c.Path] = c
	}
	for _, prev := range s.Files {
		c, found := changes[prev.Path]
		if !found || c.Status != "identical" || c.Source == nil || c.Source.SHA256 != prev.SHA256 || c.Source.Size != prev.Size {
			return fmt.Errorf("manual deletion/change review required for previously shared path %q; no copies performed", prev.Path)
		}
	}
	if p.Different > 0 {
		return fmt.Errorf("refusing to copy: %d divergent paths require manual conflict review", p.Different)
	}
	return nil
}

func plannedCopies(p Plan) []PendingCopy {
	copies := make([]PendingCopy, 0, p.SourceOnly+p.TargetOnly)
	for _, c := range p.Changes {
		switch c.Status {
		case "source-only":
			if c.Source != nil {
				copies = append(copies, PendingCopy{Path: c.Path, Direction: "source-to-target", Size: c.Source.Size, SHA256: c.Source.SHA256})
			}
		case "target-only":
			if c.Target != nil {
				copies = append(copies, PendingCopy{Path: c.Path, Direction: "target-to-source", Size: c.Target.Size, SHA256: c.Target.SHA256})
			}
		}
	}
	sort.Slice(copies, func(i, j int) bool { return copies[i].Path < copies[j].Path })
	return copies
}

// verifyCopiedFiles prevents silently accepting a committed file that was
// removed or rewritten between the preflight and final inventory.
func verifyCopiedFiles(before, after Plan) error {
	// The before scan is the durable pending journal's intended file set.
	// No newly appearing, disappearing, or modified file may be silently
	// enrolled in the ready checkpoint, including previously identical files.
	if len(before.Changes) != len(after.Changes) {
		return fmt.Errorf("folder file set changed during copy; manual recovery required")
	}
	final := make(map[string]Change, len(after.Changes))
	for _, c := range after.Changes {
		final[c.Path] = c
	}
	for _, c := range before.Changes {
		f, found := final[c.Path]
		if !found || f.Status != "identical" || f.Source == nil || f.Target == nil {
			return fmt.Errorf("file %q changed or disappeared during copy", c.Path)
		}
		expected := c.Source
		if c.Status == "target-only" {
			expected = c.Target
		}
		if expected == nil || f.Source.Size != expected.Size || f.Source.SHA256 != expected.SHA256 ||
			f.Target.Size != expected.Size || f.Target.SHA256 != expected.SHA256 {
			return fmt.Errorf("file %q changed before ready checkpoint", c.Path)
		}
	}
	return nil
}

// RunDurableContinuousAdditions runs foreground local-only copying under a
// persistent lock and a fail-closed write-ahead checkpoint. Crashes after the
// pending marker but before the ready marker require explicit manual review;
// it will NOT silently resume an ambiguous filesystem batch.
func RunDurableContinuousAdditions(ctx context.Context, left, right string, excludes []string, interval time.Duration, filename string, emit func(ContinuousAdditionsEvent) error) error {
	if ctx == nil || emit == nil {
		return errors.New("durable sync requires context and event writer")
	}
	if interval < time.Second || interval > time.Hour {
		return errors.New("durable sync interval must be between 1s and 1h")
	}
	if ctx.Err() != nil {
		return nil
	}
	state, err := ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return fmt.Errorf("open durable sync state: %w", err)
	}
	unlock, err := lockDurableState(filename)
	if err != nil {
		return fmt.Errorf("acquire durable sync lock: %w", err)
	}
	defer unlock()
	// Reload AFTER acquiring the lock: a previous cooperative owner may have
	// completed a cycle between the initial read and obtaining the lock.
	state, err = ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return err
	}
	if state.Phase != "ready" {
		return fmt.Errorf("sync state is %s at generation %d: previous operation may be incomplete; stop and perform manual recovery, never auto-resume", state.Phase, state.Generation)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var sequence uint64
	for {
		if ctx.Err() != nil {
			return nil
		}
		current, err := ValidateDurableState(left, right, filename, excludes)
		if err != nil || current.Checksum != state.Checksum {
			return errors.New("durable sync state changed or became unreadable during session")
		}
		result := BidirectionalAdditionsResult{Mode: "bidirectional-additions-only", LeftCreated: []string{}, RightCreated: []string{}}
		plan, err := CompareFiltered(left, right, excludes)
		if err == nil {
			err = verifyKnownFiles(state, plan)
		}
		if err == nil && plan.SourceOnly > MaxAdditions-plan.TargetOnly {
			err = fmt.Errorf("more than %d new files; stop before writing", MaxAdditions)
		}
		if err == nil {
			var total int64
			for _, c := range plan.Changes {
				if c.Status != "source-only" && c.Status != "target-only" {
					continue
				}
				var f *File
				if c.Status == "source-only" {
					f = c.Source
				} else {
					f = c.Target
				}
				if f == nil || f.Size < 0 || f.Size > MaxAdditionBytes-total {
					err = fmt.Errorf("new file data exceed %d-byte safety limit", MaxAdditionBytes)
					break
				}
				total += f.Size
			}
		}
		if err == nil {
			paths := plannedCopies(plan)
			if len(paths) > 0 {
				pending := state
				pending.Generation++
				pending.Phase = "pending"
				pending.Pending = paths
				state, err = updateDurableState(filename, state, pending)
				if err == nil {
					result, err = applyBidirectionalPlan(left, right, plan)
				}
				if err == nil {
					var after Plan
					after, err = CompareFiltered(left, right, excludes)
					if err == nil && (after.SourceOnly != 0 || after.TargetOnly != 0 || after.Different != 0) {
						err = errors.New("post-copy inventories changed or differ; manual recovery required")
					}
					if err == nil {
						err = verifyKnownFiles(state, after)
					}
					if err == nil {
						err = verifyCopiedFiles(plan, after)
					}
					if err == nil {
						var files []BaselineEntry
						files, err = sharedEntries(after)
						if err == nil {
							ready := state
							ready.Generation++
							ready.Phase = "ready"
							ready.Pending = []PendingCopy{}
							ready.Files = files
							state, err = updateDurableState(filename, state, ready)
						}
					}
				}
			} else {
				entries, entryErr := sharedEntries(plan)
				if entryErr != nil {
					err = entryErr
				} else if !reflect.DeepEqual(state.Files, entries) {
					updated := state
					updated.Generation++
					updated.Files = entries
					state, err = updateDurableState(filename, state, updated)
				}
				if err == nil {
					result.Applied = true
					result.Unchanged = plan.Identical
				}
			}
		}
		created := len(result.LeftCreated) + len(result.RightCreated)
		if err != nil || sequence == 0 || created != 0 {
			sequence++
			typeName := "applied"
			if sequence == 1 {
				typeName = "snapshot"
			}
			event := ContinuousAdditionsEvent{Type: typeName, Sequence: sequence, ObservedAt: time.Now().UTC(), Mode: "durable-foreground-additions", AdditionsOnly: true, Result: result}
			if err != nil {
				event.Type = "stopped"
				event.Error = err.Error()
			}
			if emitErr := emit(event); emitErr != nil {
				return fmt.Errorf("write durable sync event: %w", emitErr)
			}
		}
		if err != nil {
			return fmt.Errorf("durable sync stopped: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
