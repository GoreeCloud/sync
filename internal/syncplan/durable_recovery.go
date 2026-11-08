package syncplan

import (
	"errors"
	"fmt"
	"os"
	"reflect"
)

// DurableRecoveryReview is only a point-in-time assessment of a pending copy.
// Eligible NEVER authorizes automatic copying, deletion, conflict resolution,
// or restarting the worker. Only an explicit recovery command can finalize it.
type DurableRecoveryReview struct {
	Mode           string                      `json:"mode"`
	ReadOnly       bool                        `json:"readOnly"`
	Generation     uint64                      `json:"generation"`
	Phase          string                      `json:"phase"`
	PendingFiles   int                         `json:"pendingFiles"`
	PendingReview  []PendingFileRecoveryReview `json:"pendingReview"`
	UnplannedFiles int                         `json:"unplannedFiles"`
	Eligible       bool                        `json:"eligible"`
	Reason         string                      `json:"reason,omitempty"`
}

// PendingFileRecoveryReview helps manually distinguish missing files, altered
// hashes, and already completed copies. Its paths and hashes are sensitive.
type PendingFileRecoveryReview struct {
	Path           string `json:"path"`
	Direction      string `json:"direction"`
	ExpectedSHA256 string `json:"expectedSHA256"`
	Size           int64  `json:"size"`
	LeftStatus     string `json:"leftStatus"`
	RightStatus    string `json:"rightStatus"`
	LeftSHA256     string `json:"leftSHA256,omitempty"`
	RightSHA256    string `json:"rightSHA256,omitempty"`
	Complete       bool   `json:"complete"`
}

// DurableRecoveryResult describes a successful explicit, zero-copy finalize.
// BackupPath retains the EXACT pending checkpoint as a private hardlink.
type DurableRecoveryResult struct {
	Mode           string `json:"mode"`
	Generation     uint64 `json:"generation"`
	VerifiedFiles  int    `json:"verifiedFiles"`
	PendingCleared int    `json:"pendingCleared"`
	BackupPath     string `json:"backupPath"`
	FilesCopied    int    `json:"filesCopied"`
	FilesDeleted   int    `json:"filesDeleted"`
}

// verifyPendingBatchComplete demands a precise match to the trusted state:
// all prior shared files must still be unchanged, every intended copy must
// already exist at BOTH paths with its recorded original hash, and NO OTHER
// files may have been added. It never consults mtime as an identity substitute.
func verifyPendingBatchComplete(s DurableState, plan Plan) error {
	if s.Phase != "pending" || len(s.Pending) == 0 {
		return errors.New("only an incomplete pending batch can be finalized")
	}
	if err := verifyKnownFiles(s, plan); err != nil {
		return err
	}
	if plan.SourceOnly != 0 || plan.TargetOnly != 0 || plan.Different != 0 {
		return errors.New("pending batch is not fully copied or inventories diverged; manual reconciliation required")
	}
	if len(plan.Changes) != len(s.Files)+len(s.Pending) {
		return errors.New("unexpected new or missing paths since pending checkpoint; manual reconciliation required")
	}
	byPath := make(map[string]Change, len(plan.Changes))
	for _, c := range plan.Changes {
		byPath[c.Path] = c
	}
	for _, expected := range s.Pending {
		actual, ok := byPath[expected.Path]
		if !ok || actual.Status != "identical" || actual.Source == nil || actual.Target == nil ||
			actual.Source.Size != expected.Size || actual.Source.SHA256 != expected.SHA256 ||
			actual.Target.Size != expected.Size || actual.Target.SHA256 != expected.SHA256 {
			return fmt.Errorf("pending file %q is absent or no longer matches its recorded SHA-256; manual review required", expected.Path)
		}
	}
	return nil
}

func pendingSideStatus(actual *File, expected PendingCopy) (string, string) {
	if actual == nil {
		return "missing", ""
	}
	if actual.Size != expected.Size || actual.SHA256 != expected.SHA256 {
		return "mismatch", actual.SHA256
	}
	return "match", actual.SHA256
}

// ReviewDurableRecovery is read-only. A green assessment may become stale
// immediately if another process modifies trusted local files; finalization
// performs the same full scan again while holding the durable worker lock.
func ReviewDurableRecovery(left, right, filename string, excludes []string) (DurableRecoveryReview, error) {
	report := DurableRecoveryReview{Mode: "durable-pending-recovery-review", ReadOnly: true, PendingReview: []PendingFileRecoveryReview{}}
	s, err := ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return report, err
	}
	report.Generation, report.Phase, report.PendingFiles = s.Generation, s.Phase, len(s.Pending)
	p, err := CompareFiltered(left, right, excludes)
	if err != nil {
		return report, err
	}
	byPath := make(map[string]Change, len(p.Changes))
	for _, change := range p.Changes {
		byPath[change.Path] = change
	}
	known := make(map[string]bool, len(s.Files)+len(s.Pending))
	for _, f := range s.Files {
		known[f.Path] = true
	}
	for _, intent := range s.Pending {
		known[intent.Path] = true
		entry := PendingFileRecoveryReview{Path: intent.Path, Direction: intent.Direction, Size: intent.Size, ExpectedSHA256: intent.SHA256}
		change := byPath[intent.Path]
		entry.LeftStatus, entry.LeftSHA256 = pendingSideStatus(change.Source, intent)
		entry.RightStatus, entry.RightSHA256 = pendingSideStatus(change.Target, intent)
		entry.Complete = entry.LeftStatus == "match" && entry.RightStatus == "match"
		report.PendingReview = append(report.PendingReview, entry)
	}
	for _, change := range p.Changes {
		if !known[change.Path] {
			report.UnplannedFiles++
		}
	}
	if err := verifyPendingBatchComplete(s, p); err != nil {
		report.Reason = err.Error()
		return report, nil
	}
	report.Eligible = true
	return report, nil
}

// FinalizeCompletedDurableBatch is the ONLY recovery write operation.
// It NEVER copies, deletes, repairs or overwrites user files. It requires
// that the entire recorded batch has already been copied byte-for-byte,
// archives the pending journal without replacing any existing archive, then
// advances to ready. An interrupted recovery may leave a backup and a pending
// journal; this is intentionally fail-closed rather than auto-resumed.
func FinalizeCompletedDurableBatch(left, right, filename string, excludes []string) (DurableRecoveryResult, error) {
	var result DurableRecoveryResult
	s, err := ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return result, err
	}
	unlock, err := lockDurableState(filename)
	if err != nil {
		return result, err
	}
	defer unlock()
	// Reload after locking to avoid reusing an earlier generation.
	s, err = ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return result, err
	}
	before, err := CompareFiltered(left, right, excludes)
	if err != nil {
		return result, err
	}
	if err := verifyPendingBatchComplete(s, before); err != nil {
		return result, err
	}
	entries, err := sharedEntries(before)
	if err != nil {
		return result, err
	}
	if s.Generation == ^uint64(0) {
		return result, errors.New("sync state generation exhausted")
	}
	archive := fmt.Sprintf("%s.recovery-g%d.json", filename, s.Generation)
	// Link must not replace an existing archive. This immutable hardlink
	// preserves the pending checkpoint even after updateDurableState renames.
	if err := os.Link(filename, archive); err != nil {
		return result, fmt.Errorf("cannot preserve private pending journal backup (possibly already exists): %w", err)
	}
	if err := syncParent(archive); err != nil {
		return result, fmt.Errorf("journal backup created but persistence uncertain; stop: %w", err)
	}
	// Rehash a second time after writing the backup. A changed tree remains
	// pending with its backup; recovery cannot silently accept new contents.
	after, err := CompareFiltered(left, right, excludes)
	if err != nil || !reflect.DeepEqual(before, after) {
		return result, errors.New("folder inventories changed during pending recovery; journal remains pending and backup retained")
	}
	updated := s
	updated.Generation++
	updated.Phase = "ready"
	updated.Pending = []PendingCopy{}
	updated.Files = entries
	updated, err = updateDurableState(filename, s, updated)
	if err != nil {
		return result, fmt.Errorf("finalization failed; retain pending journal and backup: %w", err)
	}
	return DurableRecoveryResult{Mode: "completed-batch-finalized", Generation: updated.Generation, VerifiedFiles: len(updated.Files), PendingCleared: len(s.Pending), BackupPath: archive, FilesCopied: 0, FilesDeleted: 0}, nil
}
