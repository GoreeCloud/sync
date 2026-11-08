package syncplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pendingRecoveryFixture(t *testing.T, copyFinished bool) (string, string, string, DurableState) {
	t.Helper()
	left, right, filename := durableFixtures(t, true)
	s := initDurableForTest(t, left, right, filename, nil)
	continuousFile(t, left, "left-new.txt", "left content")
	continuousFile(t, right, "right-new.txt", "right content")
	p, err := CompareFiltered(left, right, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := s
	next.Generation++
	next.Phase = "pending"
	next.Pending = plannedCopies(p)
	if len(next.Pending) != 2 {
		t.Fatalf("expected two intents: %+v", next.Pending)
	}
	next, err = updateDurableState(filename, s, next)
	if err != nil {
		t.Fatal(err)
	}
	if copyFinished {
		continuousFile(t, right, "left-new.txt", "left content")
		continuousFile(t, left, "right-new.txt", "right content")
	}
	return left, right, filename, next
}

func TestPendingRecoveryCompletePreservesFilesAndArchivesJournal(t *testing.T) {
	left, right, filename, pending := pendingRecoveryFixture(t, true)
	before, err := CompareFiltered(left, right, nil)
	if err != nil {
		t.Fatal(err)
	}
	check, err := ReviewDurableRecovery(left, right, filename, nil)
	if err != nil || !check.ReadOnly || !check.Eligible || check.PendingFiles != 2 || check.Generation != pending.Generation || len(check.PendingReview) != 2 || !check.PendingReview[0].Complete || !check.PendingReview[1].Complete || check.UnplannedFiles != 0 {
		t.Fatalf("review: %+v %v", check, err)
	}
	result, err := FinalizeCompletedDurableBatch(left, right, filename, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "completed-batch-finalized" || result.Generation != pending.Generation+1 || result.PendingCleared != 2 || result.VerifiedFiles != 3 || result.FilesCopied != 0 || result.FilesDeleted != 0 {
		t.Fatalf("recovery metadata: %+v", result)
	}
	archived, err := LoadDurableState(result.BackupPath)
	if err != nil || archived.Checksum != pending.Checksum || archived.Phase != "pending" {
		t.Fatalf("archive missing the original journal: %v %+v", err, archived)
	}
	info, err := os.Stat(result.BackupPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("archive not private: %v", err)
	}
	ready, err := LoadDurableState(filename)
	if err != nil || ready.Phase != "ready" || len(ready.Pending) != 0 || ready.Generation != pending.Generation+1 {
		t.Fatalf("ready not persisted: %v %+v", err, ready)
	}
	after, err := CompareFiltered(left, right, nil)
	if err != nil || !identicalPlans(before, after) {
		t.Fatalf("recovery touched user files: %v", err)
	}
	if _, err := FinalizeCompletedDurableBatch(left, right, filename, nil); err == nil {
		t.Fatal("recovery should not run again on a ready checkpoint")
	}
	// Even after successful recovery, a deletion after restart is not recreated.
	if err := os.Remove(filepath.Join(right, "left-new.txt")); err != nil {
		t.Fatal(err)
	}
	if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, time.Second, filename, func(ContinuousAdditionsEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "manual deletion/change") {
		t.Fatalf("recovered state lost deletion safety: %v", err)
	}
}

func identicalPlans(a, b Plan) bool {
	if a.SourceOnly != b.SourceOnly || a.TargetOnly != b.TargetOnly || a.Different != b.Different || a.Identical != b.Identical || len(a.Changes) != len(b.Changes) {
		return false
	}
	for i := range a.Changes {
		ac, bc := a.Changes[i], b.Changes[i]
		if ac.Path != bc.Path || ac.Status != bc.Status || (ac.Source != nil && (bc.Source == nil || *ac.Source != *bc.Source)) || (ac.Target != nil && (bc.Target == nil || *ac.Target != *bc.Target)) {
			return false
		}
	}
	return true
}

func TestPendingRecoveryRejectsIncompleteWithoutChanges(t *testing.T) {
	left, right, filename, prior := pendingRecoveryFixture(t, false)
	review, err := ReviewDurableRecovery(left, right, filename, nil)
	if err != nil || review.Eligible || review.Reason == "" || len(review.PendingReview) != 2 || review.PendingReview[0].LeftStatus != "match" || review.PendingReview[0].RightStatus != "missing" || review.PendingReview[0].Complete {
		t.Fatalf("incomplete not flagged: %+v %v", review, err)
	}
	if _, err := FinalizeCompletedDurableBatch(left, right, filename, nil); err == nil {
		t.Fatal("finalized uncompleted copy")
	}
	if _, err := os.Stat(filename + ".recovery-g2.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected backup of unverified copy")
	}
	again, err := LoadDurableState(filename)
	if err != nil || again.Checksum != prior.Checksum || again.Phase != "pending" {
		t.Fatalf("failed recovery modified state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(right, "left-new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery copied user file")
	}
}

func TestPendingRecoveryRejectsNewOrModifiedFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, left, right string)
	}{
		{"modified pending", func(t *testing.T, left, right string) { continuousFile(t, right, "left-new.txt", "tampered") }},
		{"modified known", func(t *testing.T, left, right string) {
			continuousFile(t, left, "shared.txt", "modified")
			continuousFile(t, right, "shared.txt", "modified")
		}},
		{"unexpected new", func(t *testing.T, left, right string) {
			continuousFile(t, left, "unexpected.txt", "extra")
			continuousFile(t, right, "unexpected.txt", "extra")
		}},
		{"unilateral new", func(t *testing.T, left, right string) { continuousFile(t, left, "extra.txt", "extra") }},
		{"removed pending", func(t *testing.T, left, right string) {
			if err := os.Remove(filepath.Join(right, "right-new.txt")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right, filename, pending := pendingRecoveryFixture(t, true)
			tc.change(t, left, right)
			if _, err := FinalizeCompletedDurableBatch(left, right, filename, nil); err == nil {
				t.Fatal("recovery accepted divergent or untracked files")
			}
			s, err := LoadDurableState(filename)
			if err != nil || s.Checksum != pending.Checksum {
				t.Fatalf("rejected recovery modified checkpoint: %v", err)
			}
		})
	}
}

func TestPendingRecoveryRequiresUnusedArchiveAndExclusiveLock(t *testing.T) {
	left, right, filename, pending := pendingRecoveryFixture(t, true)
	archive := filename + ".recovery-g2.json"
	if err := os.WriteFile(archive, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeCompletedDurableBatch(left, right, filename, nil); err == nil {
		t.Fatal("recovery overwrote existing archive")
	}
	body, err := os.ReadFile(archive)
	if err != nil || string(body) != "do not overwrite" {
		t.Fatal("existing archive content changed")
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDurableState(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeCompletedDurableBatch(left, right, filename, nil); err == nil {
		t.Fatal("finalized despite another worker owning the lock")
	}
	unlock()
	if _, err := FinalizeCompletedDurableBatch(right, left, filename, nil); err == nil {
		t.Fatal("accepted swapped roots")
	}
	s, err := LoadDurableState(filename)
	if err != nil || s.Checksum != pending.Checksum {
		t.Fatal("rejected recovery changed checkpoint")
	}
}

func TestPendingCopyValidationAndLegacyRejection(t *testing.T) {
	left, right, filename, old := pendingRecoveryFixture(t, false)
	_ = left
	_ = right
	for _, tc := range []struct {
		name   string
		change func(*DurableState)
	}{
		{"incorrect direction", func(s *DurableState) { s.Pending[0].Direction = "remote-delete" }},
		{"incorrect hash", func(s *DurableState) { s.Pending[0].SHA256 = "not-a-digest" }},
		{"duplicate path", func(s *DurableState) { s.Pending[1].Path = s.Pending[0].Path }},
		{"known path", func(s *DurableState) { s.Pending[0].Path = "shared.txt" }},
		{"bad size", func(s *DurableState) { s.Pending[0].Size = -1 }},
		{"legacy version", func(s *DurableState) { s.Version = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := old
			s.Pending = append([]PendingCopy{}, old.Pending...)
			tc.change(&s)
			if err := finalizeState(&s); err != nil {
				t.Fatal(err)
			}
			if err := validateState(s); err == nil {
				t.Fatal("accepted invalid recovery intent")
			}
		})
	}
	// Ensure old journal remains present after negative validation cases.
	s, err := LoadDurableState(filename)
	if err != nil || s.Checksum != old.Checksum {
		t.Fatal("invalid-intent tests mutated the real journal")
	}
}
