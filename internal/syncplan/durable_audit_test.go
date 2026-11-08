package syncplan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDurableAuditDiagnosesDeletionAndNewFiles(t *testing.T) {
	left, right, state := durableFixtures(t, true)
	initDurableForTest(t, left, right, state, nil)
	a, err := AuditDurableState(left, right, state, nil)
	if err != nil || !a.ReadOnly || !a.SafeToRun || a.IssuesCount != 0 {
		t.Fatalf("initial audit: %v %+v", err, a)
	}
	if err := os.Remove(filepath.Join(right, "shared.txt")); err != nil {
		t.Fatal(err)
	}
	continuousFile(t, left, "new.txt", "new")
	a, err = AuditDurableState(left, right, state, nil)
	if err != nil || a.SafeToRun || a.IssuesCount != 1 || a.NewSourceOnly != 1 || a.Issues[0].Reason != "previously-shared-missing-target" {
		t.Fatalf("deletion audit: %v %+v", err, a)
	}
	if _, err := os.Stat(filepath.Join(right, "shared.txt")); !os.IsNotExist(err) {
		t.Fatal("audit restored deleted file")
	}
}

func TestDurableAuditPendingStateNeverClaimsReady(t *testing.T) {
	left, right, state := durableFixtures(t, false)
	s := initDurableForTest(t, left, right, state, nil)
	pending := s
	pending.Phase = "pending"
	pending.Pending = []PendingCopy{{Path: "file.txt", Direction: "source-to-target", Size: 1, SHA256: sha256Hex([]byte("x"))}}
	pending.Generation++
	if _, err := updateDurableState(state, s, pending); err != nil {
		t.Fatal(err)
	}
	a, err := AuditDurableState(left, right, state, nil)
	if err != nil || a.SafeToRun || a.IssuesCount != 1 || a.Phase != "pending" || len(a.Pending) != 1 {
		t.Fatalf("pending audit: %v %+v", err, a)
	}
	// Read-only reporting never clears a pending checkpoint.
	again, err := LoadDurableState(state)
	if err != nil || again.Phase != "pending" {
		t.Fatalf("mutated state: %v", err)
	}
}

func TestDurableAuditDoesNotClaimSafeAboveCopyLimit(t *testing.T) {
	left, right, state := durableFixtures(t, false)
	initDurableForTest(t, left, right, state, nil)
	for i := 0; i <= MaxAdditions; i++ {
		name := filepath.Join(left, fmt.Sprintf("%05d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := AuditDurableState(left, right, state, nil)
	if err != nil || a.SafeToRun || a.NewSourceOnly != MaxAdditions+1 || a.IssuesCount == 0 || a.Issues[0].Reason != "new-file-count-exceeds-safety-limit" {
		t.Fatalf("unsafe copy cap misreported: %v %+v", err, a)
	}
}
