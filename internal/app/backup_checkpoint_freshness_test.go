package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCheckpointFreshnessPolicyMustBeExplicitAndPositive(t *testing.T) {
	authorizer := &fakeCheckpointAuthorizer{}
	backup := &fakeCheckpointAuthority{}
	coordinator := BackupSyncCoordinator{Authorizer: authorizer, Checkpoint: backup}
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-freshness-policy",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}

	for _, maxAge := range []time.Duration{0, -time.Second} {
		if _, err := coordinator.CheckpointBeforeChangeWithFreshness(context.Background(), request, maxAge); err == nil {
			t.Fatalf("freshness window %v must fail closed", maxAge)
		}
	}
	if authorizer.calls != 0 || backup.calls != 0 {
		t.Fatalf("invalid local freshness policy must fail before authorization or Backup calls: authorizer=%d backup=%d", authorizer.calls, backup.calls)
	}
}

func TestCheckpointFreshnessRejectsStaleReceipt(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-stale-receipt",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: BackupCheckpointReceipt{
			CheckpointID: "cp-stale",
			AccountID:    request.AccountID,
			ScopeID:      request.ScopeID,
			OperationID:  request.OperationID,
			CreatedAt:    time.Now().UTC().Add(-5 * time.Minute),
		}},
	}

	_, err := coordinator.CheckpointBeforeChangeWithFreshness(context.Background(), request, time.Minute)
	if err == nil {
		t.Fatal("stale checkpoint receipt must fail closed")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale checkpoint failure must remain explainable, got %v", err)
	}
}

func TestCheckpointFreshnessAcceptsReceiptInsideCallerWindow(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-current-receipt",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: BackupCheckpointReceipt{
			CheckpointID: "cp-current",
			AccountID:    request.AccountID,
			ScopeID:      request.ScopeID,
			OperationID:  request.OperationID,
			CreatedAt:    time.Now().UTC().Add(-time.Second),
		}},
	}

	outcome, err := coordinator.CheckpointBeforeChangeWithFreshness(context.Background(), request, time.Minute)
	if err != nil {
		t.Fatalf("fresh checkpoint receipt was rejected: %v", err)
	}
	if !outcome.Created || outcome.Receipt.CheckpointID != "cp-current" {
		t.Fatalf("unexpected fresh checkpoint outcome: %+v", outcome)
	}
}

func TestCheckpointFreshnessPreservesBestEffortUnavailableOutcome(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "change-backup-unavailable",
		Reason:      "non-destructive preference change",
		Requirement: BackupCheckpointBestEffort,
	}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{err: ErrBackupUnavailable},
	}

	outcome, err := coordinator.CheckpointBeforeChangeWithFreshness(context.Background(), request, time.Minute)
	if err != nil {
		t.Fatalf("best-effort unavailable checkpoint returned error: %v", err)
	}
	if outcome.BackupAvailable || outcome.Created {
		t.Fatalf("best-effort unavailability became optimistic freshness evidence: %+v", outcome)
	}
	if outcome.Detail != ErrBackupUnavailable.Error() {
		t.Fatalf("best-effort unavailable detail = %q, want %q", outcome.Detail, ErrBackupUnavailable.Error())
	}
}
