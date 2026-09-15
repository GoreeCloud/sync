package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingCheckpointReplayGuard struct {
	calls   int
	request BackupCheckpointRequest
	receipt BackupCheckpointReceipt
	err     error
}

func (g *recordingCheckpointReplayGuard) ClaimCheckpointReceipt(
	_ context.Context,
	request BackupCheckpointRequest,
	receipt BackupCheckpointReceipt,
) error {
	g.calls++
	g.request = request
	g.receipt = receipt
	return g.err
}

func TestCheckpointReplayGuardMustBeConfiguredBeforeAuthorityCalls(t *testing.T) {
	authorizer := &fakeCheckpointAuthorizer{}
	backup := &fakeCheckpointAuthority{}
	coordinator := BackupSyncCoordinator{Authorizer: authorizer, Checkpoint: backup}
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-replay-guard",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}

	_, err := coordinator.CheckpointBeforeChangeWithFreshnessAndReplayGuard(
		context.Background(), request, time.Minute, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "replay guard is not configured") {
		t.Fatalf("missing replay guard must fail closed, got %v", err)
	}
	if authorizer.calls != 0 || backup.calls != 0 {
		t.Fatalf("missing replay guard must fail before authorization/Backup calls: authorizer=%d backup=%d", authorizer.calls, backup.calls)
	}
}

func TestCheckpointReplayGuardClaimsExactFreshReceipt(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-claim-fresh-receipt",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	receipt := BackupCheckpointReceipt{
		CheckpointID: "cp-fresh-claim",
		AccountID:    request.AccountID,
		ScopeID:      request.ScopeID,
		OperationID:  request.OperationID,
		CreatedAt:    time.Now().UTC().Add(-time.Second),
	}
	guard := &recordingCheckpointReplayGuard{}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: receipt},
	}

	outcome, err := coordinator.CheckpointBeforeChangeWithFreshnessAndReplayGuard(
		context.Background(), request, time.Minute, guard,
	)
	if err != nil {
		t.Fatalf("fresh receipt claim failed: %v", err)
	}
	if !outcome.Created || outcome.Receipt.CheckpointID != receipt.CheckpointID {
		t.Fatalf("unexpected checkpoint outcome: %+v", outcome)
	}
	if guard.calls != 1 || guard.request != request || guard.receipt != receipt {
		t.Fatalf("replay guard did not receive the exact request/receipt: calls=%d request=%+v receipt=%+v", guard.calls, guard.request, guard.receipt)
	}
}

func TestCheckpointReplayGuardRejectsPreviouslyClaimedReceipt(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-replayed-receipt",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	replayErr := errors.New("checkpoint receipt already claimed")
	guard := &recordingCheckpointReplayGuard{err: replayErr}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: BackupCheckpointReceipt{
			CheckpointID: "cp-replayed",
			AccountID:    request.AccountID,
			ScopeID:      request.ScopeID,
			OperationID:  request.OperationID,
			CreatedAt:    time.Now().UTC().Add(-time.Second),
		}},
	}

	_, err := coordinator.CheckpointBeforeChangeWithFreshnessAndReplayGuard(
		context.Background(), request, time.Minute, guard,
	)
	if !errors.Is(err, replayErr) {
		t.Fatalf("replay rejection must preserve guard error, got %v", err)
	}
	if guard.calls != 1 {
		t.Fatalf("replay guard calls = %d, want 1", guard.calls)
	}
}

func TestCheckpointReplayGuardDoesNotClaimUnavailableBestEffortOutcome(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "preference-change-no-backup",
		Reason:      "non-destructive preference change",
		Requirement: BackupCheckpointBestEffort,
	}
	guard := &recordingCheckpointReplayGuard{}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{err: ErrBackupUnavailable},
	}

	outcome, err := coordinator.CheckpointBeforeChangeWithFreshnessAndReplayGuard(
		context.Background(), request, time.Minute, guard,
	)
	if err != nil {
		t.Fatalf("best-effort unavailable outcome failed: %v", err)
	}
	if outcome.Created || outcome.BackupAvailable {
		t.Fatalf("best-effort unavailability became checkpoint evidence: %+v", outcome)
	}
	if guard.calls != 0 {
		t.Fatalf("unavailable outcome must not claim a receipt, guard calls=%d", guard.calls)
	}
}

func TestCheckpointReplayGuardDoesNotClaimStaleReceipt(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-stale-before-claim",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	guard := &recordingCheckpointReplayGuard{}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: BackupCheckpointReceipt{
			CheckpointID: "cp-stale-before-claim",
			AccountID:    request.AccountID,
			ScopeID:      request.ScopeID,
			OperationID:  request.OperationID,
			CreatedAt:    time.Now().UTC().Add(-10 * time.Minute),
		}},
	}

	_, err := coordinator.CheckpointBeforeChangeWithFreshnessAndReplayGuard(
		context.Background(), request, time.Minute, guard,
	)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale receipt must fail before replay claim, got %v", err)
	}
	if guard.calls != 0 {
		t.Fatalf("stale receipt must not pollute replay store, guard calls=%d", guard.calls)
	}
}
