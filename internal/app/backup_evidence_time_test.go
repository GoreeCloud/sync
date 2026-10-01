package app

import (
	"context"
	"testing"
	"time"
)

func TestAvailableBackupProtectionStateRequiresObservationTime(t *testing.T) {
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{state: BackupProtectionState{
			Available: true,
			Protected: true,
		}},
	}

	if _, err := coordinator.ProtectionState(context.Background(), "acct-1", "browser-state"); err == nil {
		t.Fatal("available Backup state without observed time must fail closed")
	}
}

func TestAvailableBackupProtectionStateRejectsFutureObservation(t *testing.T) {
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{state: BackupProtectionState{
			Available:  true,
			Protected:  true,
			ObservedAt: time.Now().UTC().Add(time.Hour),
		}},
	}

	if _, err := coordinator.ProtectionState(context.Background(), "acct-1", "browser-state"); err == nil {
		t.Fatal("future-dated Backup state must fail closed")
	}
}

func TestUnavailableBackupProtectionStateClearsObservationTime(t *testing.T) {
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{state: BackupProtectionState{
			Available:        false,
			Protected:        true,
			LatestCheckpoint: "cp-stale",
			ObservedAt:       time.Now().UTC(),
		}},
	}

	state, err := coordinator.ProtectionState(context.Background(), "acct-1", "browser-state")
	if err != nil {
		t.Fatalf("ProtectionState returned error: %v", err)
	}
	if state.Protected || state.LatestCheckpoint != "" || !state.ObservedAt.IsZero() {
		t.Fatalf("unavailable state retained optimistic evidence: %+v", state)
	}
}

func TestCheckpointReceiptRejectsFutureCreationTime(t *testing.T) {
	request := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-3",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}
	coordinator := BackupSyncCoordinator{
		Authorizer: &fakeCheckpointAuthorizer{},
		Checkpoint: &fakeCheckpointAuthority{receipt: BackupCheckpointReceipt{
			CheckpointID: "cp-future",
			AccountID:    request.AccountID,
			ScopeID:      request.ScopeID,
			OperationID:  request.OperationID,
			CreatedAt:    time.Now().UTC().Add(time.Hour),
		}},
	}

	if _, err := coordinator.CheckpointBeforeChange(context.Background(), request); err == nil {
		t.Fatal("future-dated Backup checkpoint receipt must fail closed")
	}
}
