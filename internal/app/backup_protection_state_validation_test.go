package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBackupProtectionStateUsesSafeUnavailableDetail(t *testing.T) {
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{
			err: fmt.Errorf("provider\x00secret: %w", ErrBackupUnavailable),
		},
	}

	state, err := coordinator.ProtectionState(context.Background(), "acct-1", "sync-state")
	if err != nil {
		t.Fatalf("ProtectionState returned error: %v", err)
	}
	if state.Available || state.Protected {
		t.Fatalf("unavailable Backup must remain unavailable and unprotected: %+v", state)
	}
	if state.Detail != ErrBackupUnavailable.Error() {
		t.Fatalf("unavailable detail = %q, want safe fixed detail %q", state.Detail, ErrBackupUnavailable.Error())
	}
}

func TestBackupProtectionStateRejectsInvalidProviderDetail(t *testing.T) {
	observedAt := time.Now().UTC().Add(-time.Minute)

	for name, detail := range map[string]string{
		"leading-space":  " provider detail",
		"trailing-space": "provider detail ",
		"control":        "provider\x00detail",
		"oversized":      strings.Repeat("d", maxProtectionDetailLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			coordinator := BackupSyncCoordinator{
				Protection: fakeProtectionProvider{state: BackupProtectionState{
					Available:  true,
					Protected:  true,
					ObservedAt: observedAt,
					Detail:     detail,
				}},
			}

			if _, err := coordinator.ProtectionState(context.Background(), "acct-1", "sync-state"); err == nil {
				t.Fatal("invalid provider detail must fail closed")
			}
		})
	}
}

func TestBackupProtectionStateRejectsInvalidLatestCheckpoint(t *testing.T) {
	observedAt := time.Now().UTC().Add(-time.Minute)

	for name, checkpointID := range map[string]string{
		"leading-space":  " checkpoint-1",
		"trailing-space": "checkpoint-1 ",
		"control":        "checkpoint\x00-1",
		"oversized":      strings.Repeat("c", maxCoordinationIdentifierLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			coordinator := BackupSyncCoordinator{
				Protection: fakeProtectionProvider{state: BackupProtectionState{
					Available:        true,
					Protected:        true,
					LatestCheckpoint: checkpointID,
					ObservedAt:       observedAt,
					Detail:           "current Backup evidence",
				}},
			}

			if _, err := coordinator.ProtectionState(context.Background(), "acct-1", "sync-state"); err == nil {
				t.Fatal("invalid latest checkpoint identity must fail closed")
			}
		})
	}
}

func TestBackupProtectionStateRejectsUnsafeDetailEvenWhenUnavailable(t *testing.T) {
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{state: BackupProtectionState{
			Available: false,
			Detail:    "provider\nmessage",
		}},
	}

	if _, err := coordinator.ProtectionState(context.Background(), "acct-1", "sync-state"); err == nil {
		t.Fatal("unsafe unavailable-state detail must fail closed")
	}
}

func TestBackupProtectionStateAcceptsCanonicalProviderEvidence(t *testing.T) {
	observedAt := time.Now().UTC().Add(-time.Minute)
	coordinator := BackupSyncCoordinator{
		Protection: fakeProtectionProvider{state: BackupProtectionState{
			Available:        true,
			Protected:        true,
			LatestCheckpoint: "checkpoint-123",
			ObservedAt:       observedAt,
			Detail:           "protected by current Backup checkpoint",
		}},
	}

	state, err := coordinator.ProtectionState(context.Background(), "acct-1", "sync-state")
	if err != nil {
		t.Fatalf("ProtectionState returned error: %v", err)
	}
	if !state.Available || !state.Protected {
		t.Fatalf("canonical Backup evidence was not preserved: %+v", state)
	}
	if state.LatestCheckpoint != "checkpoint-123" || state.Detail != "protected by current Backup checkpoint" {
		t.Fatalf("canonical Backup evidence changed unexpectedly: %+v", state)
	}
	if !state.ObservedAt.Equal(observedAt) {
		t.Fatalf("observed time changed: got %v, want %v", state.ObservedAt, observedAt)
	}
}
