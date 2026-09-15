package app

import (
	"context"
	"fmt"
	"time"
)

// BackupCheckpointReceiptReplayGuard is the durable anti-replay seam for
// Backup checkpoint receipts consumed by a guarded Sync operation.
//
// Implementations must atomically claim the exact checkpoint receipt identity
// for the exact already-validated request and fail closed if that receipt was
// previously claimed. The guard does not authorize checkpoint creation, inspect
// Backup contents, delete Backup data, or grant the guarded Sync operation.
type BackupCheckpointReceiptReplayGuard interface {
	ClaimCheckpointReceipt(ctx context.Context, request BackupCheckpointRequest, receipt BackupCheckpointReceipt) error
}

// CheckpointBeforeChangeWithFreshnessAndReplayGuard composes the existing
// authorization, exact receipt binding, caller-chosen freshness window, and an
// independently supplied durable anti-replay guard.
//
// The replay guard is mandatory for this stricter entry point. A best-effort
// Backup-unavailable outcome carries no receipt and therefore performs no replay
// claim. A created receipt is freshness-validated before the durable claim is
// attempted, so stale/future evidence cannot pollute the replay store.
func (c BackupSyncCoordinator) CheckpointBeforeChangeWithFreshnessAndReplayGuard(
	ctx context.Context,
	request BackupCheckpointRequest,
	maxReceiptAge time.Duration,
	replayGuard BackupCheckpointReceiptReplayGuard,
) (BackupCheckpointOutcome, error) {
	if replayGuard == nil {
		return BackupCheckpointOutcome{}, fmt.Errorf("backup checkpoint receipt replay guard is not configured")
	}

	outcome, err := c.CheckpointBeforeChangeWithFreshness(ctx, request, maxReceiptAge)
	if err != nil {
		return BackupCheckpointOutcome{}, err
	}
	if !outcome.Created {
		return outcome, nil
	}

	if err := replayGuard.ClaimCheckpointReceipt(ctx, request, outcome.Receipt); err != nil {
		return BackupCheckpointOutcome{}, fmt.Errorf("claim backup checkpoint receipt: %w", err)
	}
	return outcome, nil
}
