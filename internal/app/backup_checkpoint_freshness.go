package app

import (
	"context"
	"fmt"
	"time"
)

// CheckpointBeforeChangeWithFreshness composes the existing authorized checkpoint
// request with an explicit receipt-freshness policy. The caller must choose a
// positive maximum receipt age for the guarded operation; Sync does not invent a
// global freshness duration or reinterpret Backup retention policy.
//
// A best-effort unavailable outcome remains explicitly degraded and carries no
// fresh checkpoint claim. A created receipt must already satisfy the base exact
// request binding and then also fall within the configured freshness window.
func (c BackupSyncCoordinator) CheckpointBeforeChangeWithFreshness(
	ctx context.Context,
	request BackupCheckpointRequest,
	maxReceiptAge time.Duration,
) (BackupCheckpointOutcome, error) {
	if maxReceiptAge <= 0 {
		return BackupCheckpointOutcome{}, fmt.Errorf("backup checkpoint receipt freshness window must be a positive duration")
	}

	outcome, err := c.CheckpointBeforeChange(ctx, request)
	if err != nil {
		return BackupCheckpointOutcome{}, err
	}
	if !outcome.Created {
		return outcome, nil
	}

	evaluatedAt := time.Now().UTC()
	if err := validateCheckpointReceiptFreshness(outcome.Receipt, evaluatedAt, maxReceiptAge); err != nil {
		return BackupCheckpointOutcome{}, err
	}
	return outcome, nil
}

func validateCheckpointReceiptFreshness(
	receipt BackupCheckpointReceipt,
	evaluatedAt time.Time,
	maxReceiptAge time.Duration,
) error {
	if maxReceiptAge <= 0 {
		return fmt.Errorf("backup checkpoint receipt freshness window must be a positive duration")
	}
	if evaluatedAt.IsZero() {
		return fmt.Errorf("backup checkpoint receipt freshness evaluation time must be set")
	}
	if receipt.CreatedAt.IsZero() {
		return fmt.Errorf("backup checkpoint receipt is missing creation time")
	}
	if receipt.CreatedAt.After(evaluatedAt) {
		return fmt.Errorf("backup checkpoint receipt cannot be created in the future")
	}
	if receipt.CreatedAt.Before(evaluatedAt.Add(-maxReceiptAge)) {
		return fmt.Errorf("backup checkpoint receipt is stale for the configured freshness window")
	}
	return nil
}
