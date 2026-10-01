# GoreeCloud Sync — Backup Checkpoint Freshness Boundary

## Status

**Development source contract.** This document describes the explicit checkpoint-receipt freshness layer implemented by `internal/app/backup_checkpoint_freshness.go`. It does not establish deployed Backup transport, a production freshness duration, production authorization, or Stable acceptance.

## Purpose

The base `CheckpointBeforeChange` method validates authorization, Backup availability policy, canonical identifiers, exact account/scope/operation binding, and non-future receipt creation time. Those checks establish structural binding, but structural binding alone does not prove that a returned checkpoint is current enough for a particular guarded operation.

`CheckpointBeforeChangeWithFreshness` adds an explicit caller-selected maximum receipt age for operations that require current checkpoint evidence.

## Policy boundary

Sync deliberately does **not** invent one global checkpoint freshness duration.

A caller using the freshness-aware method must provide a positive `maxReceiptAge` that is appropriate for the independently authorized operation. A zero or negative duration fails closed before the checkpoint authorizer or Backup authority is called.

If Backup creates a checkpoint, the receipt must first pass the existing exact request-binding checks. Sync then evaluates the receipt against the caller-selected freshness window using a current UTC evaluation time. A receipt created before `evaluatedAt - maxReceiptAge` is rejected as stale. A future-dated receipt is also rejected.

The freshness window is a Sync orchestration acceptance rule only. It does not change Backup retention, checkpoint lifetime, storage policy, deletion authority, or backup-set validity.

## Best-effort behavior

Freshness validation does not convert Backup unavailability into success.

When a best-effort checkpoint request receives the existing explicit Backup-unavailable outcome, `CheckpointBeforeChangeWithFreshness` returns that degraded outcome unchanged. No checkpoint is marked created and no freshness claim is manufactured.

Required checkpoint requests continue to fail closed when Backup is unavailable.

## Replay boundary

Freshness narrows the period in which a structurally valid receipt can be accepted, but it is not a complete anti-replay protocol by itself.

Exact account, scope, and operation binding remains mandatory. Production replay protection still requires the broader operation/session freshness design, authenticated Backup transport, Identity/policy authorization, unique operation semantics, and any required nonce/challenge or durable replay-state contract.

The base `CheckpointBeforeChange` method remains available as the structural checkpoint primitive. Callers must not represent its receipt as satisfying an operation-specific freshness requirement unless they apply an independently defined freshness policy. Freshness-sensitive callers should use `CheckpointBeforeChangeWithFreshness`.

## Acceptance boundary

This increment is repository-local Development work. It does not choose a production freshness duration, prove synchronized production clocks, establish authenticated Backup↔Sync transport, provide durable replay ledgers, or authorize production deployment. Those remain separate acceptance gates.
