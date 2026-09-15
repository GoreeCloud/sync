# GoreeCloud Sync — Backup Checkpoint Freshness and Replay Boundary

## Status

**Development source contract.** This document describes the explicit checkpoint-receipt freshness layer in `internal/app/backup_checkpoint_freshness.go` and the stricter durable anti-replay seam in `internal/app/backup_checkpoint_replay.go`. It does not establish deployed Backup transport, a production freshness duration, a durable replay-store implementation, production authorization, or Stable acceptance.

## Purpose

The base `CheckpointBeforeChange` method validates authorization, Backup availability policy, canonical identifiers, exact account/scope/operation binding, and non-future receipt creation time. Those checks establish structural binding, but structural binding alone does not prove that a returned checkpoint is current enough for a particular guarded operation or that the same valid receipt has not already been consumed by another attempt.

`CheckpointBeforeChangeWithFreshness` adds an explicit caller-selected maximum receipt age. `CheckpointBeforeChangeWithFreshnessAndReplayGuard` composes that freshness rule with an independently supplied durable replay-claim boundary.

## Freshness policy boundary

Sync deliberately does **not** invent one global checkpoint freshness duration.

A caller using a freshness-aware method must provide a positive `maxReceiptAge` appropriate for the independently authorized operation. A zero or negative duration fails closed before checkpoint authorization or Backup authority is called.

If Backup creates a checkpoint, the receipt first passes the existing exact request-binding checks. Sync then evaluates the receipt against the caller-selected freshness window using current UTC evaluation time. A receipt created before `evaluatedAt - maxReceiptAge` is rejected as stale. A future-dated receipt is rejected.

The freshness window is a Sync orchestration acceptance rule only. It does not change Backup retention, checkpoint lifetime, storage policy, deletion authority, or backup-set validity.

## Durable replay-claim seam

`BackupCheckpointReceiptReplayGuard` is deliberately an interface rather than an in-process receipt set.

A production implementation must atomically claim the exact checkpoint receipt identity for the exact already-validated request and fail closed when that receipt was previously claimed. The guard may not create Backup checkpoints, inspect or delete Backup data, authorize the guarded Sync operation, or reinterpret Backup retention policy.

The stricter method requires a replay guard before it contacts the checkpoint authorizer or Backup authority. A missing guard fails closed locally. This prevents a caller from silently selecting a “replay-safe” API while actually running without replay state.

Ordering is conservative:

1. validate local replay-guard configuration;
2. authorize and request the checkpoint through the existing authority boundaries;
3. validate exact account/scope/operation binding;
4. validate the caller-selected freshness window; and
5. only then ask the durable replay guard to atomically claim the exact receipt.

Stale or future-dated evidence is therefore rejected before it can pollute a replay store. If the durable claim rejects a previously consumed receipt, the stricter method fails closed and preserves the guard error as the underlying cause.

A successful replay claim is **not** operation authorization. It is one evidence-control step inside an already separately authorized workflow.

## Best-effort behavior

Freshness/replay validation does not convert Backup unavailability into success.

When a best-effort checkpoint request receives the existing explicit Backup-unavailable outcome, the freshness-aware methods return that degraded outcome unchanged. No checkpoint is marked created, no freshness claim is manufactured, and the replay guard is not called because there is no receipt to claim.

Required checkpoint requests continue to fail closed when Backup is unavailable.

## Remaining replay design

The new seam closes the repository-local orchestration gap without pretending the durable store already exists. Production replay protection still requires an accepted durable implementation with authenticated Backup↔Sync transport, Identity/policy authorization, atomic persistence, operation/session lifecycle semantics, bounded retention/cleanup, restart/recovery behavior, distributed/concurrent claim behavior where applicable, observability that does not expose protected receipt material, and Everkeep-compatible recovery semantics for the replay state if required.

The base `CheckpointBeforeChange` and freshness-only method remain available as lower-level structural primitives. Callers must not represent either as satisfying durable anti-replay requirements. A workflow that requires replay-safe checkpoint evidence should use the replay-guard method only after an accepted durable guard implementation is injected.

## Acceptance boundary

This increment is repository-local Development work. It does not choose a production freshness duration, prove synchronized production clocks, deploy authenticated Backup↔Sync transport, provide the durable replay ledger, establish distributed replay safety, authorize production deployment, or qualify GoreeCloud Sync as Release Candidate or Stable. Those remain separate acceptance gates.
