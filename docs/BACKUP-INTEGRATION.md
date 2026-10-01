# GoreeCloud Sync — GoreeCloud Backup Integration Boundary

## Status

**Development source contract.** This document describes repository-local coordination implemented by `internal/app/backup_coordination.go`. It does not establish deployed Backup transport, production restore orchestration, Stable acceptance, or production approval.

## Authority split

GoreeCloud Backup and GoreeCloud Sync are separate authorities.

**Backup owns:**

- backup protection state;
- checkpoint creation and retention;
- backup-set lifecycle and deletion authority;
- backup storage and restore-source integrity;
- Backup-specific authorization and policy.

**Sync owns:**

- Sync-managed datasets and target authorization;
- Sync mutation pause/maintenance state;
- isolated restore staging for Sync-managed targets;
- reconciliation/publication into Sync state;
- Sync resume after restore attempt;
- Sync-specific authorization and consistency policy.

Reachability to one service does not transfer authority from the other. Sync intentionally has no Backup deletion interface in this contract.

## Independent protection state

`BackupProtectionStateProvider` exposes descriptive Backup-owned state to Sync. The state is read-only from Sync's perspective.

Backup unavailability is represented as `Available: false`. It is never interpreted as either protected or unprotected truth. An unavailable state cannot retain an optimistic `Protected` flag or checkpoint identifier.

This lets Sync display or use Backup protection information for bounded orchestration while preserving Backup as the source of truth.

## Pre-change and pre-migration checkpoints

`CheckpointBeforeChange` requires a separate `BackupCheckpointAuthorizer` before calling the Backup checkpoint authority.

A checkpoint request identifies an account, logical Sync scope, operation ID, reason, and one of two availability policies:

- **Required** — Backup unavailability fails closed and the guarded change/migration must not treat the checkpoint as satisfied.
- **Best effort** — Backup unavailability is returned as an explicit degraded outcome. The caller may continue only if the underlying operation is independently safe to perform without a checkpoint.

Backup returns the checkpoint identifier and creation time. Empty or otherwise invalid receipts fail closed.

This contract does not let Sync choose Backup retention, delete backup data, or convert successful checkpoint creation into broader Backup authorization.

## Restore into Sync-managed targets

`RestoreIntoManagedTarget` never accepts a caller-supplied filesystem destination path.

The Sync runtime must first:

1. authorize the logical target;
2. enter the required pause/maintenance state;
3. create an isolated staging area;
4. return an opaque restore lease bound to the exact account, target, and operation.

The restore callback receives only that opaque lease/staging identifier. A lease for a different account, target, or operation, or a malformed lease/staging identifier, fails closed before restore execution.

After staging succeeds, Sync performs `CommitAndReconcile`. Publication/reconciliation is therefore a Sync-owned operation rather than a side effect of Backup writing directly into active Sync storage.

If staging or reconciliation fails after a **valid** lease has been accepted, Sync requests lease-scoped abort cleanup. Resume is attempted for every successfully accepted lease, including failure paths.

If `BeginRestore` returns an **error after partially entering restore state**, or returns an **invalid lease**, the coordinator never feeds any returned lease—or a fabricated replacement lease—into `AbortRestore` or `Resume`. A runtime may instead implement the optional `SyncRestoreRequestCleanupRuntime` interface, whose `AbortRestoreRequest` and `ResumeRestoreRequest` methods receive only the exact already-validated `RestoreRequest`. This gives the runtime a bounded way to unwind partial begin/pause state without granting authority to identifiers returned alongside an error or in an invalid lease. If that request-bound cleanup interface is unavailable, the coordinator fails closed without invoking lease-scoped cleanup on untrusted lease material.

Once cleanup is needed, cancellation of the original request context does not by itself suppress Sync-owned cleanup. Cleanup operations receive a fresh context that preserves parent context values while detaching cancellation/deadline propagation and imposing a separate current Development ceiling of five seconds per cleanup operation. This is bounded in-process cleanup only; it does not provide crash/restart lease recovery, durable cleanup journaling, or a guarantee that a runtime implementation will successfully finish cleanup.

## Graceful unavailability

The contract distinguishes service absence from successful protection or successful restore:

- missing/unavailable Backup protection provider → explicit unavailable state;
- unavailable Backup checkpoint authority → required checkpoints fail closed, best-effort checkpoints degrade explicitly;
- missing Sync restore runtime → restore cannot begin;
- failed Sync begin/pause/staging setup → restore callback does not run and only request-bound cleanup may be used if the runtime supports it;
- invalid runtime lease → restore callback does not run and only request-bound cleanup may be used.

No component may convert an unavailable dependency into optimistic success.

## Security and privacy boundary

This layer is transport-neutral. Production integration still requires authenticated, authorized service transport and current authority evidence from the relevant GoreeCloud systems.

No raw backup payload, credential, private key, account token, user secret, or filesystem destination is introduced into shared coordination records by this contract.

Wardveil Security, Privacy Shield, GoreeCloud Identity, Everkeep, GoreeCloud Mesh, and platform storage policy retain their own authority. This contract does not manufacture their state.

## Remaining work

Before this relationship can be described as production-ready, GoreeCloud still needs, at minimum:

- authenticated Backup↔Sync transport/adapters;
- concrete authorization integration with GoreeCloud Identity and applicable policy authorities;
- real Backup protection/checkpoint implementation wiring;
- real Sync pause/maintenance/staging/reconciliation runtime wiring;
- restore conflict and rollback policy for each supported Sync-managed dataset;
- crash/restart recovery and durable reconciliation for interrupted restore leases beyond the bounded in-process cleanup implemented here;
- operational observability without sensitive payload leakage;
- target-environment tests, failure injection, recovery drills, and production acceptance evidence.
