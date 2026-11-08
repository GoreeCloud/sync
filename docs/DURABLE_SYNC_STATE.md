# GoreeCloud Sync — Durable Local Additions State (Experimental)

**Status:** Locally tested Go CLI safety foundation, not a network Sync service, native desktop/mobile release, backup or production-ready change journal. This document describes the current implementation and its limitations, not a promise of automatic file recovery.

## Purpose and operating policy

My direction for GoreeCloud Sync is private, dependable, reversible synchronization. An earlier foreground additions-only preview remembered shared file paths **only while the same process was running**. That could mistakenly restore a file intentionally deleted while Sync was stopped. To reduce that risk, I now require an explicit, private, persistent state file for the CLI `-sync-additions` mode. It tracks the last **known identical SHA-256** of every shared regular file and records a write-ahead **pending** phase before any new file is copied.

This is **not automatic deletion-aware replication**. No deletion is ever propagated, and existing files are never overwritten. If a previously shared file changes or vanishes on either side, including deletion on **both** sides, the command stops and requires manual review. It also stops if a new same-path file differs between the two folders. These rules deliberately favor refusing a questionable operation over guessing intent.

## Safe local setup

Use only two *trusted, non-overlapping* local directories with initially identical **filtered** inventories. Store state **outside** both folder trees in a private directory. State is bound to exact canonical absolute paths, their order, and all exclusion patterns; moving or swapping folders requires new, deliberate enrollment.

```sh
mkdir -m 700 ./private-sync-state
# First inspect both trees. Confirm they are intentionally identical.
go run ./cmd/sync -plan-source ./left -plan-target ./right

# Create new 0600 state. This refuses differing inventories or an existing file.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -init-sync-state

# Optionally inspect the state and read-only filesystem safety report.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -inspect-sync-state
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -audit-sync-state

# Only after enrollment: start explicit foreground, two-way additions-only copy.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -sync-additions -sync-interval 15s
```

Opt-in exclusions (`-exclude '*.tmp'`, `-exclude 'private/**'`) **must be supplied identically** to enrollment, inspection, audit, and every later run. Changing exclusions or swapping the two root directories is rejected. The CLI does **not** permit `-sync-additions` without `-sync-state`; old stateless continuous CLI invocation is intentionally no longer supported. The manual one-shot `-apply-additions` / `-apply-both-additions` commands are separate and **not** governed by this journal; avoid running them on tracked roots while the foreground worker is active.

## State schema and crash protection

The experimental v1 JSON state contains the canonical source and target roots, sorted exclusion patterns, file path/size/content SHA-256 entries, a monotonically increasing generation, a `ready` or `pending` phase, and a SHA-256 integrity checksum of canonicalized state fields. Unknown fields, malformed entries, unsupported versions, insecure file permissions, symlinks, oversized files, mismatched paths and failed checksums are rejected. The checksum detects accidental corruption, **not** malicious edits by another process with filesystem write access.

The state file is written with mode 0600. The adjacent persistent `.lock` file is 0600, and a nonblocking operating-system lock prevents two cooperating workers from running concurrently. File updates use a same-directory 0600 temporary file, `fsync`, atomic rename and parent-directory `fsync`. The lock inode is never unlinked during normal operation; it is released by the OS when the process exits. **Unix advisory flock support is required**; unsupported operating systems fail closed.

For each polling cycle:

1. Read and validate the persistent state, exact roots, exclusions and checksum.
2. Rehash both folder inventories. If a known path was deleted or changed—even identically on both sides—stop **before copying anything**. If new files conflict, also stop.
3. Check the existing combined 1,024-file / 1-GiB per-cycle limits. If new one-sided files need copying, persist `phase: pending` and the intended relative paths **before** touching destination files.
4. Reuse the existing SHA-256-verified, private staged, no-overwrite copier. Rehash the complete resulting inventories; require matching content, unchanged known hashes and the intended new hashes.
5. Persist `phase: ready` and the full new list of shared hashes only after post-copy validation. If anything fails, stop without automatic retries. Newly matching files already present on both sides are also recorded for future deletion detection.

A **pending** state is never automatically resumed. Experimental journal **v2** additionally records the exact content hash, file size and direction of every planned addition before the copy. This supports an opt-in, zero-copy finalization **only if every planned file was already copied and remains identical on both sides**. The prior local experimental v1 journal lacks those proofs and is deliberately rejected by the v2 reader. Back up the old journal and reconcile manually before enrolling a new v2 state; no automatic migration is offered. The foreground process reports the actual committed paths when it can; after a sudden kill, its last NDJSON event may not have been written.

## Read-only audit and manual recovery

`-inspect-sync-state` displays verified metadata and the content-addressed pending intents. `-audit-sync-state` hashes both folders and classifies missing shared files, changed content, untracked conflicts, newly present one-sided files and any pending batch. Its `safeToRun` value describes one **non-atomic, read-only** snapshot, not permission to repair. An audit can inspect a `pending` state and never changes data.

`-check-pending-recovery` is a separate **read-only** eligibility check. Its JSON includes **per-intent expected SHA-256**, direction, current hash/status on each side (`match`, `missing`, `mismatch`), and a count of unexpected unplanned paths. The relative filenames and hashes may be sensitive; keep reports private. The check: it requires a v2 pending state, exact matching hashes for every pending file **on both sides**, unchanged content for every previously known shared file, no unexpected files, no divergent files, and exact root/exclusion binding. `eligible: true` describes only that scan and may become stale immediately. To finalize an **already completed** batch, deliberately use `-finalize-completed-batch` with the same roots/exclusions. It acquires the durable lock, checks all data again, creates a no-overwrite private hardlink to the original pending journal (`.recovery-gN.json`), synchronizes the directory, verifies the inventories again, and only then records a new `ready` generation. It reports **zero copied or deleted files**. A pre-existing backup filename blocks finalization. Failures can leave the pending journal and/or a backup; never automatically overwrite or discard them.

```sh
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -check-pending-recovery
# Only after independently verifying all intended contents and reviewing the audit:
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -finalize-completed-batch
```

If the process stops with a conflict or pending phase:

1. Stop both workers; retain backups of both folder trees and the **complete** state directory, including the `.lock` file, before changing anything.
2. Run the normal read-only comparison and `-audit-sync-state`. Review reported paths and file contents manually, including intended deletions and any partially created files.
3. Decide independently how to reconcile both trees. This preview offers **no automated repair, tombstone acceptance, state reset or deletion propagation**.
4. **Completed batch only:** If the pending state is v2 and **all** planned copies are already present with their originally recorded hashes, review `-check-pending-recovery` and optionally invoke the explicit zero-copy `-finalize-completed-batch`. It preserves a private no-overwrite archive and advances only that verified journal. There is no data copying in recovery.
5. **Incomplete or conflicted batch:** Do not finalize. Reconcile the two trees manually, preserve the old journal and `.lock` file as backups, and perform a **new** explicit `-init-sync-state` enrollment at a fresh path after identical-state verification. Never overwrite or silently reset a pending journal. The same procedure applies to legacy v1 journals.

## Important limitations

- **Not a distributed journal or true tombstone protocol:** It stores known shared content hashes, not version vectors, device-independent IDs, signed events, deletion approvals or replicated history. It cannot track files added and deleted entirely between polling intervals or while the process is stopped before it learns about them.
- **Single-machine assumption:** Canonical root paths are device-local. Moving directories, crossing devices or syncing through a network-mounted filesystem requires a separate design. Advisory locking is not a substitute for cluster consensus.
- **Partial batches are possible:** New files committed before a later error remain present. The pending marker prevents unattended retry but cannot restore a pre-operation filesystem snapshot.
- **Metadata and concurrent actors:** Modified timestamps, ownership, ACLs and xattrs are not replicated. The filesystem walker checks regular-file identity and hashes but does not make all directories atomic; hostile concurrent renames of parent directories are outside the safety guarantee.
- **Recovery is not a complete transaction replay:** V2 journals prove only the intended content-addressed *new additions*, not a complete snapshot of a mutable filesystem. A successful eligibility review is not authorization to modify user data. Recovery only finalizes an already completed batch; incomplete batches still need manual reconciliation.
- **Crash/power semantics depend on filesystem:** `fsync` and atomic rename help on standard local Unix filesystems but are not a verified cross-filesystem backup or recovery contract.
- **Resource use:** Every cycle rehashes all included files; large trees can consume significant disk I/O. JSON state is bounded to 16 MiB and 100,000 tracked files.
- **No service lifecycle:** Ctrl+C/SIGTERM ends the foreground worker. Nothing is installed as a daemon, scheduled or run unattended outside an actively started process. No actual two-device LAN Sync, native Linux/Android client, public hosting, or GitHub-hosted CI acceptance has been verified.

## Tests

Local verification includes Go unit/race tests for restart deletion protection, same-hash rewrites, both-side removals, mismatched roots or exclusions, corrupted/insecure/symlink state, pending recovery refusal, concurrent worker locks and matching untracked files. `bash tests/continuous-additions-cli.sh` exercises the enrolled CLI flow; `bash tests/durable-state-cli.sh` verifies persisted restart behavior and state readback; `bash tests/pending-recovery-cli.sh` verifies completed-batch proof, rejected incomplete batches, immutable private pending-journal backup, zero-copy finalization and subsequent deletion safeguards. Go unit tests also cover forged/tampered pending intent, changed known files, unexpected paths, archive collision and concurrent worker locks. These tests use disposable local directories; they do not certify production reliability.
