# Journal and Source-Path Hardening — Development Checkpoint

**Status:** Locally tested implementation, not a production security certification or a Stable release.

## Purpose

The local additions-only Sync workflow records a pending copy journal before modifying either folder. In the prior preview, its copier rescanned the folders after creating the pending journal; a newly appearing file could therefore be copied even though it was not included in the recorded intents. The read-only inventory also used a path-based file open that could follow a symbolic link substituted between its directory walk and the actual open.

This checkpoint narrows both risks while preserving the existing no-overwrite, no-deletion policy.

## Exact journaled batch

- A durable cycle inventories both roots and validates previously shared hashes, conflicts and resource limits.
- The pending state records the **exact path, direction, size and SHA-256** of each planned copy.
- The worker now copies from **that specific in-memory plan**. It does not call the normal re-planning entry point after persisting the pending state.
- Each file is independently rehashed while staged; a changed file is not committed under an obsolete checksum.
- The final scan requires the **exact same set of paths** as the earlier plan, all with identical content on both sides and exactly the expected SHA-256 hashes. This also checks files that were already identical before the copy.
- Unexpected additions, removals, or changed bytes leave the operation in its pending state for explicit review. A partially committed new file is reported where possible; no automatic retry, deletion or rollback occurs.
- The read-only pending audit and explicit zero-copy finalize rules remain unchanged.

## File-read boundaries

On **Linux and Android**, inventory and copy reads use directory descriptors with `openat` and `O_NOFOLLOW` on **every path component**, including the final file. Traversal and noncanonical relative names are rejected. Lstat/file identity, size, modification time, and SHA-256 checks still run. This reduces symlink substitution risk in source file opening.

On other operating systems, a guarded path-based fallback performs component checks and file-identity verification, but does not provide the same protection against hostile concurrent path replacement. Unix advisory locking of durable state remains a separate requirement. The Go backend cross-compiling is not evidence of a native Android app.

**Not solved:** Path-based destination directory creation and hardlink commits can still race a malicious actor who has write access to ancestor directories. A non-atomic filesystem can change after a completed inventory; no filesystem snapshot is taken. An attacker with access to the journal directory can alter the journal or replace the lock file. This preview requires two locally trusted directory trees. Do not use this to automatically synchronize untrusted, adversarial, remote-mounted or production-critical data.

## Verification

Local commands:

```sh
go test -race ./...
go vet ./...
go build ./cmd/sync
node tests/encrypted-roundtrip.mjs
bash tests/durable-state-cli.sh
bash tests/pending-recovery-cli.sh
```

Additional Go regressions specifically check that symlink components are rejected, newly arriving unjournaled files are not copied from a previously captured plan, changed previously identical files fail finalization, and all existing Sync safety tests remain valid. The full CLI and crypto integration suite is rechecked for compatibility; see `docs/VALIDATION.md` for the latest source-local evidence.

**Publication boundary:** Passing these local tests does not establish GitHub publication, hosted CI, actual two-device tests, native clients, or secure unattended operation.
