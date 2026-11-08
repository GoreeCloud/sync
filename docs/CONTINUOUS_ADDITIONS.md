# GoreeCloud Sync — Foreground Additions-Only Replication (Experimental)

**Status:** Implemented and tested only against synthetic local folders; **not** network synchronization, automatic conflict resolution, a background service, or a backup. No production acceptance or real-device validation is claimed.

## Purpose and operating model

My longer-term GoreeCloud Sync direction is secure, version-aware replication between trusted devices. As a bounded intermediate implementation, I can explicitly start a **foreground-only** process that copies newly missing regular files **both ways** between two trusted, non-overlapping local directories. This uses the existing no-overwrite staged copier, not a second transfer engine.

```sh
# Review both trees before activating writes.
go run ./cmd/sync -plan-source ./left -plan-target ./right

# Requires initially MATCHING folders and a new private state file OUTSIDE both.
mkdir -m 700 ./private-sync-state
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -init-sync-state

# Explicitly authorize recurring local additions-only scans (15-second default).
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -sync-additions

# OPTIONAL ALTERNATIVE: For exclusions, use a SEPARATE new enrollment
# while the INCLUDED files on both sides match. Keep the same exclusions.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/filtered.json -init-sync-state \
  -exclude '*.tmp' -exclude 'private/**'
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/filtered.json -sync-additions -sync-interval 30s \
  -exclude '*.tmp' -exclude 'private/**'
```

Use **Ctrl+C** or SIGTERM to stop. The process does not install a service, persist itself, register a scheduled job or continue after its terminal exits.

Each interval invokes the existing `ApplyBidirectionalAdditionsFiltered` core through a guarded variant:

- SHA-256 comparison of two complete filtered inventories; no file modifications until preflight succeeds
- Abort before copying if *any* same-path regular files have divergent contents
- Reject overlaps, symbolic links, special files, invalid paths and unsupported exclusions
- Recheck each source file's identity and SHA-256 and write to a private staging file before an atomic no-overwrite hardlink commit
- Copy **at most 1,024 files and 1 GiB per scan**, counting both directions together
- Never overwrite existing files or propagate deletions, metadata changes or modification of an already shared path
- Stop on a failed scan, conflict, or partial filesystem error instead of retrying automatically
- Emit newline-delimited JSON with the first `snapshot`, subsequent nonempty `applied` events, and a final `stopped` event on error. Result fields identify actual file commits for each side; quiet scans do not emit heartbeats

### Durable deletion-resurrection safeguard

`-sync-additions` **now requires** an explicit private `-sync-state` file initialized with `-init-sync-state` while the filtered folders are identical. The state persists shared-file hashes across process restarts and refuses deleted or changed previously shared files before any new copies. Before a copy batch it records an atomic, fsynced **pending** marker; crashes leave it pending, requiring manual recovery rather than unattended retry. A second cooperating process is refused by an OS advisory lock.

A state does **not** authorize delete propagation, conflict resolution, overwrites, or unattended recovery. Version 2 records the content-addressed planned additions. A **completed** pending batch can be explicitly finalized without copying files if every expected hash matches and the previously shared files are unchanged. Incomplete or conflicted batches still require human reconciliation and fresh enrollment; see the durable state document. Polling still cannot learn about files created/deleted entirely between observations. Read [Durable Sync State](DURABLE_SYNC_STATE.md) for the setup, read-only audit, complete recovery process and platform limits.

## Threat model, limitations and recovery

- **Local-only and trusted directories:** This mode does not authenticate remote devices or exchange data over the network. The existing separate Nearby Send TLS and device identities do not automatically secure Sync folders.
- **Durable fail-closed state, not an atomic transaction:** A crash or error after some commits can leave completed additions. State remains `pending` until explicitly resolved; never treat restart as automatic recovery. A killed process may not emit its final JSON report. Inspect both trees and the state before manual recovery.
- **Concurrent path mutation:** Source data is revalidated, but an attacker or untrusted process that concurrently replaces destination parent directories is outside the safety boundary. Do not run on hostile or shared directories.
- **Polling:** Intermediate changes, rapid delete/recreate cycles, or file replacement between full scans may be missed. Every scan rereads and hashes all included files, potentially causing substantial disk I/O.
- **No overwrites or delete propagation:** Any change to the contents of an already shared same-path file is treated as a conflict. Manual additions cannot resolve conflicts or intentionally propagate edits; deletion and rename handling need future policy and versioning.
- **Metadata:** New files use 0600 permissions and directories use 0700; timestamps, ownership, ACLs, extended attributes and original modes are not retained.
- **Operational scope:** No native Linux/Android UI, remote peer discovery, resumable network sync, mutual authentication for Sync, hosted CI, multi-device acceptance, or production release is implied.

For recovery, stop the command, run the read-only `-plan-source/-plan-target` comparison, review `-baseline` historical changes if you have a verified existing checkpoint, and back up data outside both trees before deciding which files to preserve or remove. Do not rely on restarting this command to resolve ambiguous deletions or pending batches; the command now refuses automatic continuation until a new verified enrollment after manual reconciliation.

## Verification

The local regression tests include first-cycle bidirectional additions, later-cycle propagation, unchanged-cycle silence, symmetric exclusions, interval validation, cancellation, symlink rejection, differing-content fail-closed behavior, and **no silent resurrection of previously shared files during one foreground session**. The synthetic CLI check also tests process signals and rejects combinations with read-only watch, manual copy, and non-opted polling flags. Publication and platform-specific acceptance are separate requirements.
