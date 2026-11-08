# Manual, bidirectional additions-only replication (experimental)

My GoreeCloud Sync vision includes fully automatic, conflict-aware synchronization. I have implemented a much narrower **manual, additions-only** command for trusted local directories so that newly created files on either side can be shared without overwriting existing data or propagating deletions. This must not be described as a complete, automated or network-based synchronization engine.

## Inspect first, then act explicitly

```sh
# Inspect a complete SHA-256 comparison without changing either directory.
go run ./cmd/sync -plan-source ./left -plan-target ./right

# Manually opt in to copying new files in BOTH directions.
go run ./cmd/sync -plan-source ./left -plan-target ./right -apply-both-additions

# Restrict both inventories with the SAME explicit excludes.
go run ./cmd/sync -plan-source ./left -plan-target ./right -exclude '*.tmp' -exclude 'cache/**' -apply-both-additions
```

The command produces a JSON result with `mode: "bidirectional-additions-only"`, `applied`, `leftCreated` (newly created in the left directory from the right), `rightCreated` (newly created in the right directory from the left), `bytesWritten`, `unchanged`, and `conflicts`. An error result can contain **already committed paths**, even when `applied` is `false`. Read and retain this report if a run fails.

## What the command permits

- Copies only included **regular files absent on the other side**. Identical files are preserved without rewriting them.
- Refuses **all** additions if any included relative path exists on both sides with divergent content at preflight. A manual conflict decision must be made before retrying.
- Computes SHA-256 inventories and verifies file contents/identity again during the copy. New destination files are staged in a private `0600` file and committed with a no-overwrite hardlink. Newly needed directories are created with `0700` when possible.
- Enforces a **combined** maximum of 1,024 additions and 1 GiB of newly copied data across both directions in a single run. No implicit exclusions are enabled; excluded patterns apply symmetrically.
- Refuses overlapping roots, included symbolic links, special files and any request mixed with `-watch`, historical `-baseline`, `-capture-baseline` or the separate one-way `-apply-additions` mode.
- Returns a deterministic, sorted path list of files that actually committed, including when a later copy fails.

## Important limitations

- **Not atomic:** if a later copy fails, previously copied files remain and may need a manual review. There is no automatic rollback or two-phase commit.
- **No overwriting, deletions, rename detection, streaming transfer, network transport, resuming, metadata preservation or historical conflict resolution.** New files are deliberately restricted to safe additions.
- Local destination filesystem must support hardlinks; existing ACLs, ownership, timestamps and extended attributes are not preserved. Private default file and directory permissions are applied.
- Source and target directories must be trusted, locally controlled and **not modified concurrently by a malicious user or process**. Portable pathname operations cannot defend against hostile parent-directory swaps. Concurrent benign changes may abort an individual copy or lead to an incomplete batch.
- A preflight SHA-256 comparison is not an atomic filesystem snapshot. This is not an independently validated backup and must not replace an existing backup solution.
- It is a one-shot manual command. It does **not** continue after the process exits or act automatically on the read-only `-watch` output.

## Verification

`go test -race ./...` and `bash tests/bidirectional-cli.sh` cover synthetic two-way additions, exclusions, idempotence, exact file preservation, divergent-path preflight refusal, combined file limit, partial commit reporting, and unsafe write-mode combinations. These tests do not constitute physical-device validation, hostile-filesystem race safety, or a Stable release.
