# GoreeCloud Sync — Three-way change and conflict planner

**Status:** Unreleased, local-only, read-only prototype. No automatic copying, deletion, overwrite, merge, conflict resolution, or network synchronization is authorized by these commands.

My objective is to distinguish a file intentionally deleted on one device from a file newly added on the other, without making a destructive guess. A two-folder comparison alone cannot distinguish these histories; the experimental three-way planner uses a **previously verified common state**.

## 1. Capture a common baseline

On a trusted local machine, with two disjoint, previously synchronized directories, run:

```sh
# Only use test directories during development.
go run ./cmd/sync -plan-source ./source -plan-target ./target \
  -exclude '*.tmp' -capture-baseline ./initial-baseline.json
```

Both filtered directory trees must already match byte-for-byte. The tool records a JSON checkpoint with SHA-256 hashes, sizes, canonical absolute source/target roots, and normalized exclusions. Its schema version is **2**. The checkpoint is created as an immutable-by-command file with `0600` permissions outside both trees; it is **not encrypted**, backed up, or cryptographically authenticated. The output location's directory must already exist and support hardlinks. Retain the checkpoint securely and do not copy it into a publicly indexed folder.

**Baseline identity is directional:** the captured source and target paths are pinned to their resolved absolute paths. Swapping the roots, changing either directory path, or changing its exclusion list causes a hard failure. Recreate a checkpoint only from *matching* trustworthy folder contents. Older experimental v1 checkpoints are rejected rather than silently misinterpreted.

## 2. Compare changed trees without modifying them

After experimenting with edits, additions, and deletions in either folder:

```sh
go run ./cmd/sync -plan-source ./source -plan-target ./target \
  -exclude '*.tmp' -baseline ./initial-baseline.json
```

The output contains a `readOnly: true` marker, a count of detected conflicts, and a sorted array of relative-path observations. The planner uses streaming SHA-256 hashes and classifies each path:

| Status | Interpretation |
| --- | --- |
| `unchanged` | Both sides still equal their shared baseline |
| `converged` | Both sides now have the same content, whether changed or newly added |
| `source-added` / `target-added` | A file exists on only one side and was absent from the baseline |
| `source-modified` / `target-modified` | One side changed content; the other still matches the baseline |
| `source-deleted` / `target-deleted` | One side removed a baseline file; the other still matches the baseline |
| `deleted-both` | Both sides removed the same baseline file |
| `conflict-add-add` | Both sides added different files at the same path |
| `conflict-modify-modify` | Both independently changed a baseline file to different contents |
| `conflict-modify-delete` | One side modified content while the other removed its baseline file |

These are **observations, not instructions to perform a filesystem operation**. In particular, `source-deleted` is not a mandate to delete the target's copy. There is no operation in this preview that applies a three-way plan, even for non-conflicting changes.

## 3. Non-negotiable limitations

- **No immutable filesystem snapshot.** Contents can change during a scan. The scanner checks file identity, timestamps, sizes and hashes, but cannot defend against an adversarial concurrent directory writer or specially timed edits.
- **No deletion propagation.** The planner never deletes or overwrites files; no automated conflict resolution exists. `-baseline` is incompatible with `-apply-additions`.
- **No device identity or distributed state.** Absolute root binding prevents some accidental misapplications on a single local filesystem. It is not a secure device certificate, persisted peer pairing or remote trust relationship.
- **No directory-history semantics.** Folder renames appear as sets of file deletions and additions; empty directories, ACLs, symlinks, timestamps, ownership, metadata and extended attributes are not synchronized.
- **No transactional recovery or persistent revision history.** A checkpoint is not a backup. Back up important data separately before experimenting.
- **No incremental/block index.** Full-file SHA-256 scans can be expensive for large files or slow storage. Exclusions are explicit and are fixed to the baseline.
- **No compatibility guarantee.** The experimental v1 checkpoint format is intentionally rejected by schema v2. Neither format is a stabilized file or network protocol.

## 4. Verification

```sh
go test -race ./internal/syncplan
bash tests/historical-cli.sh
```

Tests cover unilateral edits and deletions, common changes, add/add and modify/modify conflicts, modify/delete conflicts, wrong root orientation, unrelated roots, immutable checkpoint behavior, private file permissions, exclusions, malformed JSON, unsafe paths, and enforcement of read-only mode. These tests use synthetic local directories; they do not establish real two-device, platform-specific or production acceptance.
