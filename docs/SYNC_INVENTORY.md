# GoreeCloud Sync — Local folder comparison and additions-only copy foundation

**Status:** Read-only local comparison, an explicitly invoked additions-only local copier, and experimental read-only three-way historical conflict planning. No network-based folder synchronization, durable deletion-aware synchronization, overwrite, deletion propagation, or automatic conflict resolution. A separate explicitly opted-in, **foreground, local-only recurring additions** mode has been added; see [CONTINUOUS_ADDITIONS.md](CONTINUOUS_ADDITIONS.md). It is non-durable and must not be mistaken for full Sync. A separate encrypted one-file Nearby Send CLI exists.

My long-term objective is secure, selective, conflict-aware synchronization between trusted devices. The default command computes a **read-only local plan**. A separate opt-in command can copy only source-only regular files into a local target. No existing target file is changed.

## How to run

From the project root, with Go 1.23+ installed:

```sh
go run ./cmd/sync -plan-source /path/to/source -plan-target /path/to/target
```

The output is JSON. File entries contain paths relative to their respective roots, byte sizes and SHA-256 content digests. The summary reports counts for:

- `identical`: both folders contain the same relative regular file with the same bytes;
- `source-only`: only the source contains the file;
- `target-only`: only the target contains the file;
- `different`: both contain the file but content or size differs.

**These are observations, not action instructions.** In particular, a `target-only` file is not a deletion recommendation, and `different` files require a deliberate conflict policy before any future overwrite.

## Explicit local additions-only application

```sh
# First review the read-only summary.
go run ./cmd/sync -plan-source ./source -plan-target ./target
# Then opt in explicitly. NEVER run this on live or irreplaceable data before review.
go run ./cmd/sync -plan-source ./source -plan-target ./target -apply-additions
```

### Selective exclusions (opt-in)

Apply a repeatable `-exclude` flag to both planning and manual additions:

```sh
go run ./cmd/sync -plan-source ./source -plan-target ./target -exclude '*.tmp' -exclude 'private/**'
go run ./cmd/sync -plan-source ./source -plan-target ./target -exclude '*.tmp' -exclude 'private/**' -apply-additions
```

- `*.tmp`: ignores matching basenames at any directory depth.
- `build/*.o`: ignores matching root-relative paths one level beneath `build`.
- `private/**`: ignores a literally named `private` directory at the root and everything below it.
- `.git`: skips a named `.git` directory wherever encountered.

Exclusion patterns are validated, limited to 64 entries, and evaluated identically in source and target. No exclusion is enabled by default. A directory excluded by a rule is not traversed, so excluded symlinks are not inspected; otherwise symlinks and special files cause an error. The grammar is not a Syncthing `.stignore` clone: there are no negative overrides, full `**` globs, device-specific policies, or persisted ignore configuration. Review the filtered read-only plan before copying, since excluded content is invisible to the plan and apply engine.

The apply command compares both trees again and **aborts without copying anything if any same-path file has different bytes**. It does not copy `target-only` files back, overwrite matching names, propagate deletions, or resolve conflicts. It rejects symlinks, special files, identical/overlapping roots, invalid relative paths, and changed source SHA-256 checksums. It also caps one batch at 1,024 new files and 1 GiB of new content.

For each new file, the implementation checks its identity and hash, stages bytes in a private temporary file, syncs them to disk, and creates the destination name using a no-overwrite hardlink. Newly created files use private `0600` permissions and new directories use `0700` permissions where supported. The target filesystem must support hardlinks. Existing target files are never deliberately replaced.

**Partial failure behavior:** There is no multi-file transaction: if a later file conflicts with an existing destination directory, or copying fails after earlier additions, those earlier additions remain. The JSON `created` list records files already created; `applied=false` indicates incomplete execution. Some newly created empty directories can remain after failure. Do not mistake a partial result for a successful all-or-nothing sync. The command has no rollback, version archive, deletion, retry or background processing.

**Threat-model limitation:** Portable path-based checks cannot prevent a malicious same-user process from swapping parent directories or filenames during an operation. The current code must not run with elevated privileges, against adversarial/multi-user writable trees, or as a public file write API. Copying a file does not make an independent backup of its prior versions.

## Security and correctness boundaries

- Both roots must already exist and be real directories (not symbolic links).
- Symbolic links and non-regular files encountered along non-excluded paths cause an error; they are not followed. Explicitly excluded paths are not examined.
- All files are read through streaming SHA-256; content is not copied into an application store.
- Hashes, relative paths and sizes may be sensitive. JSON output must remain local and should not be sent to a public issue, logs or telemetry without explicit review.
- The scanner checks file identity, size and modification timestamp before and after hashing, but does not offer a transactional filesystem snapshot. In-place modifications that preserve those indicators may evade the comparison; the apply command also rechecks actual content hashes before committing new files.
- Basic opt-in exclusions are supported, but not advanced Syncthing-compatible ignore rules, cross-platform file metadata policy, incremental block hashing, permissions mapping, mount traversal control, encrypted transport, trusted identities, or multi-device protocol negotiation.
- Never run the planner assuming it creates an independent backup; it does not.

## Next acceptance work

1. Introduce consistent snapshots or block-index state, user-controlled persistent ignore profiles, and richer exclusions with testable precedence.
2. Specify a trusted-device protocol, authenticated encrypted transport and per-folder authorization.
3. Design two-way conflict handling, atomic staging, deletion safeguards, recovery and tests with disconnected devices.
4. Add a transaction/recovery journal, verified rollback policy, file-change event integration and platform-specific no-symlink path handling before expanding beyond the opt-in additions-only preview.

Only the explicit local additions-only copy is implemented. No deletion, overwrite, two-way or network synchronization is implemented.

## Experimental three-way planner (read-only)

The separate immutable, version-2 baseline workflow records only matching common local folder states and refuses use with swapped or unrelated source/target roots. Historical classification can distinguish one-sided edits and deletions from add/add, modify/modify, and modify/delete conflicts; it never propagates changes. This does not change the earlier limited additions-only copier, and no command permits applying a historical plan. See [three-way planner design and CLI examples](THREE_WAY_PLANNING.md).
