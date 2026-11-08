# Nearby Send — receiver destination hardening (local preview)

**Status:** November 5, 2026 source-only hardening; no public service, native release, or real-device acceptance.

## Implemented

On Linux and Android, a Nearby Send receiver now opens its selected private destination directory using `O_DIRECTORY | O_NOFOLLOW`, checks directory privacy, and keeps a descriptor to that original inode while staging the plaintext file. A random `.gcsend-stage-*` file is created with `openat(O_EXCL, 0600)`, synced, and published using `linkat` relative to the same held directory descriptor. Existing final filenames are never overwritten. The containing directory is synced, and the stage is unlinked relative to the descriptor during cleanup.

The receiver checks that the destination pathname still identifies the original directory immediately **before** the no-overwrite link, and again afterward. If the path was replaced before commit, it refuses to publish. If the path is moved immediately after publication, it reports uncertainty rather than falsely claiming successful persistence. Independent tests cover post-open root replacement, symlink substitution, final-file creation during staging, permissions, no staging residue after success, and end-to-end encrypted transfer.

Other platforms preserve the prior guarded path-based implementation, which is less resilient to hostile concurrent ancestor changes. All platforms still enforce valid leaf filenames, 20 MiB maximum received payload, a private destination directory, AES-GCM encryption, HMAC upload authentication, and single-use receiver semantics.

## Threat model and limits

- This is a **local application hardening step**, not a robust filesystem sandbox or atomic transaction. Concurrent malicious renames **between** root-identity checks can still relocate an open directory. A malicious same-user process may also mutate an opened inode or manipulate ancestor directory names.
- A successful hardlink may precede a failed directory sync or post-commit check. The call then returns an error but the new file may remain, and a retry must not overwrite it. User files are never removed automatically.
- A sudden process crash can leave a private `.gcsend-stage-*` artifact. Inspect and reconcile such files manually rather than treating them as valid received content. It is not auto-cleaned after a crash.
- Destination permissions are restricted to private user directories, but local malware with the same account privileges remains outside this preview's security guarantees.
- Network transport still requires secret-pinned TLS for non-loopback LAN and independently verified identity proofs when enabled. Physical two-device transfer has not been exercised.

## Verification

Run `go test -race ./internal/lansend` and `bash tests/lan-send-cli.sh`; the standard CI workflow runs the full Go race suite, these regression tests, and the existing encrypted-transfer tests. Hosted CI has not run for this unpublished source checkpoint.
