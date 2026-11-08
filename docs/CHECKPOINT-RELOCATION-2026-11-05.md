# GoreeCloud Sync — Destination Identity and Recovery Checkpoint

**Date:** November 5, 2026 (America/Chicago)

**Status:** Locally tested, unpublished development source; not Stable, deployed, or independently audited.

## Scope and intent

My priority is to preserve files already held by users and keep experimental Sync operations fail-closed when filesystem paths cannot be trusted. This checkpoint changes only local Sync inventory and additions-only copying. It does not enable automatic deletion, overwriting, internet hosting, or unattended synchronization.

## Verified implementation

- Linux/Android destination staging keeps a directory descriptor for an atomic no-overwrite hardlink commit. It now records the original destination root's device/inode identity and rechecks that both the root and final directory are still reachable through the selected no-symlink path **immediately before and after** linking the file.
- A relocated or replaced directory or root discovered **before** commit refuses publication. If relocation is discovered **after** a successful hardlink, the function reports a **partial commit** rather than an unqualified success.
- An interrupted private `.gcsync-stage-*` inode is never treated as an ordinary source file during a walked inventory. The scan fails closed with its path; a file-level exclusion cannot hide an encountered stage artifact. Explicitly excluded entire subtrees are not traversed, so no files there can be copied. **No automatic stage cleanup** is performed.
- The portable non-Linux/non-Android target fallback remains path-based and requires trusted folder trees.

## Local validation evidence

Executed against the modified working source on Linux with Go 1.23.2 and Node 22.16.0:

- `go test -race ./...` — PASS, four packages.
- `go vet ./...` — PASS.
- `test -z "$(gofmt -l cmd internal)"` — PASS.
- Go CLI build — PASS.
- `node --check` for both browser script and encrypted integration script — PASS.
- `node tests/encrypted-roundtrip.mjs` — PASS: encrypted data, private metadata, tamper rejection, download limits, owner revocation.
- **All twelve** independent `tests/*.sh` CLI scripts — PASS, including Sync additions, durable restart, pending recovery, watcher, Nearby Send, device identity, mutual identity, signed rotation and pinned TLS.
- `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ...` — PASS, executable compile only.
- `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ...` — PASS, executable compile only, **not an APK or Android application**.
- `go test -cover ./internal/syncplan` — PASS, **82.3% statement coverage**.
- `docs/PRODUCT_SPEC.md` exactly matches the original supplied specification SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`.

## Explicit limits

There is **no atomic guarantee against an adversarial concurrent rename between the destination identity check and the hardlink commit**. The post-commit check may detect a moved destination only after a file was already created in that inode. No automatic rollback or user-file deletion is implemented. File metadata and inventory scans are not filesystem snapshots, and durable Sync requires trusted local directories and manually reconciled pending journals after incomplete operations.

The CLI builds are not real-device tests, physical LAN acceptance, native Android/Linux clients, backup verification, or security certification. Public GitHub `GoreeCloud/sync` still contains only its initial placeholder README in the last verified read; none of the local source changes are published or tested by hosted CI. No VPS or production systems were changed.

## Remaining priorities

Publish vetted source only through a permitted, authorized GitHub workflow; verify the exact committed tree and hosted CI; independently validate trusted two-device transfers; evaluate filesystem snapshot/inode relocation and recovery semantics; then build native Linux/Android clients and an explicitly reviewed network Sync protocol.
