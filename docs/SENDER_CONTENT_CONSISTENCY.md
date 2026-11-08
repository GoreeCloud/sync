# Nearby Send — double-read source content check

**Status:** November 5, 2026, local experimental security hardening. Not published to GitHub or accepted on physical devices.

## What changed

Nearby Send now reads a regular source file **twice through the same opened descriptor** before encryption/upload. The first pass collects at most 20 MiB into memory. The second pass streams through a SHA-256 digest with an extra-byte limit, so it does **not** retain a second full copy. A mismatch in bytes or length refuses the transfer. Existing Linux/Android no-follow source opening and before/after pathname, inode, size and modification-time checks remain in place; other operating systems retain the weaker documented path-opening fallback.

This detects an important class of in-place modifications that a metadata-only check can miss: an adversary or another application changing a file's bytes without changing its length, then restoring its modification timestamp **between the two reads**. It also detects additions and truncations during the checked interval. Only the unchanged first-pass bytes are submitted to AES-GCM sealing.

## Limitations

- **Not an atomic snapshot.** Concurrent writes before the first pass, after the second pass, or reversible modifications that yield matching digests are not excluded. A malicious process controlling the source inode, its contents and timestamps can still defeat an observational consistency check. Filesystems may expose inconsistent or stale reads.
- This reads each source twice; transfers require roughly twice the file-reading I/O compared with the previous implementation and still buffer up to 20 MiB in memory. There is no streaming transfer, resume capability, or filesystem snapshot.
- An application requiring authoritative, consistent copies should use an immutable/test-file copy or filesystem snapshot produced and protected separately. This implementation does not create one.
- The transfer remains single-use and authenticated/encrypted as previously designed. Pairing-secret security, receiver directory confinement, crash residue, and network acceptance requirements remain independent and unresolved where documented.
- No real-device, hosted CI, production deployment, or Stable release is claimed.

## Regression checks

```sh
go test -race ./internal/lansend -run 'TestSourceSecondPass|TestStableSenderSource'
bash tests/sender-source-cli.sh
bash tests/lan-send-cli.sh
bash tests/secure-lan-cli.sh
```

The deterministic test rewrites an already-open file with different **same-length** bytes, restores the original modification timestamp, and verifies rejection by the second-pass digest comparison. Other tests cover appended/truncated files, clean empty/ordinary files and symlinked sources. The tests do not prove atomicity against hostile concurrent processes.
