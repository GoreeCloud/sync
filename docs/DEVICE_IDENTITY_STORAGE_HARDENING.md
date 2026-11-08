# Device identity and trust-record storage hardening

**Status:** local development preview; not published, audited, deployed, or accepted on physical devices.

## Scope

`internal/deviceid` holds an Ed25519 private seed in a local `0600` `identity.json` and explicit pinned public-peer trust records under a private `trusted/` directory. The prior implementation checked paths with `Lstat` and then reopened or staged files using path-based `os.Open`, `os.CreateTemp`, `os.Link`, `os.ReadDir`, or `os.Remove`. A substituted symbolic-link ancestor could redirect one of those steps despite the earlier checks.

On **Linux and Android**, the new `private_file_linux.go` implementation:

- Traverses all absolute directory path components from `/` using `openat` and `O_DIRECTORY|O_NOFOLLOW`, refusing intermediate symlinks. Initial identity/trust directories are built with `mkdirat` and reopened without following symlinks. The identity/trust directory must be private (no group/other permissions).
- Reads records through the held directory descriptor using `openat(O_NOFOLLOW|O_NONBLOCK)`. It rejects FIFOs, sockets, directories and other special files, nonprivate files, over-limit records and files with additional hardlinks. It checks the opened inode and length around reads, and rechecks the pinned parent identity.
- Stages new `0600` records through the same pinned directory descriptor, uses a random no-overwrite name, `fsync`s the staged content and links the final name with no overwrite through `linkat`. Final staging-link removal and parent synchronization complete before successful return. Concurrent initializations/trust actions cannot overwrite the existing record.
- Lists peer records from the held directory descriptor, then verifies each signed fingerprint record through its normal independent trust validation. `Untrust` rechecks the record before a descriptor-relative `unlinkat` and synchronizes the parent before returning success.

The **macOS/Windows/other-platform fallback** remains guarded and path-based. Cross-compilation alone does not demonstrate native runtime behavior. This change neither rotates identities nor alters the Ed25519 signing, trust pinning, verification, network transfer, or offline inventory protocol.

## Remaining threat limits

The checks are **not** a filesystem-atomic operation or protection against a privileged/same-account attacker that can rename already-open directories between checks, replace inodes immediately before `unlinkat`, change bytes inside an open file, inspect process memory, steal the private seed, or tamper with the system clock. There is no hardware-backed identity keystore, complete private-key rollback protection, or key escrow/recovery. A crash **before** final cleanup may leave a private `.gc-identity-stage-*` artifact containing secret seed material. Such residues must not be uploaded, logged, published, or automatically deleted: isolate the owning private directory and review them manually before selecting recovery actions. Deletion does not prove secure erasure. Public rotation-proof input still has separate guarded path-based reads and is not covered by this change.

## Verification

```sh
go test -race ./internal/deviceid -count=2
go test -race ./...
go vet ./...
python3 -B tools/verify_source_manifest.py
bash tests/device-identity-cli.sh
bash tests/mutual-identity-cli.sh
bash tests/rotation-cli.sh
bash tests/confidential-offline-cli.sh
```

The Linux/Android tests cover linked ancestors, hardlinked seed and peer records, private modes, symlinked/special-file reads, no-overwrite publication, stage cleanup and concurrent trust enrollment. Any broader malicious-directory-relocation claim requires separate adversarial testing and a strengthened operating-system threat model.
