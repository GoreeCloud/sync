# GoreeCloud Sync — Destination Path and No-Overwrite Hardening

**Status:** Experimental local development checkpoint, November 5, 2026 (additional destination-identity and interrupted-stage checks). This is not an independent security audit or Stable-release acceptance.

## Purpose and scope

My direction is to make GoreeCloud Sync preserve existing user data and refuse unsafe path redirection. This change reduces the risk that a destination symlink substituted during a local additions-only copy causes a file to be created outside the intended folder. The existing one-way, two-way, and durable foreground additions flows reuse the same staging helper; there is no new automatic-copy mode.

## Linux and Android implementation

- The copier opens the destination root as a real directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
- It walks each destination directory component using `openat` on an already-open directory handle, never by following a symlink. Missing components are created with private mode `0700` using `mkdirat`, followed by no-follow reopening.
- The new file is written to a random, private `0600` staging inode created with `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` in the opened destination directory. The source bytes are rehashed and checked against the reviewed content plan, and the staging file is synced before publication.
- A direct Linux `linkat` operation uses the **same pinned destination directory descriptor** for the staging and final names. It cannot overwrite an existing final name; `EEXIST` is a refusal, not an implicit replacement.
- The destination directory is synced after the hardlink commit. The private staging name is unlinked on exit, including failed copies. A directory-sync error after the hardlink is reported as a possible partial commit.
- Before and after publication, the copier reopens the original destination root and walks from it with no-follow operations, confirming the original root device/inode and the final directory device/inode still match. A relocated directory, ancestor or root causes a refusal before publication. A relocation found after publication is reported as a **partial commit**, never a clean success.
- A race that substitutes a symlink at the original path after opening the directory does **not** cause this commit to follow that symlink. The new pre-commit identity check also refuses to publish into the old, moved inode in the common relocated-directory case. Source reads retain their separate no-follow descriptor walk.

## Other platforms

The non-Linux fallback continues guarded path-based staging and an `os.Link` no-overwrite commit. It checks directory components for symlinks but does not offer the same pinned-directory protection against concurrent path changes. No claim of equal Windows or macOS security behavior is made.

## Explicit limitations

- A malicious process with permission to **rename or relocate an already-open directory inode** can still win a race **between the new identity check and the final `linkat`**. The post-commit check only detects some such races **after** a possible partial commit. These checks are not atomic path confinement, filesystem snapshots or a secure multi-user sandbox.
- The initial inventory, ordered paths and final inventory are not filesystem-atomic. User edits during copying are checked where possible; hostile concurrent writes, hardlink manipulation and storage races require additional protection and design review.
- A sudden power loss between commit and staging cleanup can leave private `.gcsync-stage-*` entries. The local inventory now **fails closed** if it encounters any staging-namespace entry, even if an individual-file exclusion would hide it; it does not replicate an orphan as a user file. Fully excluded directories are not traversed and cannot be copied. No automatic orphan deletion is authorized; inspect residual data and any pending durable journal before manually removing artifacts.
- Existing files are never intentionally overwritten, but partial **new-file** commits can occur before a subsequent failure. The durable journal records intended files and requires explicit recovery or reconciliation.
- `GOOS=android` command-line cross-compilation is not evidence of a native Android user interface, APK packaging or physical-device testing. Existing network Send/Share and production security boundaries are unchanged.

The authorized use remains trusted local folder trees, manual review, and experimental development. Do not run this as unattended, adversarial-folder, or production-critical backup software.

## Verification

Relevant regression tests are in `internal/syncplan/staged_target_linux_test.go`: symlinked root and components, bad relative paths, existing-file races, symlink substitution after pinning a destination directory (now **refused**), parent and root relocation/replacement, and cleanup following checksum failure. `internal/syncplan/staging_residue_test.go` verifies fail-closed behavior for interrupted staging artifacts. Existing tests cover exact durable journaled copy plans and no-overwrite behavior.

Commands executed locally for this checkpoint:

```sh
go test -race ./...
go vet ./...
go build ./cmd/sync
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/gcsync-linux-arm64 ./cmd/sync
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o /tmp/gcsync-android-arm64 ./cmd/sync
```

These checks do not replace hosted CI, physical-device tests, or security review appropriate for a future networked Sync engine.
