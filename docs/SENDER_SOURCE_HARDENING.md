# Nearby Send — sender source-path hardening (local preview)

**Status:** November 5, 2026. Local code and tests only; not published, deployed, or accepted on physical devices.

## Security issue and implemented boundary

A file transfer sender previously checked the source using `Lstat`, but opened it later using an unrestricted pathname. A symlink substitution between those operations could redirect the read. Checks after the read might prevent upload, but would not undo an unintended local read.

On **Linux and Android**, `openSenderSource` now resolves the absolute source path one component at a time with `openat` against pinned directory file descriptors, using `O_NOFOLLOW` at every level. The final descriptor is verified as a regular file before contents are read, and `O_NONBLOCK` avoids blocking on a substituted FIFO or special entry. The existing sender checks after reading that its descriptor matches the original/final `Lstat` identity, file size, and modification time, and refuses upload on a detected change. File contents remain capped at 20 MiB. The encrypted transfer, authentication and one-time receipt protocol are unchanged.

On **macOS, Windows, and other platforms**, a portable `Lstat` component walk rejects symlinks visible during preflight and refuses non-regular files, but it cannot guarantee that parent paths remain unchanged between the checks and `os.Open`. Do not treat cross-compilation as an acceptance of the filesystem threat model on these platforms.

## Limits

- A privileged or same-user process can change the contents of an already-open regular inode; `Lstat` identity and mtime checks are **not** atomic content snapshots. Modified contents can evade timestamp-based checks in adversarial scenarios.
- A malicious process can relocate a directory after it is opened. The pinned descriptor prevents following a substituted symlink into a different inode but cannot prevent a source directory's own contents from being edited concurrently.
- Source path components that are symlinks are intentionally rejected, including symlinked parent directories. Use a direct real path to a trusted file.
- Sending uses bounded in-memory buffering, not streaming or resumable transfer. The 256-bit one-time pairing key still must be provided through a trusted private out-of-band channel.
- No hosted CI, native application, physical LAN acceptance, or security audit is claimed.

## Local verification

```sh
go test -race -count=2 ./internal/lansend -run 'TestSenderSource|TestEndToEndPrivateLoopback'
bash tests/lan-send-cli.sh
bash tests/sender-source-cli.sh
bash tests/secure-lan-cli.sh
```

Tests cover ordinary encrypted transfer, direct and ancestor symlink rejection, a pinned regular descriptor after a pathname substitution, missing/invalid paths, and a FIFO opened without blocking (Linux/Android). They do not establish a proof of safety against all concurrent filesystem attacks.
