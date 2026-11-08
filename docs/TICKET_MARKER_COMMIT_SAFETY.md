# One-use ticket marker commit safety — local development preview

**Status:** source and local tests only. No hosted CI, actual multi-device acceptance, independent audit, public repository source commit, or deployment.

## What changed and why

Signed offline-inventory comparisons use private one-use tickets stored outside the compared folders. A successful verification must durably create an adjacent `.used` hardlink before returning a read-only comparison. Previously the final commit used pathname-based `os.Link(ticketPath, ticketPath + ".used")` after the rest of the ticket handling was hardened. A symlink or ancestor substitution between validation and publication could redirect that final operation.

For **Linux and Android**, `consumeOneUseTicket` now:

1. Opens the complete private parent path from `/` using `openat(O_DIRECTORY|O_NOFOLLOW)` for every component, and verifies the held directory remains private (`0700`) and reachable at that pathname.
2. Opens the ticket through the **held parent descriptor** using `openat(O_NOFOLLOW|O_NONBLOCK)`. Refuses special files, non-`0600` permissions, sizes outside 64–4096 bytes, or tickets with multiple hardlinks.
3. Parses strict JSON from the opened inode and verifies the previously validated ticket body checksum. Reopens the same name through the held parent and refuses a changed inode.
4. Rechecks the parent's path identity, and publishes `<ticket>.used` with `linkat` against **the same directory descriptor**, without symlink following or replacing an existing marker. Only one concurrent consumer can win.
5. Syncs the parent directory before returning success; rechecks parent reachability and that the published marker is the original ticket inode. If a postcommit check fails, it **does not remove the spent marker**; it reports uncertain state requiring manual review.

The previously verified peer Ed25519 signature, signed challenge, encrypted-envelope authentication, local scan, and ticket's expected root/exclusions are still checked **before** ticket consumption. Both compared folders remain read-only. On macOS/Windows and other systems, the guarded pathname-based fallback does not provide equivalent concurrency protection. Compile-only cross-builds are not native runtime acceptance.

## Remaining risks

- A same-account or privileged adversary may move a pinned directory *between* pathname checks, replace names, mutate file contents, delete the marker, or restore an older backup. This is **not** a kernel-level move lock or a rollback-resistant/distributed replay ledger.
- A successfully linked marker is retained even if later metadata verification or directory sync fails. Treat the ticket as potentially consumed, inspect the directory, and issue a new ticket with a new name. Never silently delete `.used` to recover.
- Private files may include trusted-peer identifiers and absolute local paths. Do not upload the ticket or grant others access to the private directory. The ticket integrity SHA-256 is an accidental-corruption check, not a cryptographic authenticator.
- This improvement does not choose a repository license, publish source, encrypt legacy plaintext inventory exports, add authenticated network synchronization, or authorize physical-device operations.

## Local verification

```sh
go test -race -count=2 ./...
go test -race ./internal/syncplan -run 'TestTicketMarker|TestOneUse' -count=1
go vet ./...
bash tests/one-use-challenge-cli.sh
python3 -B -m unittest discover -s tools -p 'test_*.py'
python3 -B tools/verify_source_manifest.py
```

The strict source manifest must be regenerated after approved edits and verified again in the final clean-extracted source package. Hosted GitHub checks and physical-device testing remain separate acceptance gates.
