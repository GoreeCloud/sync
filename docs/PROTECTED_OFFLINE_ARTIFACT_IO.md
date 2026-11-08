# Protected offline artifact I/O — local development preview

**Status:** implementation and local regression tests only; no hosted CI, physical-device acceptance, public release or deployment.

## Threat and change

Offline inventory keys, signed/encrypted inventory exports and one-use challenge tickets are sensitive local artifacts. Previously their read and staged no-overwrite publish operations used pathname-based `os.Open`, `os.CreateTemp` and `os.Link`. An attacker able to change an intermediate directory into a symlink between a preflight and use could redirect a file operation.

On **Linux and Android**, this checkpoint adds:

- **Component-anchored reads:** walk from `/` through each directory component using `openat` with `O_DIRECTORY|O_NOFOLLOW`. Open the final input file through the held directory descriptor with `O_NOFOLLOW|O_NONBLOCK`, verify that the opened file is regular, and keep existing `Lstat`/opened-inode identity comparisons. Replaced ancestors are not followed through symlinks.
- **Key hardlink refusal:** an offline inventory encryption key must have exactly one link (`st_nlink=1`) as well as the existing private `0600` mode and strict 64-lowercase-hex plus newline format. This prevents a second hardlink alias from silently extending retention of a key. A duplicate *copy* or an attacker with same-account access is not detected.
- **Component-anchored exports:** open the destination parent through the same no-follow directory walk. Create a random private `0600` stage file using `openat(O_EXCL|O_NOFOLLOW)` and sync it. Publish inside the **same pinned directory FD** using `linkat` with no overwrite; verify parent inode/path identity immediately before and after publication and sync the parent. Remove the stage by `unlinkat` relative to the pinned directory on normal return, including collision/failure.
- **Ticket marker consumption:** after trusted offline comparison, Linux/Android now reopens the challenge ticket and atomically creates `.used` through the same pinned private parent descriptor, verifying the ticket inode, no hardlinks, validated content and parent identity. Directory sync completes before success; a marker is deliberately retained if later verification reports uncertainty. See [one-use marker commit safety](TICKET_MARKER_COMMIT_SAFETY.md).
- **Special-file refusal:** input FIFOs, sockets, devices and directories are not accepted, and the nonblocking input open avoids hanging on an attacker-substituted FIFO.

These are local artifact I/O protections, **not** a general filesystem sandbox or an atomic snapshot. A concurrent attacker can relocate an already-open destination directory between path-identity checks, or mutate file contents while opened. If a final file was already published when a postcommit check fails, the command reports uncertainty rather than deleting it. As before, input inventory signatures and encrypted envelopes must pass their independent cryptographic checks. On **Windows, macOS and other platforms**, the existing conservative pathname-based fallback remains; it rejects obvious symlinks but offers weaker race guarantees. Cross-compilation is not runtime acceptance.

## Privacy, durability and recovery

Offline inventory encryption keys and decrypted inventory bytes may exist in process memory. Newly created key files are `0600` within an existing private `0700` parent; a **crash may leave a private `.gcsync-offline-inventory-*` stage** containing key material or plaintext signed inventory metadata if one of those is being written. The staging filename is shared by all offline artifacts. Do not publish, upload, or automatically sweep such residues. If found, review them in the owning private directory and follow an intentional retention/recovery procedure. Remove only after authorized review; deleting the stage is not verified secure erase. Encrypted exports are staged as ciphertext only, but a *plaintext signed inventory export* can leave plaintext metadata in its stage. Keys require separate confidential authenticated exchange and cannot be recovered if the required key is lost.

## Verification

Run:

```sh
go test -race ./internal/syncplan -run 'TestProtected|TestConfidential|TestInventoryKey|TestPaddedConfidential|TestLegacyConfidential' -count=1
go test -race ./...
go vet ./...
python3 -B tools/verify_source_manifest.py
bash tests/confidential-offline-cli.sh
bash tests/one-use-challenge-cli.sh
```

Linux regression tests exercise ancestor symlinks, hardlinked keys, FIFO nonblocking refusal, stage cleanup, no-overwrite, `0600` permissions and refusing symlink destinations. These do not constitute a hostile concurrent filesystem stress test or independently audited security guarantee. Native Android/Windows/macOS acceptance remains a separate release gate.
