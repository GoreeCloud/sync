# GoreeCloud Sync

**Early development preview — not production-ready.**

**License:** [MIT](LICENSE) (`SPDX-License-Identifier: MIT`), Copyright (c) 2026 GoreeCloud. The license is selected for this repository's original software and associated documentation, subject to rights in any separately attributed third-party material. This local source package is not yet committed to GitHub. See [license decision and release checks](docs/PUBLICATION_LICENSE_GATE.md).

**Device identity-store hardening (November 7, 2026 — local/unpublished):** Linux/Android now protect Ed25519 seed and explicit pinned-peer trust files with component-by-component no-symlink directory-descriptor reads, private no-overwrite writes, and descriptor-relative untrust removal. Additional hardlinks, special files, symlinked ancestors and concurrent trust overwrites are rejected. Same-account directory relocation, in-place mutation, recovery stage residue and macOS/Windows path races remain outside the guarantee. See [device identity storage security](docs/DEVICE_IDENTITY_STORAGE_HARDENING.md).

**Protected offline artifacts (November 7, 2026 — local/unpublished):** On Linux/Android, private inventory keys, export files and one-use tickets now use no-follow, directory-handle-anchored reads and staged no-overwrite publishing, with hardlink refusal for symmetric keys. Other platforms retain a weaker path-based fallback; crash stages can contain sensitive bytes. See [protected offline artifact I/O](docs/PROTECTED_OFFLINE_ARTIFACT_IO.md).

**One-use marker commit hardening (November 7, 2026 — local/unpublished):** On Linux/Android, the persistent `.used` ticket marker is now linked and synced through the same pinned no-symlink private-directory descriptor used to reopen and verify the one-use ticket. It rejects symlinked parents, preexisting markers, multiply-linked tickets, and changed ticket contents at commit. Non-Linux/Android still has a weaker guarded pathname fallback. See [ticket marker safety](docs/TICKET_MARKER_COMMIT_SAFETY.md).

**Confidential offline inventory (November 7, 2026 — local/unpublished):** Optional `-new-inventory-key` creates a private 256-bit exchange key file, and `-inventory-key-file` encrypts the signed folder inventory as an AES-256-GCM envelope. The peer decrypts in memory and still verifies its pinned Ed25519 signature and any required request challenge; a one-use ticket is consumed only after successful verification. This prevents disclosure of plaintext filenames and hashes through the exported inventory, but the symmetric key requires a separately authenticated **confidential** exchange and is stored unencrypted at rest. See [confidential inventory exchange](docs/CONFIDENTIAL_OFFLINE_INVENTORY.md) (new exports pad encrypted metadata to 64 KiB buckets; authenticated legacy v1 envelopes remain readable).

**Offline one-use challenge tickets (November 6, 2026 — local/unpublished):** An opt-in `-challenge-ticket` records a request for one trusted peer and local folder in a private `0600` ticket outside the scanned tree. A successful verified comparison atomically creates a persistent `.used` hardlink before returning a report, blocking reuse of the same ticket after restart. This is not rollback-proof and requires preserving both ticket files. See [one-use offline tickets](docs/ONE_USE_OFFLINE_TICKETS.md).

**Offline inventory challenge binding (November 6, 2026 — local/unpublished):** To resist reuse of old signed inventories across *different* manual comparison requests, generate a fresh 256-bit public challenge with `-new-inventory-challenge`; include it when signing with `-inventory-challenge` and require it when comparing with `-expect-inventory-challenge`. The match is enforced against the trusted peer's signature and cannot be silently downgraded. Reusing the same challenge can still replay the same response; no durable replay database exists. See [challenge-bound inventory exchange](docs/OFFLINE_INVENTORY_CHALLENGE.md).

**Signed offline inventory preview (November 5, 2026 — local/unpublished):** Devices with explicitly trusted Ed25519 identities can exchange *private, signed file inventories* and compare a local folder with a peer’s historical content hashes, **without a network listener or file writes**. Captured inventories expose names, sizes, hashes and timestamps to anyone who obtains the file. Signatures prove the trusted key signed a claim, not freshness or honest contents. See [signed offline folder comparison](docs/OFFLINE_SIGNED_INVENTORY.md).

**Nearby Send content consistency (November 5, 2026 — local/unpublished):** The sender now re-reads a source file through the same opened descriptor and hashes the second pass before encryption/upload. Same-length in-place rewrites that restore the original mtime between passes are rejected. This is a *best-effort double-read check*, not an atomic filesystem snapshot or guaranteed defense against malicious concurrent modification; expect additional read I/O. See [sender content consistency](docs/SENDER_CONTENT_CONSISTENCY.md).

**Nearby Send source-file security (November 5, 2026 — local/unpublished):** Linux/Android sender reads now open source paths component-by-component through no-follow directory descriptors; symlinked parents and filenames, and special files, are refused before reading. Other platforms have a weaker path-checking fallback. Source contents can still be mutated by a local adversary. See [sender source-path hardening](docs/SENDER_SOURCE_HARDENING.md).

**Nearby Send crash inspection (November 5, 2026 — local/unpublished):** A read-only `-audit-receive-dir /private/inbox` command reports leftover `.gcsend-stage-*` files without reading/deleting them; the receiver refuses to start or save a new file until they are manually reconciled. See [receiver crash-stage inspection](docs/RECEIVER_CRASH_RECOVERY.md).

**Nearby Send receiver security (November 5, 2026 — local/unpublished):** Linux and Android now stage incoming files and perform no-overwrite commits relative to a held private directory descriptor, with checks for destination path replacement before and after publication. Existing `SaveNew` behavior and one-time encryption remain, but hostile renames between checks remain unresolved; crash leftovers are detected and block a new transfer but are not repaired. See [receiver destination hardening](docs/RECEIVER_DESTINATION_HARDENING.md).

**Security checkpoint (November 5, 2026 — local/unpublished):** Linux/Android destination commits now verify the originally pinned destination **root and directory identity** immediately before and after no-overwrite publication. A relocated or replaced directory causes refusal (or an explicit partial-commit warning if the move is detected after publication). Directory renames between checks remain an unsolved hostile-concurrency race. Inventories reject reserved `.gcsync-stage-*` crash artifacts instead of accidentally replicating them; inspect and remove them only after confirming recovery. The original specification, Share/Send behavior and no-delete policy remain unchanged. See [destination hardening](docs/DESTINATION_PATH_HARDENING.md).

**Local checkpoint (November 5, 2026):** Linux/Android destination staging and no-overwrite commits now use directory-anchored `openat`/`mkdirat`/`linkat` operations, preventing a substituted symlink pathname from redirecting a committed file. The copier still requires trusted local directories; a malicious process can relocate an already-open directory, and this is not filesystem-atomic. See [destination path hardening](docs/DESTINATION_PATH_HARDENING.md).


**Current local checkpoint (November 5, 2026):** Source inventory reads use descriptor-anchored, no-symlink file opens on Linux/Android; durable Sync executes exactly its pre-recorded pending copy plan and rejects any unplanned or modified files before marking the journal ready. See [journal and path hardening](docs/JOURNAL_AND_PATH_HARDENING.md). This is still local, additions-only, and does not make destination writes safe against hostile concurrent path mutation.


I am developing GoreeCloud Sync as a privacy-first, self-hosted platform with three future experiences: **Send**, **Share**, and **Sync**. The original 33-section feature specification is preserved at [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md).

This standalone source bundle implements a narrow encrypted Share prototype, one-time encrypted Nearby Send, and local Sync development utilities. The Share prototype uses browser-side AES-256-GCM encryption of a file and its metadata, temporary encrypted links, one/five download counts, owner-only revocation, one-hour/24-hour expiration, minute-based encrypted-file cleanup, persistent encrypted storage, a small responsive web interface, persistent SHA-256 ciphertext checksums to detect accidental stored-data corruption before downloads, a non-destructive storage audit command, orphan-aware storage quota enforcement, a maximum of 512 active share records, local-process admission control of 60 upload attempts per minute, and Go tests. **Local-only** access is enforced by the server listener.

## Run

Install Go 1.23 or later. Run from the repository root:

```sh
go test ./...
go run ./cmd/sync
```

Open `http://127.0.0.1:8787` in your browser.

Optional private storage directory:

```sh
mkdir -m 700 private-storage
go run ./cmd/sync -data ./private-storage
```

Only loopback IP bindings are accepted. Client-side encryption uses the browser Web Crypto API. The encryption key is encoded after `#` in the link, and is not sent over HTTP. A file is encrypted entirely in memory, so the preview limits encrypted files to 20 MiB and stored ciphertext to 256 MiB. It now runs expiration cleanup once per minute while running, and also checks on startup and share activity. Each successful ciphertext GET counts as a download even if decryption later fails. The 512-active-share and 60-attempt-per-minute limits apply to this running local server instance; the rate counter resets on process restart and does not authenticate users. These controls do not authorize public hosting.

## Android device capability preflight (read-only)

Before considering a physical Android device test, run `python3 -B tools/adb_device_preflight.py --serial 'AUTHORIZED-DEVICE-SELECTOR'` with a trusted Android SDK `adb` installed. The tool checks the selected device's Android SDK/ABIs without installing or executing an application, and omits its device identifier from the JSON output. **`android/arm64` is compile-only; it is not runtime-verified.** A device advertising only 32-bit `armeabi-v7a` is not supported by the current CLI artifact. Do not deploy a mismatched binary, especially to a TV. See [Android ABI and deployment gates](docs/ANDROID_DEVICE_PREFLIGHT.md).

## Source package integrity (local/unpublished)

Run `python3 -B tools/verify_source_manifest.py` before building a downloaded source bundle. This checks that **every file** (except the manifest itself and `.git` metadata) appears exactly once in the SHA-256 manifest and has its recorded contents. The test suite also rejects missing, extra, tampered, duplicate or symlinked source files. This is an **integrity check, not a digital signature**: anyone who can modify the archive and its manifest can regenerate both. The manifest must be regenerated after deliberate edits. See [source-integrity validation](docs/SOURCE_MANIFEST_VALIDATION.md).

## Signed offline folder comparison (experimental, read-only)

On each device, create a private identity (`-device-action init`) and **independently verify the full fingerprint** before trusting a peer using `-device-action trust`. For example, on the exporting device:

```sh
# The identity folder is private (0700); do not copy its identity.json seed.
mkdir -m 700 ./peer-identity
# Initialize once; fails if already initialized.
go run ./cmd/sync -device-action init -device-dir ./peer-identity
# Output outside the scanned folder (created no-overwrite with mode 0600).
go run ./cmd/sync -plan-source ./peer-files -device-dir ./peer-identity -exclude '*.tmp' -export-inventory ./peer-snapshot.json
```

Copy **only** `peer-snapshot.json` through an appropriate confidential channel, not the private identity. After independently checking and pinning the exporting device public key using the existing explicit trust workflow, compare on another device:

```sh
go run ./cmd/sync -plan-source ./local-files -device-dir ./local-identity -peer-fingerprint 'sha256:YOUR_VERIFIED_PEER_KEY_HASH' -exclude '*.tmp' -compare-inventory ./peer-snapshot.json
```

The JSON report classifies `source-only` (local), `target-only` (signed peer snapshot), `identical` and `different`, without transferring or modifying files. Matching exclusions are mandatory. A signed snapshot can be stale, fabricated by a compromised trusted signer, or inaccurate due to concurrent filesystem changes; it contains plaintext relative filenames, sizes, hashes and a capture timestamp. **Do not feed it directly to any automatic copy, deletion or recovery operation.** See [offline inventory security and limitations](docs/OFFLINE_SIGNED_INVENTORY.md).

### Fresh-challenge option for an offline inventory

```sh
# Comparing device: generate a fresh request nonce (JSON includes `challenge`).
go run ./cmd/sync -new-inventory-challenge
# Exporting device: sign that nonce inside its private inventory JSON.
go run ./cmd/sync -plan-source ./peer-files -device-dir ./peer-identity \
  -inventory-challenge '<64-LOWERCASE-HEX-FROM-REQUEST>' -export-inventory ./peer-fresh.json
# Comparing device: require the SAME nonce and the separately pinned peer key.
go run ./cmd/sync -plan-source ./local-files -device-dir ./local-identity \
  -peer-fingerprint 'sha256:YOUR_VERIFIED_PEER_KEY_HASH' \
  -expect-inventory-challenge '<64-LOWERCASE-HEX-FROM-REQUEST>' \
  -compare-inventory ./peer-fresh.json
```

This stateless variant is read-only. Create a **new** challenge for each exchange. An earlier signed inventory cannot satisfy a new challenge; an identical response can still be replayed if the same challenge is reused. Filenames and hashes are not encrypted. See [request binding and limitations](docs/OFFLINE_INVENTORY_CHALLENGE.md).

### Optional persistent one-use challenge tickets

```sh
# Comparing device: private folder must exist with mode 0700, outside ./local-files.
go run ./cmd/sync -new-inventory-challenge -plan-source ./local-files \
  -device-dir ./local-identity -peer-fingerprint 'sha256:YOUR_VERIFIED_PEER_KEY_HASH' \
  -challenge-ticket ./private-tickets/request-001.json
# Exporting device: sign the returned nonce using the normal -inventory-challenge flow.
# Comparing device: enforce and consume its one-use ticket upon verified success.
go run ./cmd/sync -plan-source ./local-files -device-dir ./local-identity \
  -peer-fingerprint 'sha256:YOUR_VERIFIED_PEER_KEY_HASH' \
  -challenge-ticket ./private-tickets/request-001.json -compare-inventory ./peer-fresh.json
```

A successful ticket comparison makes **no changes to either scanned folder**, but writes the adjacent private `request-001.json.used` replay marker. It rejects subsequent use of the ticket even after restart. Backups or manual deletion of this marker can undo the protection; tickets expire after 24 hours. Use a new ticket filename per exchange and retain its spent marker. See [one-use ticket security and recovery](docs/ONE_USE_OFFLINE_TICKETS.md).

## Local verification

```sh
python3 -B -m unittest discover -s tools -p "test_*.py"
python3 -B tools/verify_source_manifest.py
go test -race ./...
go vet ./...
go build ./cmd/sync
node --check cmd/sync/web/app.js
node tests/encrypted-roundtrip.mjs
bash tests/additions-cli.sh
bash tests/lan-send-cli.sh
bash tests/sender-source-cli.sh
bash tests/offline-inventory-cli.sh
bash tests/offline-challenge-cli.sh
bash tests/one-use-challenge-cli.sh
bash tests/device-identity-cli.sh
bash tests/mutual-identity-cli.sh
bash tests/rotation-cli.sh
bash tests/secure-lan-cli.sh
bash tests/historical-cli.sh
bash tests/watch-cli.sh
bash tests/bidirectional-cli.sh
bash tests/continuous-additions-cli.sh
bash tests/durable-state-cli.sh
bash tests/pending-recovery-cli.sh
```

To inspect private storage without modifying its contents, run the following in a separate terminal while the service is stopped (or use a consistent snapshot):

```sh
go run ./cmd/sync -data ./private-storage -audit-store
```

The command emits JSON counts and findings containing only opaque share IDs. A nonzero exit status (2) indicates detected **errors**; warnings such as orphaned ciphertext or legacy entries without checksums are reported without automatic deletion. It does not create missing directories, repair files, or erase orphans. New files include a SHA-256 digest to detect disk corruption before consuming a retrieval allowance; this checksum does **not** replace authenticated encryption or protect against a malicious local user with access to the data directory.

The Node test builds a standalone Go binary and checks encryption, decryption, metadata privacy, tampering rejection, file retrieval limits, and revocation. It explicitly waits for the temporary server to shut down. Browser compatibility and real mobile-device testing require separate acceptance. See [security notes](docs/SECURITY.md).

## Local Sync planning and additions-only replication

A new **non-destructive local folder comparison** utility is included. It calculates SHA-256 content hashes for regular files and classifies relative paths as identical, source-only, target-only, or different:

```sh
go run ./cmd/sync -plan-source /path/to/source -plan-target /path/to/target
```

The default command writes a JSON comparison report without changing files. To explicitly copy **only newly discovered regular files** from one local directory into another, with no overwrites or deletions, use:

```sh
# Inspect the read-only plan first.
go run ./cmd/sync -plan-source ./test-source -plan-target ./test-target

# Manually opt in to adding source-only files, after reviewing that plan.
go run ./cmd/sync -plan-source ./test-source -plan-target ./test-target -apply-additions
```

Selective comparison and copy are opt-in with repeatable exclusions:

```sh
go run ./cmd/sync -plan-source ./test-source -plan-target ./test-target -exclude '*.tmp' -exclude 'private/**'
go run ./cmd/sync -plan-source ./test-source -plan-target ./test-target -exclude '*.tmp' -exclude 'private/**' -apply-additions
```

Patterns support basename globs such as `*.tmp` anywhere in the tree, relative globs such as `build/*.o`, and literal directory subtree skips such as `private/**`. Exclusions apply symmetrically to both inventories. Without an `-exclude` flag, **nothing is silently ignored**. The syntax is intentionally much smaller than Syncthing `.stignore`; see [the Sync inventory document](docs/SYNC_INVENTORY.md).

The new `-apply-additions` mode refuses to act when matching paths contain different data, when source and target overlap, or when symbolic links/special files occur. It revalidates source hashes while copying, commits new files without overwriting existing names, and limits each invocation to **1,024 files / 1 GiB** of newly copied content. It creates new files with mode `0600` and new directories with mode `0700` where supported. Files are staged and hard-linked into the destination, so the destination filesystem must support local hardlinks.

**Important:** This is a *manual, local, one-way additions-only copy*, not continuous or peer-to-peer Sync. A failed batch may leave successfully added files and empty new directories; its JSON result reports committed file paths. It does not preserve timestamps, permissions beyond private defaults, ACLs, ownership or extended attributes. It cannot safely operate if another process or an attacker concurrently changes destination parent directories, and it is not an independently verified backup. Review [Sync inventory and apply design](docs/SYNC_INVENTORY.md) before invoking on anything other than synthetic test data.

## Read-only three-way synchronization planning (experimental)

For trusted, non-overlapping local test folders that are *already identical*, I can record a previous common state and later classify unilateral changes, intentional deletions and conflicts without modifying files:

```sh
go run ./cmd/sync -plan-source ./source -plan-target ./target -capture-baseline ./baseline.json
# After changing the folders, compare them against that exact saved baseline:
go run ./cmd/sync -plan-source ./source -plan-target ./target -baseline ./baseline.json
```

The baseline is private (`0600`), stored outside both scanned trees, and bound to the exact canonical source/target paths **and their direction**. It requires matching contents to capture and refuses overwrites of an earlier baseline. Optional `-exclude` flags must be identical in both invocations. JSON statuses include `source-modified`, `target-deleted`, `conflict-modify-modify`, and `conflict-modify-delete`. All historical planning is read-only; combining `-baseline` with `-apply-additions` is rejected. The v2 experimental baseline format invalidates the earlier unshipped v1 checkpoint layout.

See [three-way planning, statuses, threat model and validation](docs/THREE_WAY_PLANNING.md). This is **not automatic, network, or continuous synchronization** and does not authorize file deletion or conflict resolution.

## Manual bidirectional additions-only replication (experimental)

For two **trusted, non-overlapping local folders**, I can now deliberately copy files that are present on only one side **into the other side** in a single bounded operation. This is a separate explicit command; it is **never triggered by** the read-only `-watch` observer:

```sh
go run ./cmd/sync -plan-source ./left -plan-target ./right
go run ./cmd/sync -plan-source ./left -plan-target ./right -apply-both-additions
```

The preflight refuses the **entire batch** if it finds differing file contents at the same relative path. Combined safety limits are 1,024 files / 1 GiB, and all existing files and deletions are left unchanged. The resulting JSON names files created on each side; failures can leave already completed additions and no automatic rollback. No continuous synchronization, conflict resolution, or network transfer is implied. See [bidirectional additions safety and test notes](docs/BIDIRECTIONAL_ADDITIONS.md).

## Foreground, read-only change observation (experimental)

I can inspect two non-overlapping local folders repeatedly without changing either folder. `-watch` emits an initial JSON snapshot and then NDJSON events **only** when a new inventory comparison differs. Its default 5-second polling interval is configurable from 1 second to 1 hour. Optional `-baseline` reports historical unilateral edits/deletes and conflicts against a **frozen** checkpoint; a modified checkpoint causes observation to stop. Exclusions are supported and no changes are applied automatically.

```sh
go run ./cmd/sync -plan-source ./source -plan-target ./target -watch
go run ./cmd/sync -plan-source ./source -plan-target ./target -watch -watch-interval 10s -exclude '*.tmp'
go run ./cmd/sync -plan-source ./source -plan-target ./target -baseline ./baseline.json -watch
```

Use Ctrl+C to stop it; it does **not** persist or run in the background. Scanning entire folder contents every interval consumes disk I/O; the output exposes relative filenames and hashes, and intermediate changes between scans can be missed. Watch mode explicitly rejects write operations. See [read-only watch safety notes](docs/READ_ONLY_WATCH.md). This is **not continuous file replication or network synchronization**.

## Foreground additions-only Sync with durable restart safety (experimental)

The explicit `-sync-additions` workflow repeats a bounded, two-way, **no-overwrite/no-delete** local copier in the foreground. It now **requires** a private, persistent state file so known shared file deletions or changes are rejected even after process restart. The very first enrollment requires both filtered folders to be identical and a new state file outside both roots.

```sh
mkdir -m 700 ./private-sync-state
go run ./cmd/sync -plan-source ./left -plan-target ./right
# Only after confirming BOTH trees are identical (read-only check above).
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -init-sync-state
# Check current safety without modifying the file trees or state.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -audit-sync-state
# Manually begin foreground copying; Ctrl+C to stop.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -sync-additions -sync-interval 15s
```

The state records known shared SHA-256 hashes and writes a `pending` marker **before** new copies. A crash, partial copy, deletion or modification can require **manual recovery**; an incomplete batch is **never auto-resumed**. No existing file is overwritten or deleted. The process uses an adjacent persistent 0600 OS lock file and requires supported Unix flock semantics. It does not provide safe hostile-directory concurrency, an atomic transaction, full deletion event history, backup recovery, automatic networking or mobile apps. Read the [durable state setup, audit, crash recovery and limitations](docs/DURABLE_SYNC_STATE.md) and [foreground Sync protocol](docs/CONTINUOUS_ADDITIONS.md) before use.

## Explicit completed-batch recovery (experimental journal v2)

After a crash, `-sync-additions` refuses a `pending` state. The new v2 journal records **each planned addition's exact path, direction, size and SHA-256** before copying. I can now review, then explicitly finalize a previously completed batch **only** when every planned copy already exists with the expected contents on both sides, every known shared file is unchanged, and no extra files appear. Neither command transfers or deletes data:

```sh
# Read-only: a pending batch is eligible ONLY if all previously planned files
# already exist on both sides with their exact recorded SHA-256 contents.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -check-pending-recovery

# Explicit opt-in: only if the review says eligible AND you independently
# reviewed the actual files and backed up important data.
go run ./cmd/sync -plan-source ./left -plan-target ./right \
  -sync-state ./private-sync-state/state.json -finalize-completed-batch
```

The read-only check reports per-file expected SHA-256, current left/right match/missing/mismatch statuses, and unplanned files; its output may contain sensitive relative filenames and hashes. The finalization command rechecks every file while holding the single-worker lock, retains the exact pending journal as `state.json.recovery-gN.json` (private `0600`, no overwrite), then marks the state ready. **If even one intended file is still missing, changed, or conflicted, recovery refuses to proceed.** Existing local journal v1 files from prior experimental previews are deliberately rejected by v2; preserve them as evidence, independently reconcile both folder trees, and enroll a **new** state at a new path. There is no automatic format migration or deletion propagation. This is a bounded local recovery aid, not a filesystem-atomic backup or network Sync protocol. See [durable state and recovery](docs/DURABLE_SYNC_STATE.md).

## Nearby Send — manually operated, encrypted single-file transfer

A new **single-use Nearby Send CLI preview** transfers one encrypted file between manually operated devices. By default, the receiver binds only to `127.0.0.1:8788`; binding a private LAN IP requires the explicit `-allow-lan` opt-in. The receiver automatically exits after five minutes without a successful transfer (configurable using `-receive-timeout`). A fresh 256-bit pairing key is printed on the receiving machine and entered on the sending machine through **standard input**, not a command-line argument. File contents **and filenames** are AES-256-GCM encrypted. HMAC authenticates both the upload and the final receiver acknowledgment; a receiver accepts at most one successful file per process. Files larger than 20 MiB, existing destination names, unsafe filenames, untrusted/public destination URLs, and unauthenticated uploads are rejected.

```sh
# Receiver: use test files; stays on loopback without -allow-lan.
mkdir -m 700 ./received
./goreecloud-sync -receive-dir ./received

# Sender: in a separate terminal, enter the key printed by receiver on stdin.
./goreecloud-sync -send-file ./example.txt -send-url http://127.0.0.1:8788/send
```

For a real trusted LAN, use `-receive-listen <private-ip>:8788 -allow-lan -receive-tls`, then enter the printed key on the sending computer. **No actual LAN-exposed service was started in this development session.** The default unpinned path uses a one-time shared secret. An **opt-in pinned receiver identity** is now available locally; an **additional explicit mutual sender/receiver proof** is now available, but neither mode establishes automatic pairing, real-device acceptance, or deployment. Do not open this port to the internet. Read the protocol, private-directory requirements, security limits, and setup instructions in [Nearby Send development notes](docs/NEARBY_SEND.md) and [Session TLS](docs/SESSION_TLS.md).

## Manual, signed device-key rollover (experimental)

The CLI now supports non-destructive `rotation-proof`, read-only `rotation-verify`, and explicit `rotation-trust`. An existing and a newly initialized Ed25519 identity co-sign an ordered public-key transition. The recipient **must** already trust the old identity; staging a new pin additionally requires the new full fingerprint to have been verified on an independent trusted channel. Proof verification makes no changes; staged trust preserves the old pin and private key. Rollover is not automatic or synchronized.

See the [complete synthetic-device procedure and security limits](docs/KEY_ROTATION.md). The local CLI acceptance check is `bash tests/rotation-cli.sh`.

## Persistent device identity (receiver-verification preview)

The local CLI now supports explicit Ed25519 device identity creation, public-key export, manually verified trust records, and removal of a trust record. A trusted sender can require a one-time receiver to prove ownership of its pinned public key, cryptographically bound to the one-time transfer secret **before any encrypted file upload**. No automatic trust-on-first-use or silent fallback is permitted.

```sh
# Initialize each participating device once, storing the private seed 0600.
./gc-sync -device-dir ./receiver-id -device-action init
./gc-sync -device-dir ./sender-id -device-action init
./gc-sync -device-dir ./receiver-id -device-action show

# Independently verify the receiver's FULL fingerprint before trusting it.
./gc-sync -device-dir ./sender-id -device-action trust \
  -trust-public 'RECEIVER_BASE64URL_PUBLIC_KEY' \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'

# Receiver (local-only unless an explicit private-LAN flag is supplied):
./gc-sync -receive-dir ./received -device-dir ./receiver-id

# Sender (enter the receiver's new one-time pairing key via stdin):
./gc-sync -send-file ./example.txt -send-url http://127.0.0.1:8788/send \
  -device-dir ./sender-id -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'

# Optional mutual identity verification:
# Receiver must first trust sender's public key and independently verified
# fingerprint using -device-action trust (same procedure as above).
./gc-sync -receive-dir ./received -device-dir ./receiver-id \
  -require-sender-fingerprint 'sha256:SENDER_FULL_64_HEX_DIGITS'
# The sender requires the receiver to enforce sender identity authentication:
./gc-sync -send-file ./example.txt -send-url http://127.0.0.1:8788/send \
  -device-dir ./sender-id -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS' -mutual-auth

# Explicitly remove a previously verified trust record:
./gc-sync -device-dir ./sender-id -device-action untrust \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'
```

**Security caveat:** The private Ed25519 seed is on disk in a permission-restricted but **unencrypted** local file. Receiver-only mode authenticates the receiver. Explicit `-mutual-auth` mode additionally requires the receiver to trust and verify the sender's persistent identity for that individual transfer. Session-pinned TLS 1.3 is now available for Nearby Send (`-receive-tls`), and is mandatory for non-loopback. There is still no automatic discovery, key backup/recovery, or independently tested physical-device transfer. A fingerprint copied from the same untrusted source as the public key is **not** independent verification. See [device identity and trust model](docs/DEVICE_IDENTITY.md) and [Nearby Send notes](docs/NEARBY_SEND.md).

## Security limits

**Do not expose this version to the public internet or behind a public reverse proxy.** It has no uploader authentication, per-client rate limits, tenant isolation, virus scanning, hardened quotas, key recovery, or streaming/chunked uploads. Four concurrent uploads are permitted; this is a global concurrency cap, not a per-user rate limit. A shared link is a bearer secret. Anyone who obtains the full link can retrieve the file before expiry or count exhaustion. The owner may revoke the most recently created link while the creating browser tab remains open; the separate revocation token is not copied into the recipient link. Creating a new share currently discards the previous share's in-memory revocation control. This is a preview limitation, not a durable multi-share management experience. Cross-site retrieval requests and non-loopback Host headers are rejected. This is a preview implementation, not an audited security product.

This preview only accepts literal loopback Host values (such as `127.0.0.1`), which also helps defend against browser DNS rebinding. Do not use hostname aliases like `localhost` in the URL.

Unattended, networked continuous folder synchronization, automatic deletion/overwrite, local peer discovery, native Linux/Android apps, relays, **automated mutual device pairing**, and GoreeCloud Identity platform integration remain unimplemented. Manual encrypted Nearby Send, local additions-only replication, and read-only three-way conflict planning now exist. See [`docs/ROADMAP.md`](docs/ROADMAP.md). Synchronization is not a backup; GoreeCloud Backup should serve independent recovery use cases.

## What is not verified

Real Chromium UI operation in this execution environment was blocked by an administrative browser/network policy. Local Go tests and the Node protocol integration test passed, but that does not establish real-browser, native-client, accessibility, deployment, or cross-platform acceptance.

## Project status and rights

No software license has been selected. Publishing source does not implicitly grant third-party redistribution or modification rights. Third-party technologies require provenance, compatibility and security review. No proprietary Wormhole.app code has been imported.

The current source bundle was created locally because the connected GitHub write was blocked. It is **not** evidence of source committed to `GoreeCloud/sync`.

## Session-pinned TLS transport (unreleased)

A one-time Nearby Send receiver may use `-receive-tls` to announce HTTPS using a session-unique Ed25519 TLS certificate whose public key is strictly verified against the out-of-band 256-bit pairing secret. For real private LAN listening, `-receive-tls` and `-allow-lan` are both required; wildcards are refused. The sender automatically verifies this pin for `https://` addresses. Plain HTTP remains loopback-only. This is not PKI, a complete secure-messaging protocol or a real-device release; see [SESSION_TLS.md](docs/SESSION_TLS.md).
