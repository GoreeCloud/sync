# GoreeCloud Sync — Security Model (Early Preview)

**Status: development evidence, not a security certification or production deployment authorization.**

The founder intends GoreeCloud Sync to protect content and metadata across Send, Share and Sync. This document describes the implemented localhost **Share** slice, a bounded one-time encrypted **Nearby Send** CLI, and separate local folder comparison and manually invoked additions-only copy primitives. No continuous network synchronization is implemented.

## Trust boundaries

- Browser: generates independent random 256-bit AES-GCM content keys and 256-bit revocation secrets. File bytes and metadata are separately encrypted with unique 96-bit nonces. The decryption key is sent to the recipient **inside the URL fragment**, which HTTP requests do not transmit to the server.
- Server: stores ciphertext and encrypted metadata in a local private directory, retains expiry/count records, and stores a SHA-256 digest of the separate revocation secret. The server does not receive the decryption key during normal operation.
- Link recipient: a full sharing URL is a bearer credential. Any party possessing it can decrypt the file while it remains retrievable; the key can leak from history, screenshots, logging by third parties, browser extensions, or recipient behavior.
- Host: only literal loopback hosts are permitted, and listening on a non-loopback IP is disallowed. This blocks common Host-based DNS-rebinding patterns but does not prevent malicious local software from communicating with the service.

## Controls implemented and tested

| Area | Control |
| --- | --- |
| Network | Reject non-loopback listener and non-loopback/hostname Host headers |
| Browser requests | Uploads and revocations require same-origin Origin; encrypted download GET requires custom client header; cross-site Fetch Metadata rejected for Share API |
| HTTP | Content Security Policy, no-store, no-referrer, no sniff, frame denial, same-origin resource policy |
| Encryption | WebCrypto AES-256-GCM with fresh per-file key and fresh nonces for content/metadata |
| Storage | Private 0700 directory and 0600 files, bounded per-file and aggregate ciphertext quota |
| Concurrency | At most four simultaneous uploads |
| Lifetime | Expiration enforced on read, startup cleanup, and minute-based cleanup |
| Access | Random 128-bit sharing IDs; fixed count of downloads (1 or 5), independent 256-bit revoke secret |
| Revocation | Owner-only token checked against SHA-256 digest in constant time; server-side ciphertext and record removed |
| Integrity | Authenticated decryption rejects tampered ciphertext or wrong keys. Newly stored ciphertext also receives an SHA-256 checksum, checked before a retrieval is counted, to detect accidental disk corruption; a checksum is not an authentication or tamperproofing substitute |
| Store audit | Read-only JSON diagnostics for malformed metadata, orphan blobs, missing files, expired records, and checksum mismatches |
| Storage quota | Counts app-owned orphan ciphertext and in-flight upload files, not only active indexed shares |

**Offline one-use ticket hardening (local/unpublished):** The optional signed-inventory comparison consumes replay state by creating a `.used` hardlink. On Linux/Android the final marker commit is now descriptor-anchored (`openat`, `linkat`), private and no-overwrite; a late parent replacement or altered ticket is rejected or reported as uncertain. This is not rollback-resistant storage, hostile-concurrent-rename immunity, a distributed nonce ledger, or native-device acceptance. See [marker commit safety](TICKET_MARKER_COMMIT_SAFETY.md).

## Nearby Send security boundary

A new manual `-receive-dir` mode exposes one `/send` endpoint only after explicitly starting the command. Its default listener is `127.0.0.1:8788`; any non-loopback bind requires `-allow-lan` and a literal private/link-local/unspecified IP. It creates a fresh 256-bit key, shows it only in a locally printed connection instruction, and receives at most one authenticated file. The sender reads that key from stdin, never places it in the URL, request header, or command-line option, and allows only private IP destinations with no HTTP proxy or redirect. Contents and filenames are independently protected by an AES-256-GCM envelope. Separate derived HMAC keys authenticate the request and cryptographic receipt. Receiver writes are private, bounded to 20 MiB, no-overwrite, and use same-directory stage/hardlink/disk sync operations. Tests cover authentication, tampering, filenames, source checks, private directories, one-shot behavior and a full loopback CLI transfer.

**Important:** The key is displayed in the receiving terminal and must be shared over a trustworthy private channel. Optional manually pinned Ed25519 receiver-only proof and an additional explicit **mutual application-layer identity proof** now exist. Neither is automatic pairing, mutual TLS, a relay-resistant secure transport, LAN discovery, browser/Android integration, or network QoS/DoS resistance. The private identity seed is stored unencrypted in a permission-restricted file, and the full public-key fingerprint must be verified independently. New TLS 1.3 session pinning protects HTTP headers/metadata (not IP, transfer size, timing or denial-of-service), while insecure loopback HTTP remains available for compatibility. Key compromise allows TLS impersonation. A hostile network can still interrupt transfers. `-allow-lan` is an explicit opt-in network exposure; the operation has only been executed and verified over loopback. Do not forward ports or put this receiver behind a public reverse proxy. For exact flow and threats see [NEARBY_SEND.md](NEARBY_SEND.md) and [DEVICE_IDENTITY.md](DEVICE_IDENTITY.md).

## Local folder comparison boundary

The default `-plan-source` / `-plan-target` command scans two local directory trees, streams contents through SHA-256, and returns a sorted JSON difference report without modifications. The separately opted-in `-apply-additions` mode copies only source-only files locally and refuses to proceed if any same-path content differs; it will not overwrite or delete target files. It revalidates SHA-256 during copy, stages into a private file and uses an atomic no-overwrite hardlink, with batch limits of 1,024 files / 1 GiB. Symlinks and special files are rejected; sensitive relative filenames and hashes appear in output. The `-exclude` flag enables explicit, validated symmetric filtering (no default ignore), but excluded entries are not checked or copied. It does not provide transactional rollback, versioning, network synchronization, OS-level sandboxing, or protection from hostile same-user directory replacement races. Partial failures can leave already-created files or directories. See [SYNC_INVENTORY.md](SYNC_INVENTORY.md).

## Limitations and unresolved risks

1. **Not a public service:** no uploader identities or public rate-limiting; global storage and concurrency limits cannot stop all malicious traffic. Do not put behind a public reverse proxy.
2. **No TLS:** loopback-only preview uses HTTP. Never expose it over an untrusted network.
3. **Memory-limited:** browser encrypts files in RAM and caps ciphertext at 20 MiB; not suitable for large files or streaming.
4. **Link bearer secret:** possession of the complete URL allows access. Neither expiry nor retrieval limits stop recipients from copying downloaded plaintext.
5. **File availability:** all attempted ciphertext GET requests with a valid client header count toward download limits, including failed recipient decryption or interrupted network delivery.
6. **Possible residual bytes:** filesystem deletion and OS/device storage retention are not guaranteed secure erasure. Backup/snapshots may retain data.
7. **Local unauthorized apps:** a malicious process running as the same user can access local storage and interact with the service. This version does not authenticate local applications.
8. **Browser acceptance:** real-browser automation was not completed in the current execution environment because access to the local test page was blocked by its administrator policy; the protocol-level WebCrypto test is not a browser UI acceptance substitute.
9. **Revocation scope:** The browser keeps only the last share's revocation token in memory; opening a new share or closing the tab discards access to prior tokens. An already-started download may finish after a concurrent revocation.
10. **Crash recovery:** storage metadata is recovered on startup, and app-created temporary upload/metadata files older than one hour are cleaned after restart. A read-only storage audit flags orphan ciphertext and inconsistent metadata without erasing potentially recoverable data. Multi-instance coordination, recovery of every possible orphan, and crash-injected adversarial tests remain unimplemented.
11. **Store checksum limitations:** legacy encrypted shares created before the checksum field remain readable with a warning and retain browser-level AEAD tampering detection. SHA-256 is not an HMAC or digital signature: a malicious process with write access to the private store may replace both the bytes and the digest. The checksum verifies stored ciphertext before use, not plaintext authenticity.
12. **Local apply limitations:** the opt-in additions-only copier uses portable path checks; files can be replaced concurrently by malicious code with local write access, and it does not promise atomic all-or-nothing multi-file transactions or retain historical versions. Hardlink support is required on the target filesystem.
13. **No external penetration test or security audit** has been performed. The tests verify selected properties, not complete system security.

## Security-release prerequisites

Implement authenticated uploader identities, per-IP/per-user request controls, chunked encrypted streaming, quotas, controlled file retention and deletion, storage isolation, a key lifecycle and credential strategy, CSRF/Host hardening in the deployed topology, TLS and reverse-proxy trust boundaries, telemetry minimization, incident response, and integration/recovery tests before any public or production deployment.

## Responsible disclosure

Do not publish private keys, credentials, or private test data in GitHub issues or logs. The repository has no live production service in this candidate.

## Manual signed key rollover (November 3, 2026 preview)

GoreeCloud Sync now supports an experimental, **local-only** pair of Ed25519 signatures over an explicit predecessor-to-successor public-key transition. A verifier must already pin the predecessor and must independently verify the successor's complete SHA-256 fingerprint before adding the new pin. Proof inspection is read-only, replacement-pin creation never overwrites an existing record, and the prior pin and private key are not removed automatically. There is no cross-device propagation, trust-on-first-use, revocation broadcast, hardware keystore, encrypted signing seed at rest, automatic switch, or real-device acceptance. See [KEY_ROTATION.md](KEY_ROTATION.md).

## Local Share admission limits (November 3, 2026 preview)

The localhost-only Share endpoint now enforces a maximum of **512 active share records** and a process-local fixed window of **60 header-valid upload attempts per minute** (including ciphertext bodies later rejected as corrupt). The count limit is checked before accepting the ciphertext body **and again while committing** after concurrent uploads; expired records can release slots. Rejections happen before a ciphertext temporary file is created when the initial limit is reached. Rate enforcement resets on process restart and is not per-user, distributed or persistent. It does not provide authentication, public-facing abuse protections, origin-independent authorization, network isolation, or sufficient DoS resistance for internet exposure. The existing 256 MiB physical storage cap and 4 concurrent uploads remain in force.

## Session-pinned TLS protection (November 3, 2026, local preview)

New Nearby Send `-receive-tls` creates an in-memory, short-lived, self-signed Ed25519 TLS certificate whose signing public key the sender deterministically pins to its independently supplied 256-bit session secret. The client enforces TLS 1.3, public-key match, exact IP SAN, validity and signature. This does not rely on CA trust or arbitrary self-signed certificates. Non-loopback private transfers require TLS; HTTP remains loopback-only. It protects HTTP payload headers and network request metadata while remaining a bounded, single-file application-layer encrypted transfer. It does not implement TLS client certificates, protect the pairing secret exchange, add automatic pairing, prevent network traffic correlation, or establish real-device acceptance. See [SESSION_TLS.md](SESSION_TLS.md).

## Read-only watch and sensitive metadata

The optional foreground `-watch` mode never applies changes or accesses the network. It reads every included regular file to compute SHA-256 during each interval, and emits paths/digests on standard output. Do not publish watch logs if paths are sensitive. Included symlinks and special files fail the scan; excluded paths are not scanned. It rejects overlapping roots and write-mode combinations and stops when a previously loaded baseline changes. Cross-directory scans are not atomic, and transient changes can be missed or yield a scan error. These events must **not** be treated as authorization to delete, overwrite, or automatically resolve conflicts.

## Manual two-way additions-only safety boundary

`-apply-both-additions` reuses the existing private staged + hardlink no-overwrite file copier for trusted local roots, but applies it in both directions after a single **conflict-free** SHA-256 preflight. It enforces a combined 1,024-file / 1-GiB cap and returns the exact paths committed in either direction if a later operation fails. Do not treat it as atomic or resilient to hostile concurrent path or parent-directory mutation; it does not preserve file metadata and never resolves conflicts or propagates deletions. `-watch` cannot trigger this write operation. Review `docs/BIDIRECTIONAL_ADDITIONS.md` before use.

## Experimental foreground Sync additions — extra boundaries (2026-11-03)

The opt-in `-sync-additions` command periodically runs trusted **local** two-way additions-only copying. It never deletes or overwrites files; source hashes and no-overwrite commit mechanisms are checked at each run, with strict per-cycle limits. A divergent file, symlink, failed filesystem action, or deletion of a previously shared path *within the active session* stops the process and requires manual attention. The current enrolled CLI persists shared-file hashes between runs and refuses deletion resurrection, but it is still not an atomic backup and cannot detect all changes between scans. Do not treat it as backup, hostile-directory protection, network Sync or a daemon. See [CONTINUOUS_ADDITIONS.md](CONTINUOUS_ADDITIONS.md).

## Durable local Sync restart boundary (2026-11-03 experimental)

The foreground `-sync-additions` CLI now requires a pre-enrolled private `-sync-state` file. Exact ordered absolute roots, exclusions, version, generation and all previously shared relative path hashes are validated before copying. Previously shared deletions or changes cause a fail-closed stop even after restart. Copy batches persist a write-ahead pending phase before filesystem writes; no incomplete batch auto-resumes. Cooperative concurrent workers are refused through a persistent adjacent Unix flock. The state checksum detects ordinary corruption but not a malicious same-user rewrite; no OS keystore, replicated signed event log, durable network tombstones, atomic filesystem snapshot or hostile parent-directory race protection is claimed. A read-only audit can report anomalies but never reset/repair the state. See [DURABLE_SYNC_STATE.md](DURABLE_SYNC_STATE.md).

## Manual zero-copy pending recovery (experimental v2)

The durable journal now records expected content hashes, sizes, paths and directions before every copy batch. A newly added explicit `-check-pending-recovery` command reads both folders and reports whether **every** intended copy is already complete, with no unexpected or changed files; it never modifies state. The separate `-finalize-completed-batch` command revalidates all contents while holding the existing single-worker lock, preserves a private no-overwrite hardlink backup of the original pending journal and only then advances to a ready generation. It performs **no data copying, deletion or repair**. A missing or changed expected file, a changed previously shared file, a new unplanned file or a backup collision refuses finalization. This is not an atomic filesystem transaction, does not guard against malicious concurrent parent-directory replacement and does not make old experimental journal v1 format safe to resume. Manual verification and reconciled new enrollment are still required for incomplete or inconsistent batches.

## November 5, 2026 — Experimental Sync journal/source-path hardening

The durable worker executes the exact copy intents recorded before a batch rather than re-planning after the pending marker. The final inventory rejects unexpected paths and any changed content (including previously matching files). On Linux/Android, source inventory and copy reads use `openat` through no-follow directory descriptors; on other platforms the guarded fallback does not offer equivalent concurrent-symlink protection. Destination writes and other path-based operations are **not** hardened against hostile concurrent directory renames. These changes are not a distributed or crash-atomic Sync implementation; see [limitations](JOURNAL_AND_PATH_HARDENING.md).

## November 5, 2026 — Destination-path hardening

Linux and Android local Sync additions now stage and commit new files relative to opened no-follow destination directory descriptors, refusing symbolic-link path components and existing final names. The source-integrity hash check and durable exact batch journal remain in place. Other platforms continue the explicitly weaker path-based fallback. Malicious concurrent directory **relocation** is not solved by descriptor-relative writes. See [the implementation and limitations](DESTINATION_PATH_HARDENING.md).

## November 5, 2026 — Local filesystem staging and relocation checkpoint (unpublished)

For trusted local folders, Linux/Android Sync now validates that its pinned destination root and final directory still resolve to their original inodes just before and after the no-overwrite commit. It refuses relocated destinations observed **before** the commit and reports partial-commit uncertainty when observed **after** the commit. No guarantee is made against adversarial rename operations between these checks. A staging crash residue matching `.gcsync-stage-*` is rejected during local inventories and must be inspected manually. No automatic cleanup, deletion propagation, overwrite, or restored-backup claim is made. Directory trees excluded by an explicit subtree exclusion are not inspected or copied. No remote service or native-app release is affected.

## November 5, 2026 — Nearby Send receiver destination hardening (unpublished)

Linux and Android `SaveNew` now stage received plaintext using a held private no-follow directory descriptor and publish through `linkat` without replacement. Root identity is checked immediately before/after publication; errors after publication may mean a partial commit. Other operating systems retain the less resilient path-based fallback. Do not claim confinement against hostile renames between checks, production audit, real-device validation, or hosted CI. See [receiver destination hardening](RECEIVER_DESTINATION_HARDENING.md).

## November 5, 2026 — Nearby Send source-file read hardening (unpublished)

On Linux/Android, the sender now opens each component of the absolute source path with `openat` and `O_NOFOLLOW` under pinned directory descriptors, rejects non-regular files and avoids blocking on special-file substitution. The original/final path identity, size and timestamp checks remain. Portable platforms have a less race-resistant preflight. An attacker modifying an already-open file or exploiting filesystem relocation still falls outside these guarantees; see [sender-source details](SENDER_SOURCE_HARDENING.md).

## November 5, 2026 — Nearby Send interrupted-write residue (unpublished)

A process crash can leave `.gcsend-stage-*` with **plaintext** in a private receiver folder. The receiver and `SaveNew` now fail closed on encountered residue; a read-only `-audit-receive-dir` CLI reports suspicious reserved names and returns status 2 to require manual review. Linux/Android also recheck using the pinned destination directory handle immediately before staging. No files are automatically deleted, resumed, inspected for content, or claimed to be complete. A same-user attacker can race the check or alter a private directory; this is neither atomic confinement nor secure erase. See [receiver crash recovery](RECEIVER_CRASH_RECOVERY.md).

## November 5, 2026 — Source package manifest completeness (unpublished)

The proposed verification workflow now runs `tools/verify_source_manifest.py` and its unit tests. Unlike plain `sha256sum -c`, it refuses **extra unlisted files**, duplicate entries, altered content, missing files and source symlinks. It excludes only the root manifest itself and `.git` metadata. This is not cryptographic provenance: an adversary able to change both files and the manifest can make the verifier pass. Independently authenticate the source archive and expected SHA-256 through an appropriate trusted channel. See [source-manifest validation](SOURCE_MANIFEST_VALIDATION.md).

## November 5, 2026 — Nearby Send double-read consistency (local/unpublished)

Before encrypting a file, the sender now performs two bounded reads through the same pinned source descriptor, comparing a streaming second-pass SHA-256 to the first-pass bytes. This catches an in-place same-length rewrite with a restored mtime *between reads*, and ordinary truncation/append anomalies. It is not an atomic snapshot and can be defeated by concurrent writes before/after the check or deliberately oscillating contents. It adds read I/O and does not change source or network authentication. See [SENDER_CONTENT_CONSISTENCY.md](SENDER_CONTENT_CONSISTENCY.md).

## Signed offline inventories (experimental; source-only)

A signed offline inventory is **not encrypted**. Its relative filenames, byte counts, SHA-256 file hashes, exclusion patterns and self-reported UTC timestamp are visible to anyone who receives the JSON. Never distribute sensitive inventories publicly, place the export inside the scanned tree, or share `identity.json`. The exporting identity's private seed is not included. Only previously trusted, independently fingerprint-verified public keys may authorize comparison. A valid signature establishes who signed a recorded claim, **not** truthful file content, freshness, anti-replay or a right to modify files. The compare path is read-only and rejects unmatched exclusions. This is not a filesystem-atomic snapshot or network Sync protocol. See [OFFLINE_SIGNED_INVENTORY.md](OFFLINE_SIGNED_INVENTORY.md).

## Signed offline inventory fresh-challenge binding (November 6, 2026, local preview)

A comparing device can generate a public random 256-bit challenge and require the exporting, explicitly trusted device to sign that exact challenge into its canonical inventory. This rejects unchallenged/incorrectly challenged older exports and cannot be silently downgraded when challenged. **This does not provide a durable replay ledger** or prevent reusing the same response for the same reused challenge; mint a new challenge each time. The signature binds a claim, not a truthful directory snapshot, trusted time, confidentiality, or file-transfer authorization. See [OFFLINE_INVENTORY_CHALLENGE.md](OFFLINE_INVENTORY_CHALLENGE.md).

## November 6, 2026 — One-use offline challenge ticket state (local/unpublished)

An opt-in private on-disk challenge ticket binds the verified peer's public fingerprint to a local canonical directory and exclusions. After successful signed challenge verification and read-only folder comparison, a no-overwrite hardlink `.used` marker is created and directory-synced **before** result delivery. This prevents a second successful comparison using the same issued ticket pathname, even across normal restarts, without changing scanned file contents. Failure or crash after marker creation requires a fresh ticket. The protection depends on preserving the issued file and spent marker, a private `0700` parent, filesystem hardlink/durability semantics and a reasonably accurate local clock; it is **not** robust against disk snapshot rollback, marker deletion, same-user malware or duplicated tickets under new paths. Metadata remains plaintext; no network Sync or physical-device acceptance is claimed. See [ONE_USE_OFFLINE_TICKETS.md](ONE_USE_OFFLINE_TICKETS.md).

## November 7, 2026 — Optional confidential offline inventory (local/unpublished)

Signed inventory JSON previously exposed relative names, sizes, content hashes and timestamps. Optional AES-256-GCM authenticated encryption now protects that entire signed claim with a separate high-entropy 256-bit key. The importer decrypts in memory **before** verifying the already trusted Ed25519 signature, exclusion policy and exact optional challenge. Plaintext cannot silently satisfy encrypted mode, and a failed decrypt or signature does not spend a one-use ticket. Both devices must independently exchange and protect the symmetric key; it is stored on disk unencrypted under a private `0600` mode and requires a private `0700` parent. New version-2 exports use authenticated length + random padding to **64 KiB size buckets**, reducing exact-length metadata inference; authenticated encrypted v1 files remain readable. Approximate bucket count remains visible. Same-user malware, compromised key transfer, random nonce collision, process-memory exposure, local filesystem races, stale/false inventories and rollback of one-use state remain outside the security guarantee. No physical-device audit or hosted CI is claimed. See [confidential inventory protocol](CONFIDENTIAL_OFFLINE_INVENTORY.md).

## Private offline artifact input/output boundary (November 7, 2026 local preview)

Linux/Android now open offline inventory keys, signed/encrypted inventory inputs and one-use ticket files using component-by-component no-symlink directory descriptors, with no-follow/nonblocking final opens. Offline inventory keys also reject hardlinks. Private files are staged and no-overwrite committed via `openat`/`linkat` inside a held directory handle with path-identity checks before and after publication. This reduces parent-symlink substitution risks but does not prevent hostile directory relocation between checks. Other platforms retain weaker pathname-based behavior. Crashes may leave **private staged key material or signed inventory metadata**, requiring manual review; never auto-delete unknown residues. See [PROTECTED_OFFLINE_ARTIFACT_IO.md](PROTECTED_OFFLINE_ARTIFACT_IO.md).

## Device identity and trusted-peer records (November 7 local checkpoint)

Linux/Android private identity seeds and trusted peer records now use no-follow directory-descriptor-based reads, private no-overwrite staged writes, descriptor-relative trust removal and hardlink refusal. They still require trusted local owners, private directories and manual recovery review after crashes; this is not a keystore, atomic filesystem snapshot or defense against a malicious same-account process. Other platforms retain a weaker path-based fallback. See [device identity storage hardening](DEVICE_IDENTITY_STORAGE_HARDENING.md).

## Android ABI and device preflight boundary (local development)

The optional `tools/adb_device_preflight.py` performs read-only ADB properties checks on one explicitly selected authorized device. It omits device identifiers from JSON and never transfers or launches software. A returned `candidateGoTarget` establishes only that an existing compile-only target matches a reported ABI; it is **not** a runtime trust decision or installation approval. Android/arm64 preview binaries are not 32-bit ARM/Android TV binaries. Never substitute `linux/arm` artifacts for a missing Android NDK/cgo build, expose wireless ADB or assume a remembered device identity. See `ANDROID_DEVICE_PREFLIGHT.md`.
