# GoreeCloud Sync — Roadmap

The complete feature request is in [PRODUCT_SPEC.md](PRODUCT_SPEC.md). Features described below are unimplemented unless separately verified.

1. **Share security and scale:** Add uploader authentication, per-client abuse/rate limits, streaming and resumable encrypted transfers, durable revocation management across browser sessions, hardened quotas, safe orphan recovery decisions, crash-injected audit/repair tests, and review requirements for any public exposure. (Basic revocation, periodic expiry cleanup, SHA-256 ciphertext checksums, non-destructive orphan diagnostics, quota accounting for orphaned ciphertext, and four-upload concurrency bounds, 512 active share-record cap and a process-local 60-upload-attempts/minute limit are implemented in the local preview.)
2. **Nearby Send:** A bounded, one-time AES-256-GCM encrypted single-file CLI transfer with out-of-band 256-bit secret, HMAC-authenticated request/receipt, a private destination, and an explicit LAN-listening opt-in is implemented in the local candidate and tested on loopback. Now includes tested local Ed25519 identity pins, signed receiver proof and an explicitly selected per-transfer mutual application-layer sender proof (not automatic pairing; new session-pinned TLS 1.3 is implemented and loopback-tested). Next: physical two-device LAN acceptance, automatic discovery and recipient approval, rollover proof and local staged trust implemented (automatic key rotation/revocation propagation still outstanding), further transport hardening and relay resistance, streaming, resume, clipboard and native client integrations. See [NEARBY_SEND.md](NEARBY_SEND.md).
3. **Continuous Sync:** Read-only local folder comparison and a bounded, manual additions-only copy operation and explicit ignore globs are implemented in the local candidate. Manual two-way additions and experimental foreground additions-only polling now exist; no **network**, background daemon, deletion-aware durable, or automatic conflict-resolving synchronization exists. Next: Evaluate licensed Syncthing integration or independent engine, block-level updates, file watching, folder modes, conflict handling and version retention.
4. **Native clients:** Build and test Linux and Android clients with native file selection, background policies and responsive GoreeCloud UI.
5. **Operations:** Add secure observability, administration, CI, recovery validation, documented updates and optional ecosystem integration.

Each phase requires verifiable tests, threat-model review, licensing checks, real-device acceptance and documentation of what is actually implemented. Publication recovery and verification are tracked in [PUBLISHING.md](PUBLISHING.md).

## Read-only local change observation — 2026-11-03 checkpoint

I added an explicit foreground polling mode (`-watch`) that emits read-only NDJSON snapshots only when folder inventory results change. It supports existing three-way baselines, fails closed if a baseline changes, and never applies writes. It is tested on synthetic local folders; this is not a continuous sync protocol, background watcher, network peer, or native client. See `docs/READ_ONLY_WATCH.md`. The remaining requirement is an authenticated, resumable, conflict-aware sync protocol with independent physical-device acceptance and safety reviews.

## Manual two-way additions-only stage — 2026-11-03

I added `-apply-both-additions` as a strictly explicit, bounded local step toward future bidirectional Sync. It copies only new files in either direction, refuses divergent same-path files before any write, preserves existing content and deletions, revalidates file hashes, and reports partial commits. It is **not** network synchronization or a continuous version-aware system. Next work still requires a durable versioned protocol, authenticated peer networking, safe conflict resolution, resumable transfer, tested rollback/recovery, and native clients. See `docs/BIDIRECTIONAL_ADDITIONS.md`.

## Foreground recurring additions-only checkpoint — 2026-11-03

I added opt-in `-sync-additions` using the original bounded two-direction copier at 1s–1h polling intervals (15s default). It stops on divergent content, partial copy error, path safety error, or deletion of a path previously present on both sides during the *same process*. Source SHA-256 and no-overwrite staging remain enforced. The check does not persist history and **can silently restore a previously deleted file after process restart**; it is not an authorized durable Sync/deletion policy, native client, network protocol or background service. See [CONTINUOUS_ADDITIONS.md](CONTINUOUS_ADDITIONS.md). Future work must add durable versioned history, deliberate deletion handling, crash consistency, and peer-to-peer transport with verified device authentication before claiming continuous multi-device Sync.

### Local Sync state safety checkpoint — 2026-11-03

Implemented an experimental, local-only persisted checkpoint for foreground two-way additions-only operation, with initialized matching roots, state-bound exclusions, write-ahead pending intent, non-automatic recovery, immutable known-content guard, read-only diagnostics and cooperating process lock. It reduces deletion-resurrection risk after restart but is **not** a full version-vector, tombstone, remote event or recoverable replication protocol. Remaining: explicit reviewed state-reconciliation UI, signed multiparty events and retention policy, snapshot-consistent hashing, honest conflict/tombstone propagation, network Sync with trusted identity and transport, throughput/backpressure testing, and native Linux/Android clients. No public deployment/CI accepted.

## Pending-batch verified recovery (2026-11-03, local uncommitted)

The next-stage v2 local journal records exact intended file hashes before copying and provides **read-only eligibility** plus **explicit zero-copy completion** for fully copied pending batches. It preserves the prior pending journal for audit. Do not equate this with full crash replay, automatic repair, storage snapshotting or distributed multi-device Sync. Next: snapshot-resistant path traversal, durable trusted-device version vectors/tombstones, encrypted network Sync, native Linux/Android and real-device tests.

## November 5, 2026 — Local destination safety checkpoint

Linux/Android directory-descriptor-based no-overwrite creation is implemented and locally tested. Next security priorities are hostile directory-relocation defenses, snapshot-consistent inventories, multi-file crash recovery, and verified physical-device transport. See `DESTINATION_PATH_HARDENING.md`. GitHub publication and native-app acceptance remain open.

## November 5, 2026 — Sender source-path security assessment

Linux/Android Nearby Send now refuses source symlinks and special files before reading, with directory-FD based opens to reduce symlink-swap exposure. Remaining: content-snapshot integrity against hostile in-place writers, physical-device tests, native UI, and authenticated resumable transport; see [sender-source hardening](SENDER_SOURCE_HARDENING.md).

## November 5, 2026 — Manual receiver crash-stage assessment

Local source now detects leftover plaintext `.gcsend-stage-*` artifacts and blocks a new receiver; a read-only CLI reports manual review requirements. Still needed: a designed, authenticated resumable transfer protocol; independent two-device LAN testing; operating-system crash semantics; destination relocation confinement; explicit backup/recovery controls and native clients. No release/publish claim.

## November 5, 2026 — Source-manifest validation hardening

The local publication candidate now includes strict SHA-256 manifest completeness and negative regression tests; this reduces accidental packaging drift but cannot establish trusted provenance. Next steps include authenticated release signing and exact-published-commit hosted CI after GitHub publication becomes permitted. See [source manifest validation](SOURCE_MANIFEST_VALIDATION.md).

## 2026-11-05 — Signed offline comparison foundation (experimental, local only)

Explicitly trusted devices can exchange signed read-only file hash manifests for manual offline comparison, with private no-overwrite exports and no remote files written. This is **not** peer networking, freshness proof, distributed version vectors, tombstones, or authenticated live synchronization. Remaining: confidential transfer of metadata, trusted clock/replay policy, consistent filesystem snapshots, durable conflict history, physical-device acceptance, full native clients and transport. See [OFFLINE_SIGNED_INVENTORY.md](OFFLINE_SIGNED_INVENTORY.md).

## 2026-11-06 — Fresh request challenges for offline signed claims (local preview)

Added opt-in signer-bound 256-bit public challenges to reject reuse of older signed inventory claims across distinct requests. Remaining: verified secure offline exchange on physical devices, explicit one-time use/replay policy, confidential metadata delivery, trust recovery/rotation, consistent file snapshots and conflict-safe authenticated network Sync. This is not an offline freshness guarantee when challenges are reused. See [OFFLINE_INVENTORY_CHALLENGE.md](OFFLINE_INVENTORY_CHALLENGE.md).

## November 6, 2026 — Local one-use request ticket stage

Added an opt-in private one-use challenge ticket bound to an existing explicitly trusted peer, canonical local folder and filter policy, with a crash-persistent no-overwrite consumed marker. This reduces accidental same-request replay across normal restarts but **not** disk rollback, same-user tampering, or re-issuance of the same nonce under a separate restored ticket path. Next: authenticated confidential cross-device delivery, durable device-wide anti-replay state with backup rollback strategy, filesystem snapshot-consistent inventory, peer-to-peer live Sync and physical native client acceptance. See [ONE_USE_OFFLINE_TICKETS.md](ONE_USE_OFFLINE_TICKETS.md).

## November 7, 2026 — Offline metadata confidentiality checkpoint

Added an optional local-only AES-256-GCM envelope around a trusted signed inventory, with independently exchanged 256-bit key files, enforced signature verification and optional one-use signed challenge binding. This addresses plaintext disclosure by the transferred inventory file, **not** key distribution, native secure storage, rollback-resistant replay state, real-device acceptance, authenticated network synchronization or filesystem-atomic snapshots. See [CONFIDENTIAL_OFFLINE_INVENTORY.md](CONFIDENTIAL_OFFLINE_INVENTORY.md).
