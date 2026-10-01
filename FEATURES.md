# Features

This file distinguishes implemented repository capability from partial development capability and planned product capability. Source-level implementation does not imply production deployment or Stable qualification.

## Current source features

### Service and repository foundation

- Go module and first-party service/CLI shell.
- `serve`, `version`, and `help` commands.
- Loopback-only default development listener at `127.0.0.1:8787`.
- Development health and status endpoints.
- Privacy/security response headers and graceful process shutdown.
- GitHub Actions validation for formatting, tests, vetting, and build.

### Peer transport and identity foundations

- Pre-stabilization `GC-SYNC/1` capability handshakes.
- Bounded length-prefixed control framing with a 1 MiB hard limit and fail-closed malformed/truncated/unknown-field/trailing-value handling.
- Bounded binary payload framing with a 1 MiB global ceiling and caller-supplied expected-chunk allocation bound.
- Frame writers retry valid partial writes and fail on zero-progress writes rather than silently truncating a frame.
- Context-bound raw TCP peer transport helpers that do not imply authentication.
- TLS 1.3-only mutually authenticated secure-peer dial/accept wrappers for already-trusted devices.
- Short-lived self-signed Ed25519 certificates used only as TLS key-possession carriers; trust is based on exact expected device ID and raw Ed25519 public-key pinning rather than Web PKI or network location.
- GoreeCloud Sync ALPN binding, bounded TLS handshake time, and TLS session-ticket disabling for the secure-peer wrapper.
- GC-SYNC capability-handshake local and remote device-ID binding to the TLS-authenticated identities.
- Ed25519 device-key and fingerprint primitives.
- Signed pairing proofs bound to device identity and challenge.
- Cryptographically random, short-lived one-time pairing challenges.
- Exact challenge consumption with expiry and replay rejection.
- `VerifiedPairing` output only after pairing proof verification and challenge consumption.

### Trusted-device authorization and session foundations

- Durable account-scoped trusted-device records.
- Explicit authorization only from a verified pairing result.
- Explicit device revocation.
- Refusal to silently replace an active trusted device with different key material.
- Stored public-key/fingerprint consistency validation before trust is accepted.
- Private trusted-device storage directory/file permissions and atomic publication.
- Runtime trusted-peer resolver that composes authenticated peer resolution with exact account, device ID, and key-fingerprint authorization.
- Fail-closed handling for unknown, revoked, mismatched, or trust-store-error states at that resolver boundary.
- Secure-peer factory resolution of current trusted remote identity before local private-key opening and TLS admission.
- Binding of the admitted trusted public-key fingerprint to the authenticated `PeerConn`.
- Explicit `RevalidatePeer` checkpoint that rechecks the exact account/device/fingerprint against current trusted-device state and closes the local peer when trust is revoked, replaced, missing, corrupt, or unreadable.
- `RunWithCurrentTrust` operation guard that performs that current-trust check immediately before invoking a protected peer operation and never invokes the callback when trust is no longer current.
- Bounded `RunOperationSequenceWithCurrentTrust` orchestration for up to 64 validated callbacks with a fresh current-trust checkpoint before every step.
- Payload-transfer application composition that revalidates current trust before transfer start, before sender source reads, before receiver staging writes, and before returning verified success.
- Idempotent local peer close state for fail-closed session retirement.

### Transfer and integrity foundations

- Versioned single-file transfer manifests with deterministic ordered chunk metadata.
- Streaming manifest construction with SHA-256 digests for each chunk and the complete payload.
- Structural manifest validation for version, filename, declared size, ordered chunk indexes, chunk sizing, and canonical lowercase SHA-256 metadata.
- Manifest filenames are constrained to descriptive leaf names and cannot carry destination paths, slash/backslash separators, `.` or `..` path semantics.
- A current Development chunk-size bound of 1 MiB for the manifest/verification and binary-frame path.
- Per-chunk integrity verification before acceptance.
- Whole-payload verification that rejects corruption, truncation, and undeclared trailing bytes before completion can be accepted by higher-level code.
- Versioned one-to-one payload offers for file and text transfers.
- Cryptographically random 128-bit transfer identifiers encoded as canonical lowercase hexadecimal.
- Explicit receiver accept/reject decision before any payload bytes are transmitted.
- Sender completion and receiver verified-receipt records bound to the exact transfer ID, declared byte size, and whole-payload digest.
- Secure payload transfer requires a TLS-authenticated `PeerConn` with a durable trusted-device fingerprint bound by the application trust layer; raw or merely unbound peer sessions fail closed.
- Source chunks are verified against the manifest before transmission.
- Received chunks are verified before they are written to the caller-provided staging destination.
- Protocol, framing, stream, staging-write, and integrity failures close the peer fail-closed rather than continuing on a potentially desynchronized connection.
- Explicit staging semantics: a receiver must not publish or commit partial content until verified success is returned.

### Backup coordination foundations

- Read-only consumption of Backup-owned protection state without transferring Backup authority into Sync.
- Backup-unavailable protection state remains explicitly unavailable rather than being inferred protected or unprotected.
- Separately authorized pre-change/pre-migration checkpoint requests with distinct required and best-effort availability policy.
- Required checkpoints fail closed when Backup is unavailable; best-effort requests degrade explicitly rather than manufacturing success.
- Backup checkpoint receipts require a non-empty checkpoint identifier and creation time.
- Sync intentionally exposes no Backup deletion interface; backup-set retention/deletion remains Backup authority.
- Restore requests identify logical Sync-managed targets rather than caller-supplied destination filesystem paths.
- Sync runtime restore leases own target authorization, pause/maintenance state, isolated staging, reconciliation/publication, abort cleanup, and resume.
- Wrong-target or malformed restore leases fail closed before restore execution.
- Failed staging or reconciliation requests abort cleanup, and resume is attempted for every begun restore lease.
- Once a restore lease begins, request cancellation cannot by itself suppress abort/resume cleanup: each cleanup call receives a fresh cancellation-detached context with a separate five-second Development timeout.

See `docs/BACKUP-INTEGRATION.md` for the explicit authority and lifecycle boundary.

### First-party application record replication foundations

- Dataset capability negotiation for GoreeCloud Browser, Search, and Bookmarks.
- Versioned transport-neutral record envelopes.
- Exact negotiated dataset/schema validation.
- Deterministic record conflict resolution.
- Payload-free tombstones for deletion propagation.
- Record-bound proof foundations and client/server proof conformance contracts.
- Replay/high-water, observation-receipt, tombstone-convergence, and protected device-key lifecycle foundations.
- Persistent development stores and source ingestion/retrieval handlers for `search.history`, `bookmarks.items`, `browser.tabs`, and `browser.history`.
- Authenticated retrieval ordered by record ID.
- 512-byte record-ID and cursor limit.
- Default retrieval page size of 256 and maximum of 1,024.
- Complete persisted-store validation before page return so off-page corruption remains fail-closed.
- Page-bounded candidate retention during retrieval rather than full-envelope page materialization.

## Partial or development-only features

- The default `serve` command exposes the base development service and does not by itself wire the complete replication, account, trusted-device, secure-peer, payload-transfer, Backup, or restore runtime composition.
- Pairing, challenge consumption, trust authorization, revocation, secure admission, explicit revalidation, operation guards, and payload-transfer trust checkpoints exist as source foundations but do not yet provide complete user-facing trust administration.
- Trust revalidation is checkpoint-based; the repository does not yet choose a complete production cadence, run a background revocation monitor, or guarantee instantaneous termination of an operation already running after a successful checkpoint.
- Production secure listener/dial orchestration, discovery/address policy, reconnect behavior, and complete session lifecycle remain incomplete.
- Raw TCP peer helpers remain intentionally unauthenticated lower-level primitives.
- Account-scoped trusted-device state is durable locally, but production multi-user identity/account authority remains incomplete.
- Authenticated one-to-one file/text payload movement exists as a bounded source primitive, but it is not yet wired into the default runtime, durable resume persistence, final filesystem path authorization/confinement, transfer history/progress/rate controls, user-facing Nearby workflows, or a folder-sync engine.
- The current random transfer identifier and ordered stream contract do not establish the broader production replay/freshness policy still required for transfer operations.
- Backup coordination is a transport-neutral source contract only. It now protects in-process abort/resume cleanup from request cancellation with bounded cleanup contexts, but live Backup transport, Identity/policy authorization, concrete Sync restore runtime wiring, process-crash/restart recovery, durable restore-lease reconciliation, target-environment validation, and production acceptance remain pending.
- First-party application-record replication handlers are not a complete folder synchronization engine or production deployment claim.
- Privacy Shield and Wardveil decision boundaries exist in source, but complete production integration and acceptance evidence remain pending.

## Planned — Sync Core

- Persistent approved-folder replication.
- Send/receive, send-only, and receive-only modes.
- Selective synchronization.
- Filesystem watching and efficient change detection.
- Ignore patterns.
- Offline change queues.
- Chunked and resumable synchronization.
- Efficient changed-block transfer where justified.
- Bandwidth controls and schedules.
- File versioning.
- Conflict Center and user-facing conflict resolution.
- Deletion safety and recovery-aware controls.
- Whole-file and transfer integrity acceptance.
- Authoritative-copy labeling.
- Durable resume state and interrupted-transfer recovery.

## Planned — Nearby

- LAN discovery.
- User-facing QR pairing and optional confirmation workflows.
- User-facing file and folder transfer workflows using the approved transfer engine.
- Text, URL, and clipboard transfer experiences.
- Drag and drop.
- Android share-sheet integration.
- Favorite devices and user-facing trust management.
- Background receiving.
- IPv4 and IPv6 operation.
- Wi-Fi, Ethernet, and approved private-network transport.
- Resume and post-transfer verification.

## Planned — Share

- Expiring links.
- One-use links.
- Download limits.
- Immediate share revocation.
- Optional passphrases.
- Optional authenticated-recipient requirements.
- QR codes.
- Client-side end-to-end encryption.
- Encrypted metadata where practical.
- Peer-to-peer preferred delivery.
- Encrypted temporary relay/storage fallback.
- Automatic expiration and cleanup.

## Planned — Product, multi-user, and administration

- Production GoreeCloud Identity/account runtime integration.
- Complete account and independently owned-device administration.
- User-facing device approval, revocation, recovery, retirement, and key-replacement workflows.
- Approved runtime revalidation schedule/checkpoints and revocation-aware reconnect/session policy.
- Explicit folder ACLs and multi-user isolation tests.
- Read, write, contribute, receive-only, drop-only, and administrative grants.
- Audit events and administrative activity views.
- Transfer history, progress, cancellation, prioritization, quotas, and rate controls.
- Migration Mode and drop folders.
- Glaze UI web administration and accessibility acceptance.
- Native Android client and Debian packaging.
- GoreeCloud Mesh coordination, GoreeCloud Network reachability, Notify, Manager, Photos, Drive, Search, API, Wardveil Security, Privacy Shield, Everkeep, Backup, and broader GoreeCloud Identity integrations as applicable.
- Broader transport/session/transfer replay and freshness policy beyond implemented TLS, random transfer identifiers, and pairing-challenge boundaries.
- Production monitoring, deployment, migration/rollback, storage, and Stable acceptance evidence.
