## November 7, 2026 — Read-only Android device/ABI preflight (local, unpublished)

Added `tools/adb_device_preflight.py`, its eight mock-ADB tests, and `docs/ANDROID_DEVICE_PREFLIGHT.md`. Explicitly selected authorized devices can be checked for SDK/ABI without installation or any device mutation; serials are not included in the reported JSON. Found a release-testing mismatch: Android ARM64 Go CLI builds cannot be assumed compatible with 32-bit ARM-only TV devices. Android/arm requires an NDK/cgo external linker (not available or validated in this checkpoint). Source, test matrix and release notes keep the TV target unverified.

## November 7, 2026 — Repository-specific MIT license selection (local, unpublished)

- Under the founder's explicit license-selection delegation, selected **MIT** (`SPDX: MIT`) specifically for GoreeCloud Sync's original code and associated documentation, with the complete standard license text at repository-root `LICENSE` and `Copyright (c) 2026 GoreeCloud`.
- Reviewed the local module declaration (Go 1.23 with no third-party Go module requirements), local browser assets and a bounded text scan for outside notices. No bundled dependency licenses or code attributions were identified in that review. Rights in the original founder-provided specification and future third-party contributions still require appropriate provenance confirmation; the MIT file does not relicense third-party rights.
- This is **local source authoring**; the public `GoreeCloud/sync` repository is still README-only. Repository-level license compliance requires a permitted commit to the default branch, readback, and any remaining source/provenance checks. No public GitHub license or hosted CI is claimed.

## November 7, 2026 — Private device identity/trust storage I/O (local, unpublished)

- Linux/Android Ed25519 identity seeds and trusted-peer records now use directory-descriptor-anchored `openat`/`mkdirat`/`linkat`/`unlinkat` with no-follow path traversal, regular/private/single-link validation, no-overwrite staging and directory synchronization.
- Added Linux regression coverage for ancestor symlinks, hardlinks, regular-file refusal, private staging cleanup, and concurrent trust enrollment. The existing signing/trust protocols are unchanged.
- macOS/Windows keep a weaker guarded pathname fallback; same-account hostile rename and crash-stage privacy risks remain. No hosted CI or published source was produced by this checkpoint.

## 2026-11-07 — One-use ticket marker commit hardening (local/unpublished)

- Linux/Android one-use ticket `.used` consumption now pins the whole parent path without symlink-following, revalidates the opened private single-linked ticket body/hash and source inode, and publishes the no-overwrite hardlink using `linkat` relative to the held descriptor. Syncs the directory before success; suspicious post-commit changes are reported for manual review, not erased.
- Added regression tests for symlinked parent, preexisting file/symlink markers, hardlinked ticket, altered ticket, and eight-way concurrent single-winner commit; preserved guarded fallback on other systems.
- Existing encrypted inventory/Ed25519 signature, ticket expiration/nonce policy, original specification and local-only maturity are unchanged. No hosted CI, device acceptance, public release or license grant.

## 2026-11-07 — Private offline artifact path hardening (local/unpublished)

- Linux/Android inventory keys, encrypted/signed inventory imports and challenge-ticket reads now refuse symlinks in every parent path component via `openat(O_NOFOLLOW)` from `/`, including special-file inputs. New encrypted-key reads reject hardlinks.
- Local private exports now stage and publish via held parent directory descriptor and same-dir `linkat` no-overwrite commit. Pinned parent identity is verified before/after commit; stages are cleaned on ordinary error, with documented crash-residue privacy risk.
- Other platforms retain a guarded path-based fallback, not equivalent concurrency protection. No actual physical-device, hostile concurrency or hosted CI validation is claimed. See [docs/PROTECTED_OFFLINE_ARTIFACT_IO.md](docs/PROTECTED_OFFLINE_ARTIFACT_IO.md).

## 2026-11-07 — Proposed CI supply-chain pinning (unpublished)

- Replace movable `actions/checkout@v4` and `actions/setup-go@v5` workflow references with exact commit IDs verified from their official `actions` GitHub repositories. Keep workflow permissions `contents: read`. This reduces tag-movement risk but does not audit dependencies or prove hosted CI execution.

## 2026-11-07 — Padded confidential offline inventory v2 (local preview, unpublished)

- New AES-256-GCM offline inventory exports use a domain-separated v2 envelope with an authenticated exact plaintext length and random padding to the next 64 KiB ciphertext bucket. This reduces exact metadata-size inference without hiding large size differences.
- Decrypting clients continue to accept authenticated legacy encrypted v1 envelopes under their original v1 AAD. Changing an envelope's version cannot bypass GCM verification, and plaintext inventory fallback remains forbidden when a key is required.
- Added length-bucket, downgrade, malformed authenticated-length, and legacy compatibility tests. No new credentials, cryptographic dependencies, network modes, deployment, public license grant or hosted CI execution.

## 2026-11-07 — Confidential offline inventory envelope (local preview, unpublished)

- Added optional AES-256-GCM encryption around the existing trusted Ed25519-signed file inventory, with new per-export random nonce and purpose-separated AAD. No plaintext intermediate inventory is written to disk.
- Added no-overwrite private 256-bit key-file generation and strict 0700 parent/0600 file loading. Export/compare with a key requires the encrypted envelope, and plaintext/encrypted downgrade attempts fail closed.
- Integrated existing exact-challenge comparison and one-use ticket logic: a ticket is spent only after successful decryption, pinned signature verification and read-only local comparison. Added Go adversarial tests and an end-to-end CLI test.
- The exchange key must be shared over a separate confidential authenticated channel and is stored unencrypted in a private local file. This does not implement a native keystore, forward secrecy, distributed replay ledger or physical-device acceptance. Source is not published to GitHub.

## 2026-11-06 — Persistent one-use offline request tickets (local preview, unpublished)

- Added optional `-challenge-ticket` issuance and consumption tied to a previously trusted peer, canonical local root and exclusion policy. Tickets are private, no-overwrite, 24-hour state outside the scanned folders.
- After full peer signature/challenge and local comparison success, atomically create and sync a no-overwrite `.used` hardlink before returning the read-only folder report. Exactly one simultaneous comparison wins; reused tickets are rejected across process restarts.
- Added Go race/tampering/expiration/collision tests, end-to-end CLI acceptance, security documentation and proposed CI step. No automatic cleanup or backup rollback protection; deleting spent markers undoes the local replay guarantee.
- This does not provide metadata confidentiality, a distributed replay ledger, a trusted clock, network synchronization or physical-device acceptance.

## 2026-11-06 — Offline inventory request-challenge binding (local preview, unpublished)

- Added a cryptographically random 256-bit per-request public challenge generator, optional signed challenge binding on export, and required challenge matching on read-only comparison.
- A challenged inventory is rejected by unchallenged comparison, while legacy unchallenged exports cannot satisfy challenged requests. No changes to transfer protocols, file contents or other Sync write modes.
- Added Go test cases for signed challenge tampering, noncanonical hex, legacy compatibility, downgrade and replay mismatch, plus CLI acceptance and proposed CI. No durable replay ledger: a response may be replayed if a challenge is reused.
- See [offline challenge guidance](docs/OFFLINE_INVENTORY_CHALLENGE.md). No GitHub publication or physical-device acceptance claimed.

## 2026-11-05 — Signed offline file-inventory comparison (local preview, unpublished)

- Added experimental, explicitly private Ed25519-signed folder inventory export and read-only comparison against a previously pinned peer public key.
- No network listener, source-file payload, transfer, overwrite, deletion or background process. The JSON captures relative filenames, sizes, hashes, excludes and a self-reported timestamp; it is sensitive metadata, not encrypted.
- Enforced no-overwrite private export outside the scanned folder, 16 MiB/100,000-file bounds, strict canonical paths and hashes, canonical exclusions, signature verification against a trusted peer key, and no automatic writes from imported claims.
- Added adversarial unit and CLI tests plus documentation and proposed CI configuration. Requires independent testing on real devices; **no GitHub commit or hosted CI**.

## 2026-11-05 — Sender double-read consistency (local preview)

- Hash a second read through the pinned source descriptor before Nearby Send encryption to reject detected in-place content mutations, including same-size rewrites with restored mtime between passes. Keep pre/post metadata checks and 20 MiB cap. This is a best-effort check, not an atomic snapshot.
- Add deterministic modification/append/truncate tests, explicit performance and threat-model documentation, and a proposed CI regression target. No remote publication or deployment.

## November 5, 2026 — Nearby Send sender source-path hardening (local/unpublished)

- Linux/Android sender file reads use pinned, no-follow directory descriptors and reject source symlinks/special files before opening, including parent symlinks. Portable platforms retain preflight path checks with weaker concurrency protection. Added tests and `docs/SENDER_SOURCE_HARDENING.md`.
- Existing one-time encryption and identity protocol, receiver crash-audit behavior, original product specification and source publication status are unchanged.

## November 5, 2026 — Strict source manifest verification (local/unpublished)

- Added a standard-library Python verifier that rejects source checksum mismatches, missing or unlisted files, duplicate/unsafe manifest entries, and symlinked source contents, plus eight negative/positive tests.
- CI configuration now performs exhaustive verification rather than checking only pre-listed entries. This is not a signature, and hosted CI has not run against the unpublished source.

## November 5, 2026 — Read-only Nearby Send crash-stage inspection (unpublished)


- Added `-audit-receive-dir` for an existing private receiver folder: count and show up to 32 reserved `.gcsend-stage-*` entries without reading contents, changing files, or opening a listener. Exit code 2 indicates manual review is required.
- One-shot receiver initialization, `SaveNew`, and Linux/Android pinned-directory staging now refuse to accept new files if a previous crash left a staging artifact. No automatic recovery/deletion, no assumption that staged plaintext is a complete or authenticated file.
- Added Go tests, loopback-free CLI acceptance, CI configuration and `docs/RECEIVER_CRASH_RECOVERY.md`. Local verification only; no GitHub publication or physical-device testing.

## November 5, 2026 — Local Nearby Send receiver destination safety (unpublished)

- Added Linux/Android directory-descriptor-anchored private staging and no-overwrite `linkat` publication for received files.
- Added before/after destination-root identity checks, collision/root-replacement and symlink tests, and platform fallback for other systems.
- Existing encrypted one-time protocol, original founder specification, and source-only maturity unchanged. No GitHub publication, hosted CI, physical-device acceptance or production deployment is claimed.

## November 5, 2026 — Pre-commit destination identity and staging-residue checks (local/unpublished)

- Revalidate the Linux/Android destination root's device/inode identity and the final directory's reachability from the chosen root immediately before and after the no-replace hardlink commit. Fail closed if the originally pinned directory, root, or an ancestor was moved/replaced. A move after publication is reported as a **partial commit** (never silently called a success).
- Reserve the `.gcsync-stage-*` staging namespace in local inventory scans. Fail on an exposed interrupted stage file or directory, including when an ordinary file-level exclude would hide it; require explicit manual review before copying. Entire deliberately excluded subtrees are not traversed and are never copied. No automated removal is implemented.
- Add relocation/root-replacement tests and the stage-residue protection test. Existing no-overwrite, trusted-folder and no-delete constraints remain. These checks are not an atomic guarantee against malicious concurrent renames.
- No source was published to GitHub, hosted CI run, or device deployed in this local checkpoint.

## November 5, 2026 — Local destination hardening (unpublished)

- Added Linux/Android descriptor-relative destination staging (`openat`), private directory creation (`mkdirat`), and atomic no-overwrite commit (`linkat`), eliminating final-commit redirection through a substituted parent symlink.
- Kept the guarded path-based fallback for other platforms, with documented limitations.
- Added adversarial symlink, staged destination collision, pinned-directory swap, and stage-cleanup regression tests.
- Added Linux ARM64 and Android ARM64 Go command-line cross-build checks (not native client or APK releases).
- Preserved the existing encrypted Share, Nearby Send, durable local Sync, and full original specification.
- No GitHub commit, hosted CI result, deployment, or Stable designation is claimed for this local checkpoint.

## 2026-11-05 — Source path and journal consistency (local, unreleased)

- Changed Linux/Android source inventory and copy reads to refuse symlink traversal through directory-descriptor-anchored `openat` and `O_NOFOLLOW` on every path component. Portable fallback retains prior file-identity checks.
- Changed durable Sync to execute only the pre-recorded pending copy plan, with no second planning step that could admit unjournaled files.
- Tightened post-copy validation to reject unexpected new, missing, or modified paths (including files originally identical) before advancing from pending to ready.
- Added security regressions, implementation notes and honest remaining destination-path race limitations. No source was published to GitHub or deployed through this local checkpoint.

## Unreleased — explicit verified pending-batch recovery (2026-11-03)

- Bump the experimental local durable Sync journal from v1 to v2. Every pending addition now records content SHA-256, size, direction and path **before** filesystem copying. Legacy v1 state files fail closed; back them up and manually re-enroll only after full reconciliation.
- Add `-check-pending-recovery` (read-only eligibility report) and `-finalize-completed-batch` (explicit, zero-copy journal finalization after a complete hash recheck). Every previously shared file remains hash-pinned; unexpected or missing paths reject recovery.
- Preserve the exact prior pending journal as a private, no-overwrite `state.json.recovery-gN.json` backup before advancing generation; no file is copied, overwritten or deleted during recovery. Abort on duplicate backup names, held locks, missing expected files or conflicts.
- Add dedicated Go adversarial tests, a synthetic CLI end-to-end test, CI job step and recovery documentation. This is **local-only development**, not automatically recovering or deployed to GitHub.

## Unreleased — durable foreground Sync history and read-only recovery diagnostics (2026-11-03)

- Upgraded `-sync-additions` to require explicitly initialized private `-sync-state` (no stateless automatic restart). Enrollment accepts **only initially matching folders**, with no-overwrite initial state creation outside both roots.
- New experimental v1 SHA-256-checked persistent state tracks full shared content hashes, ordered canonical folder roots and exclusions, generation and `ready`/`pending` phase. Writes are 0600 staged, fsynced and atomically renamed under stable adjacent flock. A pending marker is persisted **before copying**; incomplete operations do not auto-resume.
- Previously shared file deletions or content changes now fail closed across restarts. Known hash consistency and intended copied content are rechecked after each batch. No deletions, overwrites, conflict resolution, backup or autonomous service are performed.
- Added `-inspect-sync-state` and **read-only** `-audit-sync-state` diagnostics for known-path deletion, changed contents, untracked conflicts and pending operations; neither repairs or accepts a modified journal.
- Removed the legacy in-memory continuous copying API; remaining regression tests now exercise the persistent safety path.
- Go unit/race tests, CLI restart/regression tests, docs/DURABLE_SYNC_STATE.md and configured CI acceptance added. GitHub source publication and hosted CI have not occurred; all verified execution is local.

## Unreleased — explicit two-way additive replication (2026-11-03)

- Added manual `-apply-both-additions` for trusted local directories, reusing the existing checksum-verifying, private staged, no-overwrite copier.
- Added conflict-first preflight, one combined 1,024 file / 1 GiB limit, deterministic per-side partial-commit reporting, and incompatibility with watch, one-way apply or baseline modes.
- Added Go tests, CLI acceptance and CI configuration, and documented non-atomicity, filesystem safety assumptions and absence of continuous/network Sync. No hosted CI or remote publication is implied.

## Unreleased — local experimental foreground observer (2026-11-03)

- Added `-watch` with bounded `-watch-interval` for local, **read-only** folder comparison updates, emitting a complete initial NDJSON snapshot and only material changes afterward.
- Added optional existing-baseline, three-way historical change observation with same-run baseline pinning and fail-closed tamper checks.
- Enforced source/target isolation and incompatibility with automatic write flags; graceful signal shutdown, explicit no-persistence guarantee.
- Added Go race-test coverage and a synthetic CLI acceptance test; configured the additional verification in CI. No GitHub commit, hosted CI or production deployment is implied.

## 2026-11-03 — Session-pinned TLS 1.3 for one-shot Nearby Send (unreleased local continuation)

- Added ephemeral in-memory self-signed Ed25519 TLS certificates deterministically bound to each fresh random 256-bit pairing secret through a distinct key-derivation label. No certificate or private key is persisted.
- Sender enforces TLS 1.3, the expected ephemeral certificate public key, exact literal IP subject alternative name, certificate signature and validity, never trusting arbitrary self-signed certificates or public hostnames.
- Non-loopback receivers now require both `-allow-lan` and `-receive-tls`, explicit private IP and no wildcard. Non-loopback HTTP sender destinations are refused; loopback HTTP remains available for local compatibility.
- Added unit tests for wrong pairing keys, unrelated certificates, wrong interface IP and refusal of plaintext-LAN downgrade, and `tests/secure-lan-cli.sh` combining one-time TLS with persistent pinned mutual identity. Configured CI includes the new test; hosted CI remains unverified.
- Updated `docs/SESSION_TLS.md`, Nearby Send, security and onboarding. Only loopback transfers have been executed. No actual multi-device LAN exposure, automatic pairing, public deployment or production readiness.

## 2026-11-03 — Share admission and metadata-count limits (unreleased, local source only)

- Added a hard cap of 512 active share records alongside the existing 256 MiB physical ciphertext quota.
- Added a process-local fixed-window cap of 60 validated upload attempts per minute, including attempts with invalid ciphertext, enforced before accepting file contents.
- Rechecks record-cap at the commit boundary under the existing app mutex, preventing concurrent uploads from bypassing it; expired records free slots.
- New tests cover early rejection without temporary files, recovery after expiration, rejection when the rate budget is exhausted and window reset. The controls do **not** make this localhost preview internet-safe.

## 2026-11-03 — Signed device-key rollover foundation (unreleased, local source only)

- Added double-signed domain-separated Ed25519 public key rotation proofs; a proof is bound to a locally pinned predecessor, a distinct replacement public key, and both private signing keys.
- New explicit `rotation-proof` (public-only output), `rotation-verify` (no side effects) and `rotation-trust` (staged no-overwrite replacement trust) CLI actions.
- A new pin requires an independently verified complete replacement fingerprint. Neither the old identity nor the old trust record is deleted or replaced implicitly; no active receiver process is modified.
- Added validation limits for proof files, rejection of symlinks and noncanonical identities, tests for forged signatures, unknown predecessor, mismatched fingerprint, malformed input, duplicate pins, and explicit independent retirement.
- Added `tests/rotation-cli.sh` to the development CI workflow. This feature is not unattended key rotation, trust replication, TLS, or production release.

# Development changelog

## 2026-11-03 — Optional mutual device proof for single-use Nearby Send (unreleased local continuation)

- Receiver may now require one explicitly pinned sender Ed25519 identity via `-require-sender-fingerprint`, in addition to a freshly shared one-time transfer secret.
- Sender can require a reciprocal receiver policy using `-mutual-auth`. After verifying the receiver's pinned challenge response, it signs the receiver-issued HMAC-protected random ticket, the session key digest and the exact ciphertext request MAC. Receiver verifies all elements before saving or decrypting the upload.
- Added fail-closed checks for untrusted sender, absent signature, forged ticket, wrong session key, mutual-to-one-way downgrade and one-way-to-mutual downgrade. Default Nearby Send remains unchanged unless both sides explicitly select mutual proof.
- Added adversarial Go unit tests and `tests/mutual-identity-cli.sh` for an actual two-process loopback transfer and impersonation/downgrade checks. Hosted CI and two-physical-device testing remain unverified.
- **Security boundary:** This is manually pinned application-layer identity proof, not TLS, authenticated channel binding, automatic pairing, relay resistance or a production service. One-time key sharing, private file storage and fail-closed public-network restrictions remain necessary.


## 2026-11-03 — Explicit persistent device identity and signed receiver proof (unreleased local continuation)

- Added `internal/deviceid`: private, no-overwrite Ed25519 device identities, full SHA-256 public-key fingerprints, explicit pinned peer trust and removal, read-only listing and validation of trust records. No trust-on-first-use or implicit pairing.
- Added an optional Nearby Send receiver challenge endpoint. A signed, domain-separated proof authenticates the receiver's pinned public key and binds it to a fresh one-time transfer key and sender nonce before any ciphertext upload. No identity or key is silently accepted as a fallback.
- Integrated `-device-action init/show/trust/list/untrust`, `-device-dir`, `-trust-public`, and sender `-peer-fingerprint` flags. The private signing seed never appears in the CLI responses; it is stored **unencrypted** inside a restricted private local file.
- Added unit, adversarial, and loopback CLI tests covering insecure permissions, symlinks, duplicate identities, fingerprint mismatches, malformed trust records, replay, wrong receiver/key, unpaired downgrade and explicit untrust. CI workflow includes `tests/device-identity-cli.sh` (hosted execution unverified).
- Limits: receiver-only identity authentication, manual one-time key exchange, no transport-layer confidentiality for metadata, no PKI or GoreeCloud Identity integration, no two-device LAN acceptance or native app, no production release.

## 2026-11-03 — Read-only, three-way historical sync planning (unreleased local continuation)

- Introduced a private, no-overwrite baseline checkpoint for two initially identical local folder roots and a read-only historical comparison that distinguishes added, modified, deleted, converged and conflicting files.
- Used deterministic SHA-256 comparisons and an explicitly enumerated conflict taxonomy: add/add, modify/modify, and modify/delete. Existing target/source content is never changed by historical planning.
- Hardened the experimental checkpoint schema from v1 to v2 by binding exact canonical absolute source and target roots and their orientation. Mismatches and old-format checkpoints are rejected; the checkpoint must be stored outside both roots and is not an authenticated backup.
- Added tests for swapped/unrelated roots, malformed path identity, immutable checkpoints, exclusion consistency and conflict classifications; added `tests/historical-cli.sh` to configured GitHub CI (hosted CI still unverified).
- Remaining: persistent device identity, actual two-device testing, incremental file indexing, filesystem snapshot consistency, manual conflict resolution UI, deletion safety policy and automatic continuous synchronization.

## 2026-11-03 — Encrypted Nearby Send CLI foundation (unreleased)

- Added a one-file, one-time receiver and sender using an out-of-band random 256-bit pairing key and AES-256-GCM encryption of filenames and contents. Independent derived HMAC keys authenticate transfers and receipts; the secret is read via sender stdin, not command-line arguments or HTTP fields.
- Receiver binds to loopback by default; non-loopback requires explicit `-allow-lan` and only private/link-local interfaces are accepted. Sender forbids public endpoints, DNS, credential-bearing URLs, HTTP proxies, and redirects.
- Added 20 MiB limit, private receiving directory, no-overwrite atomic hardlink commit, destination path validation, and a bounded receiver lifetime (default 5 minutes; maximum 30 minutes). No filename is echoed in the plaintext HTTP response. No LAN listener was run in this development session: integration was exclusively loopback.
- Added adversarial protocol unit tests and `tests/lan-send-cli.sh` full loopback CLI acceptance in GitHub Actions configuration. No actual hosted CI run has happened.
- Remaining: no persistent device pairing, trusted identities, recipient confirmation UI, discovery, TLS, streaming/chunking, resume, native apps, production rate limits or real-device verification.

## 2026-11-03 — Explicit additions-only local replication (unreleased)

- Added a manual `-apply-additions` command requiring source/target roots, with separate read-only preview as the default.
- Added an explicit `-exclude` option for both local planning and application: basename globs, relative globs, and literal recursive directory skips; no implicit ignores, and no claim of Syncthing `.stignore` compatibility.
- Copies source-only regular files with SHA-256 revalidation, private staging, disk sync and atomic no-overwrite hardlink commit. Existing files are preserved; divergent same-path data causes a preflight abort.
- Rejects overlapping directory roots, symlinks, special files, invalid relative paths and stale source content; limits each invocation to 1,024 newly added files / 1 GiB.
- Added tests for empty files, nested files, target-only preservation, repeated idempotent runs, hash changes, conflicts, traversal, symlinks, overlapping roots, batch-size limits and visible partial results.
- Strengthened read-only directory inventory by comparing open file identity with the pre/post path metadata, in addition to SHA-256, size and modification time.
- Explicit limitation: local manual copy only; no continuous/network Sync, two-way conflicts, deletion, overwrite, rollback journal, or validated cross-platform native client.


## 2026-11-03 — Read-only Sync comparison foundation (unreleased)

- Added `internal/syncplan`, a deterministic streaming-SHA-256 local directory inventory and comparison library.
- Added `-plan-source` / `-plan-target` CLI flags for JSON reports. The tool makes no file mutations and does not perform network synchronization.
- Added tests for nested paths, same-size content differences, missing roots, invalid symlink paths and read-only behavior.
- Added explicit security and follow-up design notes in `docs/SYNC_INVENTORY.md`.

## 2026-11-03 — Storage-integrity checkpoint (unreleased, local source bundle)

- Added SHA-256 digests to new encrypted file metadata and verified stored ciphertext before charging download allowance. Browser AES-GCM remains the cryptographic authenticity control.
- Added a **read-only** JSON storage audit (`-audit-store`), identifying corrupted ciphertext, malformed or missing metadata, missing blobs, legacy records, expired shares, and orphan files without modifying them.
- Included orphaned ciphertext and in-progress uploads in physical storage quota checks, preventing unindexed blobs from bypassing the application quota.
- Added regression tests for corruption with no download-count consumption, restoration, store audits, retention of orphaned data, legacy-format compatibility, directory permissions, and quota accounting.
- Preserved the original full 33-section product specification.

## 2026-11-03 — Hardening checkpoint (unreleased, local source bundle)

- Added strict loopback Host validation to reduce DNS-rebinding exposure.
- Added same-origin upload and revocation enforcement, cross-site API protections, and custom-header download gating to prevent simple requests consuming download allowances.
- Added owner-secret-based share revocation: the server stores only a SHA-256 digest of the 256-bit revocation secret, and deletes stored ciphertext and metadata on a valid revocation.
- Added four-upload concurrency limit and rejected unexpected upload media types.
- Added minute-based expiry janitor and graceful process termination.
- Improved expired-file deletion retry behavior.
- Added conservative cleanup of stale, app-owned upload and metadata temporary files after a crash/restart, without touching unrelated user files.
- Added Go tests for DNS rebinding, cross-origin controls, revocation, quotas, concurrent downloads, and expiry cleanup.
- Improved Node encrypted round-trip test to compile and stop its standalone server process, avoiding orphan test processes.
- Added documented threat boundaries, local verification results and future work priorities.

**Status:** Local development candidate only. No completed GitHub commit, hosted CI, public deployment, native app build, or Stable release is represented by this document.

## 2026-11-03 — Foreground local additions-only synchronization (unreleased)

- Added explicit `-sync-additions` with `-sync-interval` (default 15s; 1s–1h) to run the existing two-direction, bounded local additions-only copier in the **foreground**.
- Added NDJSON lifecycle receipts for first scan, successful changed batches, and fail-closed termination. No duplicate heartbeat or silent retry after a partial failure.
- Added per-session **deletion-resurrection guard**: previously shared paths disappearing from one side stop replication without copying other files in the same scan.
- Added Go and shell regressions for propagation, conflicts, exclusions, symlinks, cancel, interval/mode misuse, process exit and previously shared-file deletion.
- Added [foreground Sync safety and recovery documentation](docs/CONTINUOUS_ADDITIONS.md), updated workflow configuration. **Session history is not durable**: restarting may reintroduce a missing file; not full or network Sync, not a backup, not Stable.
