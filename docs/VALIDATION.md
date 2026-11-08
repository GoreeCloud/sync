## November 7, 2026 — Read-only Android ABI/device preflight

`tools/adb_device_preflight.py` refuses implicit selection and uses only `adb devices -l` and whitelisted `adb -s SERIAL shell getprop` queries. The Python unit suite contains eight synthetic/fake-ADB scenarios for ABI matching, 32-bit-only refusal, offline/unlisted devices, invalid selectors, malformed data, timeouts and no serial in output. Run `python3 -B -m unittest discover -s tools -p 'test_*.py'`. The tool does **not** prove Android runtime, Wi-Fi peer connectivity, installability, or protocol acceptance; see `ANDROID_DEVICE_PREFLIGHT.md`. The actual device preflight is read-only and should record sanitized model/ABI evidence privately, not in public repository history.

## November 7, 2026 — Linux/Android ticket-marker commit hardening (local/unpublished)

New `internal/syncplan/consume_ticket_linux.go`, `consume_ticket_other.go` and Linux regression tests verify descriptor-anchored private `.used` hardlink publication after validated offline comparison. `TestTicketMarker*` checks symlinked ancestors, no-overwrite collision and symlink marker handling, hardlinked/mutated ticket rejection, private marker inode identity and concurrent one-winner semantics. Existing `TestOneUse*` and the full CLI workflow continue to exercise replay across restarts. Recommended CI and local checks include `go test -race ./internal/syncplan -run 'TestTicketMarker|TestOneUse' -count=1`, the full race suite and `bash tests/one-use-challenge-cli.sh`. This is local implementation evidence, not a hosted CI or adversarial directory-relocation proof.

## November 6, 2026 — One-use signed inventory tickets (experimental local candidate)

New `internal/syncplan/offline_ticket.go`, targeted race tests and `tests/one-use-challenge-cli.sh` exercise explicit issuance and durable single-winner consumption after trusted signed comparison, including checksum/permissions/expiry, wrong peer/root/excludes, malformed state and replay refusal. The comparing folder remains read-only; ticket directory gets a durable `.used` marker. This is not rollback-proof or a distributed ledger. Actual test results and hashes belong to the current source archive handoff; proposed CI alone does not establish hosted verification. See [one-use ticket documentation](ONE_USE_OFFLINE_TICKETS.md).

## November 6, 2026 — Offline inventory challenge-bound comparison (local implementation; not hosted)

Added optional 256-bit random per-exchange challenge generation and signed binding in `internal/syncplan/offline_inventory.go`, with new CLI flags and fail-closed downgrade checks. Automated tests cover valid trusted matching, wrong/missing challenge, legacy compatibility, invalid canonical hex, signed malicious claims, lack of local file writes, and standalone generation mode. No persistent replay registry or physical-device exchange is claimed. Local test execution and artifact hashes are recorded in the checkpoint handoff, not inferred from CI configuration.

## November 5, 2026 — Signed offline comparison (local implementation; not hosted)

Implemented explicit Ed25519-signed offline inventory export and a read-only verified-peer comparison in `internal/syncplan/offline_inventory.go` plus purpose-separated signatures in `internal/deviceid`. Validation targets include successful private export and no-overwrite, independent trust, matching exclusions, sorted relative paths, signature tampering, path traversal, unknown JSON fields, duplicate entries, a direct output-inside-root refusal, trust removal and a CLI no-write policy. No real-device exchange, hosted GitHub CI, deployment, filesystem-atomic snapshot, or proof of inventory freshness is claimed. This entry documents the implementation and required tests; see this checkpoint's handoff report for actual run outcomes.

# GoreeCloud Sync — Verified local development checkpoint

**Date:** November 3, 2026 (development preview; not Stable or deployed).

I require test-backed progress, explicit security boundaries, and a clear separation between my intended product and its implemented capabilities.

## Source provenance

- The complete 33-section feature specification from the user-provided `Pasted text.txt` is retained without modification at `docs/PRODUCT_SPEC.md`.
- Source document SHA-256: `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9` (37,464 bytes).
- No proprietary Wormhole.app implementation was copied.
- The Go implementation has no third-party module dependencies.

## Tests performed in this execution environment

Go 1.23.2, Node 22.16.0 on Linux, using locally built and executed code:

| Verification | Result | Evidence |
| --- | --- | --- |
| `go test ./...` | PASS | Go HTTP, persistence, corruption, quota and audit tests |
| `go test -race -count=3 ./...` | PASS | Concurrent state tests; no reported races |
| `go test -cover ./...` | PASS | 63.4% Go statement coverage for `cmd/sync`; 84.9% for `internal/syncplan` after adding the safety-bounded apply and exclusions engines |
| `go vet ./...` | PASS | Static vet checks |
| `gofmt -l cmd internal` | PASS | No unformatted Go files |
| `go build -o /tmp/goreecloud-sync-next ./cmd/sync` | PASS | Built a local Linux executable; no package or deployment |
| `node --check cmd/sync/web/app.js` | PASS | JavaScript parse check |
| `node tests/encrypted-roundtrip.mjs` | PASS | Local HTTP/WebCrypto interoperability, wrong-key and ciphertext-tampering rejection, encrypted metadata, owner-only revocation, and download limits |
| Full specification byte comparison | PASS | Embedded Markdown exactly matches original input |
| Real Chromium navigation / UI interaction | BLOCKED | Browser reported `net::ERR_BLOCKED_BY_ADMINISTRATOR` for the test localhost page; no visual acceptance claim |
| Public GitHub publication / hosted CI | NOT VERIFIED | GitHub write was blocked in the prior interaction; public repo only contains initial README |

This checkpoint added five targeted integrity/audit/quota tests and three local folder-comparison tests; its source archive is a local candidate only. Local directory comparison tests also cover content hash differences, traversal safety, deterministic reporting, and read-only behavior. The tests do **not** establish a complete security review, public deployment, native Linux/Android application readiness, interoperability with Syncthing or LocalSend, or the full 33-section product scope.

## November 3, 2026 — additions-only local replication checkpoint

This local follow-up implemented an explicitly selected `-apply-additions` command in `internal/syncplan/apply.go`, an opt-in `-exclude` pattern filter, and a synthetic end-to-end CLI acceptance script. Verification ran under Go 1.23.2, Node 22.16.0 and Linux in the current isolated container:

| Check | Actual result |
| --- | --- |
| `gofmt -l cmd internal` | PASS, no outstanding formatting |
| `go test -race -count=3 ./...` | PASS, including new copy, conflict and traversal tests |
| `go test -cover ./...` | PASS, 63.4% `cmd/sync`; 84.9% `internal/syncplan` statement coverage |
| `go vet ./...` | PASS |
| `go build ./cmd/sync` | PASS |
| `node --check cmd/sync/web/app.js` | PASS |
| `node --check tests/encrypted-roundtrip.mjs` | PASS |
| `node tests/encrypted-roundtrip.mjs` | PASS, local encrypted Share protocol |
| `bash -n tests/additions-cli.sh` | PASS, script syntax |
| `bash tests/additions-cli.sh` | PASS, default read-only plan, explicit exclusions, additions-only copy, idempotence, conflict refusal, target-only preservation |
| Complete uploaded product specification | Unmodified SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9` |

**Verified property scope:** the optional copier with user-defined exclusions does not deliberately overwrite or delete files, refuses known content conflicts, verifies source hashes before committing new names, and shows partial additions when later writes fail. It has no multi-file transaction, no undo journal, no protection against hostile concurrent parent-directory mutation, and no support for target filesystems without hardlinks. This is not a secure peer-to-peer transport, native-client release, or production-ready continuous synchronization implementation.

GitHub main and the existing development branch were rechecked before this work and still pointed at the initial commit. There was no GitHub publication, hosted CI run, real-browser visual acceptance, remote deployment, Drive repository-index edit or new GitHub license selection in this checkpoint.

## Confirmed security behavior

The updated preview now also adds persisted SHA-256 ciphertext digests, verification before retrieval counting, a non-destructive storage audit, and physical quota accounting for app-owned orphaned ciphertext and in-progress uploads.

The preview binds only to literal loopback IPs and validates loopback Host headers. Its Share API requires a matching Origin for upload and revocation, a client header for download, bounded encrypted storage, concurrency limits, expiration cleanup and hashed revocation tokens. Go tests include conservative crash-temporary cleanup and a 60-request race-check scenario where exactly five downloads succeed for a five-retrieval share.

## Open acceptance and operational gaps

1. GitHub branch commit and hosted CI remain blocked and unverified.
2. Browser real-device visual/interaction acceptance cannot be claimed from the blocked Chromium run.
3. Authentication, persistent multi-share revocation management, per-user rate limits, streaming, crash-injection and broader abuse prevention remain unimplemented.
4. Persistent-pairing LAN Send, continuous Sync, and native Linux/Android applications remain unimplemented. A manually paired one-time encrypted Nearby Send CLI exists as a later local preview.
5. No public reverse proxy or production deployment is authorized for this local-only preview. Multi-instance coordination, crash-injected recovery tests and automated deletion of orphaned ciphertext remain open.

## Repeatable verification

```sh
go test -race -count=3 ./...
go test -cover ./...
go vet ./...
go build ./cmd/sync
go run ./cmd/sync -plan-source /path/to/source -plan-target /path/to/target
go run ./cmd/sync -plan-source ./test-source -plan-target ./test-target -apply-additions
bash tests/additions-cli.sh
node --check cmd/sync/web/app.js
node tests/encrypted-roundtrip.mjs
```

For local manual browser evaluation, run `go run ./cmd/sync` and visit `http://127.0.0.1:8787`. Only use test files; do not expose this preview beyond localhost.

## November 3, 2026 — single-use encrypted Nearby Send checkpoint

This local continuation added `internal/lansend`, a command-line one-file receiver (`-receive-dir` / optional `-receive-listen`, `-allow-lan`, `-receive-timeout`) and a sender (`-send-file` / `-send-url` with high-entropy key on standard input). The client encrypts content and the filename, authenticates the request with an independent derived HMAC key, verifies a keyed receiver acknowledgment and refuses public targets, HTTP proxies or redirects. The receiving directory and destination must be private; a receiver accepts only one successful upload, never overwrites, and expires after five minutes by default. Explicit LAN listening support is implemented but **was never invoked on a LAN or VPS in these tests**. All network tests bound loopback (`127.0.0.1`).

New tests cover AES-256-GCM payload confidentiality, fresh nonce separation, tampering and wrong-key rejection, request MAC and receipt authentication, unsigned/replayed requests, filenames, 20 MiB cap, URL restrictions, receiver lifecycle, private file permissions, no-overwrite behavior and a complete sender/receiver CLI loopback test. A source review caught plaintext filename echoing in an HTTP response; that disclosure was removed and a regression test was added.

| Verification | Actual local result |
| --- | --- |
| `go test -race -count=3 ./...` | PASS, all three packages |
| `go test -cover ./...` | PASS, `cmd/sync` 58.3%, `internal/lansend` 80.4%, `internal/syncplan` 84.9% statements |
| `go vet ./...` | PASS |
| `test -z "$(gofmt -l cmd internal)"` | PASS |
| `go build ./cmd/sync` | PASS, Linux only |
| `node --check cmd/sync/web/app.js` and `node --check tests/encrypted-roundtrip.mjs` | PASS |
| `node tests/encrypted-roundtrip.mjs` | PASS, existing encrypted Share integration |
| `bash tests/additions-cli.sh` | PASS, existing bounded additions-only Sync integration |
| `bash tests/lan-send-cli.sh` | PASS, encrypted loopback Send integration and opt-in listener check |
| SHA-256 of full original 33-section specification | `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`, unchanged |

No browser UI acceptance, real two-device LAN testing, firewall penetration review, native Android/Linux installer, public service authentication, complete abuse protection, hosted CI, GitHub source commit, or deployment was completed. The new pairing key authenticates a one-time file transfer; it is **not** a persistent device identity. Review [NEARBY_SEND.md](NEARBY_SEND.md), [SECURITY.md](SECURITY.md) and [PUBLISHING.md](PUBLISHING.md) before further development.

## November 3, 2026 — Read-only three-way planning checkpoint

Implemented a local historical comparison and immutable `0600` JSON baseline capture for two identical folder trees, with deterministic SHA-256 classification of unilateral additions/edits/deletions, shared changes, and add/add, modify/modify and modify/delete conflicts. The format was hardened to **v2** by anchoring the exact local canonical source/target roots and orientation, rejecting wrong-folder reuse. No automatic application, deletion, overwrite, network synchronization or persistence of device identity is implemented.

Acceptance: `go test -race -count=3 ./...`, `go vet ./...`, Go build, `node --check` JavaScript, `node tests/encrypted-roundtrip.mjs`, `bash tests/additions-cli.sh`, `bash tests/lan-send-cli.sh` and new `bash tests/historical-cli.sh`. These are local execution checks only; hosted CI and real device testing require future verification. See [THREE_WAY_PLANNING.md](THREE_WAY_PLANNING.md).

## November 3, 2026 — Local pinned receiver identity checkpoint

Added an explicit Ed25519 identity/trust record package and optional signed Nearby Send receiver proof bound to an unpredictable challenge and the current receiver's one-time pairing key. Identity creation and trust records are private, no-overwrite, and reject permissive permissions, symlinks, fingerprint mismatches and malformed records. Sender-side pinning is opt-in but **fail-closed**: if a pin is configured, a missing, incorrect, or invalid receiver proof stops the encrypted upload instead of falling back to unpinned mode. The private signing seed remains unencrypted on disk and is not exported by management CLI output.

Test implementation includes `internal/deviceid/identity_test.go`, new adversarial `internal/lansend/transfer_test.go` cases, and `tests/device-identity-cli.sh` for two locally launched processes. The end-to-end script confirms pinning, protected transfer, impersonator denial, no fallback to unpaired mode, and explicit pin revocation, using **loopback only**. Actual physical-device LAN acceptance, key vault integration, persistent mutual authentication, secure transport/relay prevention, public service safety and native application packaging remain unverified.

### Exact local verification of the pinned-identity candidate (November 3, 2026)

This continuation independently extracted the previous three-way planner ZIP with its published SHA-256 companion, reviewed relevant source, changed the local copy, and ran the following in an isolated Linux container using Go 1.23.2 and Node 22.16.0:

| Command | Recorded result |
| --- | --- |
| `test -z "$(gofmt -l cmd internal)"` | PASS |
| `go test -race -count=3 ./...` | PASS (all four packages) |
| `go vet ./...` | PASS |
| `go build -o /tmp/gc-sync-device-identity-preview ./cmd/sync` | PASS |
| `go test -cover ./...` | PASS; statement coverage: `cmd/sync` 50.9%, `internal/deviceid` 79.5%, `internal/lansend` 80.5%, `internal/syncplan` 84.2% |
| `node --check` on browser JS and encrypted round-trip test | PASS |
| `node tests/encrypted-roundtrip.mjs` | PASS |
| `bash tests/additions-cli.sh` | PASS |
| `bash tests/historical-cli.sh` | PASS |
| `bash tests/lan-send-cli.sh` | PASS |
| `bash tests/device-identity-cli.sh` | PASS; pinned valid receiver, mismatched public key, impersonation attempt, unpaired fallback refusal, explicit untrust |
| `cmp docs/PRODUCT_SPEC.md` against original uploaded source | PASS; SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9` |

These are local test results, not GitHub-hosted CI, static-security certification, authenticated mutual pairing, real LAN network acceptance, native Linux/Android packaging, or a release approval. No network listener outside localhost was created during these tests. No GitHub source publication, public VPS deployment, or canonical Google Drive index mutation was performed.


## November 3, 2026 — Mutual sender/receiver proof continuation

Implemented optional receiver-side pinned sender authentication and sender `-mutual-auth` opt-in. The receiver issues a MAC-protected random ticket and requires an Ed25519 signature from the pinned sending device bound to the receiver session and the exact upload request MAC; the receiver already proves its pinned identity before the sender transmits encrypted bytes. An unverified sender with the shared one-time key cannot complete a mutual-mode transfer. Pinned senders refuse a missing required-sender policy when mutual mode was requested and refuse a required-sender policy when one-sided mode was selected. The receiver only supports one successful upload per process.

New local Go tests cover mutual success, unpinned sender denial, impersonation rejection, bad ticket and signature denial, and both policy downgrade directions. `tests/mutual-identity-cli.sh` performs a complete loopback two-process mutually authenticated encrypted transfer, with synthetic private identities and explicitly configured two-way pins. **This is still an HTTP application-layer proof, not mutual TLS, automatic pairing, a channel-bound identity protocol, or two-physical-device acceptance.** GitHub CI and public service deployment are not claimed.

### Exact local validation of optional mutual-identity candidate (November 3, 2026)

On isolated Linux with Go 1.23.2 and Node 22.16.0, the working source passed `go test -race -count=3 ./...`, `go vet ./...`, `test -z "$(gofmt -l cmd internal)"`, `go build ./cmd/sync`, and `go test -cover ./...`. Recorded statement coverage: `cmd/sync` **49.1%**, `internal/deviceid` **80.5%**, `internal/lansend` **81.0%**, `internal/syncplan` **84.2%**. Syntax and integration checks passed for browser JavaScript, encrypted Share roundtrip, additions-only Sync, historical three-way Sync, Nearby Send CLI, pinned receiver CLI, and mutual-identity CLI. The full original founder-supplied 33-section specification remained byte-for-byte unchanged (SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`). Local checks do **not** establish real-browser acceptance, hosted CI, physical two-device transfer safety, deployed service operation, or Stable release readiness.

## November 3, 2026 — signed device identity rollover (local preview)

Added `internal/deviceid/rotation.go` and targeted tests for dual Ed25519 signatures bound to an ordered old-to-new identity transition. A verifier must load its existing pinned predecessor; unsigned/untrusted substitution is rejected. `rotation-trust` requires an independently verified new full fingerprint, creates an additional no-overwrite record, and never removes an old pin or changes a private identity. CLI end-to-end tests use synthetic identities and no network listeners. Commands: `go test -race ./...`, `bash tests/rotation-cli.sh`. The actual recorded results and exact tested source archive checksum should be included with the packaging checkpoint; hosted CI and physical-device validation are still unverified.

## November 3, 2026 — Share admission and record count limits (local preview)

Added `cmd/sync/limits_test.go` validating early `507` rejection when 512 active records exist, slot reclamation after expiration, early `429` rejection after 60 upload attempts/minute, and reset after a minute without creating unwanted temporary files. Rate budgets are per-process and not durable; no public-network security or authentication claim. Full test results for this checkpoint are recorded in the delivery report and clean-extraction verification, not in hosted GitHub CI.


## November 3, 2026 — Session-pinned TLS checkpoint (local, uncommitted)

**Scope:** After reviewing the current 47-file, checksummed, locally distributed key-rotation source candidate, I implemented only the experimental `Nearby Send` transport hardening documented in [`SESSION_TLS.md`](SESSION_TLS.md). No public GitHub source commit, hosted GitHub Actions run, VPS deployment, privileged remote operation, real two-device LAN transfer, Linux-native package, Android APK, or product-wide security audit was completed.

**Evidence (Go 1.23.2, Node 22.16.0, local Linux):**

| Verification | Result |
| --- | --- |
| `go test -race -count=3 ./...` | PASS, all four packages |
| `go vet ./...` and `test -z "$(gofmt -l cmd internal)"` | PASS |
| `go build -o /tmp/goreecloud-sync-tls-check ./cmd/sync` | PASS |
| `node --check cmd/sync/web/app.js` and `node --check tests/encrypted-roundtrip.mjs` | PASS |
| `node tests/encrypted-roundtrip.mjs` | PASS, ciphertext Share round-trip, tamper, revoke and limits |
| `bash tests/additions-cli.sh` | PASS, additions-only safe replication |
| `bash tests/lan-send-cli.sh` | PASS, legacy loopback HTTP one-shot transfer |
| `bash tests/device-identity-cli.sh` | PASS, trusted receiver identity |
| `bash tests/mutual-identity-cli.sh` | PASS, explicit mutual proof |
| `bash tests/rotation-cli.sh` | PASS, signed manual identity rollover |
| `bash tests/historical-cli.sh` | PASS, three-way read-only history |
| `bash tests/secure-lan-cli.sh` | PASS, session-pinned TLS 1.3 with manually trusted mutual device identities, wrong-key and downgrade refusal |
| `go test -cover ./...` | PASS: cmd/sync 49.1%, internal/deviceid 82.5%, internal/lansend 81.7%, internal/syncplan 84.2% |
| `sha256sum docs/PRODUCT_SPEC.md` | `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`; exact match with original user-uploaded source |

**New safeguards:** TLS 1.3 server certificate exists only in memory, signed using an Ed25519 seed derived from the separate `ephemeral-tls-certificate-ed25519` pairing-key label. The sender checks the certificate's public key against that fresh out-of-band key, the intended literal IP subject alternative name, time validity, signature and TLS protocol. Plain HTTP is refused for non-loopback addresses; non-loopback receivers must opt in to a specific private interface and TLS; wildcard addresses are rejected. The previously implemented end-to-end AES-256-GCM envelope, HMAC receipt, and manual public-key identity pinning remain independent. Tests exercise these conditions **on loopback**, not a physical LAN. TLS does not protect against exfiltration of the pairing secret or malicious endpoint software; the design has not been externally audited.

**Publication state:** The publicly checked `GoreeCloud/sync` repository still holds its initial placeholder README on main, and its `feat/initial-share-foundation` branch still has the initial commit. A previously encountered GitHub write policy block was not bypassed. The revised `SOURCE_SHA256SUMS.txt` and source ZIP are local development artifacts only.

## Read-only watch regression checkpoint — 2026-11-03

The opt-in foreground `-watch` workflow was implemented locally with a 1s–1h polling bound, initial + change-only NDJSON observations, explicit immutable-baseline comparison and error-on-tamper behavior. Added `internal/syncplan/watch_test.go` and `tests/watch-cli.sh`; the existing GitHub workflow configuration now includes the CLI acceptance test. Verification scope is local temporary directories only. This feature does **not** perform continuous replication, network syncing, automated deletion, native UI integration or hosted background work. See `docs/READ_ONLY_WATCH.md` for security and resource limits.

### Verified 2026-11-03 local read-only observation acceptance

- `gofmt` check: PASS. `go test -race ./...`: PASS. `go vet ./...`: PASS. Build of `cmd/sync`: PASS.
- Node encrypted Share round-trip: PASS. Additions-only CLI, one-time Nearby Send CLI, persistent identity CLI, mutual identity CLI, signed key rotation CLI and session-key-pinned TLS CLI: PASS.
- Initial combined verification command reached its execution timeout while entering the historical CLI script; the latter was rerun independently and PASSED. `tests/watch-cli.sh` was also run separately and PASSED. The timeout must not be represented as a finished combined run.
- `go test -cover ./...` reported cmd/sync 47.9%, internal/deviceid 82.5%, internal/lansend 81.7%, and internal/syncplan 84.4% statement coverage. Coverage percentages are diagnostic, not production security claims.
- `docs/PRODUCT_SPEC.md` was compared byte-by-byte against the original upload and its SHA-256 remained `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`.
- Watch-specific unit tests verify initial/change-only emission, historical modify/modify conflict classification, baseline mutation stop, invalid/overlapping roots, cancellation and symlink refusal. CLI test verifies opt-in exclude patterns and that attempts to combine watch with writes fail.
- All validation was local and synthetic; no two-physical-device, real-browser, GitHub Actions, native Android/Linux UI, LAN infrastructure or production deployment was run.

### Manual bidirectional additive acceptance — 2026-11-03

Added `internal/syncplan/bidirectional.go`, `internal/syncplan/bidirectional_test.go` and `tests/bidirectional-cli.sh`. Verified synthetic local two-way additions, symmetric filters, repeat idempotence, unchanged file identity, preflight conflict rejection before either direction writes, combined 1,024-file safety cap, partial-result reporting when a later destination directory collision occurs, symlink rejection and unsafe mode combinations. Existing `copyOneAtomic` revalidates content SHA-256 before committing new files with hardlink-based no-overwrite. The code does NOT provide all-or-nothing rollback or protections against hostile concurrent path mutation. No network or production operations occurred.

### Consolidated observer and bidirectional-additions regression — 2026-11-03

- Source Go formatting (`gofmt`), `go vet ./...`, build and `go test -race ./...`: PASS.
- Encrypted Share Node integration, one-time Nearby Send, pinned persistent identity, mutual identity, signed rotation, and session-pinned TLS shell tests: PASS.
- Local additions-only, immutable three-way planning, foreground watch and bidirectional additions-only CLI checks: PASS in isolated synthetic directories.
- Go statement coverage after both improvements: cmd/sync 47.4%, internal/deviceid 82.5%, internal/lansend 81.7%, internal/syncplan 85.2%.
- Original `docs/PRODUCT_SPEC.md` still equals the uploaded file byte-for-byte (SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`).
- No real-browser, physical two-device LAN, native Linux/Android UI, hosted GitHub CI, or production test was conducted. The public `GoreeCloud/sync` repository remains an initial placeholder due to prior platform safety blocks.


## 2026-11-03 — Foreground additions-only development checkpoint

The local code adds `internal/syncplan/continuous.go`, guarded reuse of the original bidirectional additions copier, `-sync-additions/-sync-interval`, Go race-focused unit tests and `tests/continuous-additions-cli.sh`. The command does not daemonize or connect network peers. Per-process in-memory tracking blocks re-creation of a previously shared file removed from one side during that process, but **does not preserve deletion intent across restart**. The CLI/Go tests exercise conflict stops, no-overwrite behavior, creation receipts, Ctrl+C cancellation, selective exclusions and deletion detection. Actual validation evidence (local/clean extraction) must be recorded separately from hosted CI; publication and two-device validation remain unverified.

### Verified local checks for foreground additions-only code — 2026-11-03

- `test -z "$(gofmt -l cmd internal)"`: PASS.
- `go test -race -count=2 ./...`: PASS; all Go packages including the new `internal/syncplan` tests.
- `go vet ./...` and `go build -o /tmp/goreecloud-sync-20261103-continuous ./cmd/sync`: PASS.
- JavaScript syntax (`node --check`) and `node tests/encrypted-roundtrip.mjs`: PASS.
- `bash tests/continuous-additions-cli.sh`: PASS, including initial bidirectional copy, a later scan, excluded paths, preflight conflict termination, incompatible flags, and previous-shared-file deletion stop.
- All existing shell CLI regressions (`additions`, `bidirectional`, `device-identity`, `historical`, `lan-send`, `mutual-identity`, `rotation`, `secure-lan`, and `watch`): PASS when run as individually bounded scripts.
- The initial combined command did NOT finish because the cumulative command timed out after it reached coverage; `go test -cover ./internal/syncplan -v` was rerun independently and PASS, reporting **85.9%** statement coverage. The timeout is not misrepresented as a passed combined command.
- No hosted GitHub CI, production deployment, physical-device transfer, native platform acceptance, live network Sync, or durable deletion-journal testing was performed.

## Durable local Sync journal development checkpoint — November 3, 2026

Implemented and locally exercised `internal/syncplan/durable.go` and `durable_audit.go` (experimental v1 file format). The foreground CLI now requires `-sync-state` and an explicit no-overwrite `-init-sync-state` after the two filtered inventories match. The journal's `pending` phase is saved before file copies and forces a fail-closed restart after incomplete batches. Known paths and SHA-256 hashes are persisted across clean restarts; deletion/changes on either side stop copying before any unrelated additions. Added read-only `-inspect-sync-state` / `-audit-sync-state` and tests for permissions, symlinks, corrupted state, exact-root/exclusion binding, pending states, wrong direction, interprocess locks, identical manual changes, missing files on both sides and restart deletion safety. No work was performed against production user folders or remote devices. Actual per-command verification and packaging evidence must be recorded at the tested checkpoint; the code has not been published to GitHub and hosted CI is still unverified.

### Tested local durable checkpoint — November 3, 2026 (latest)

**Scope:** No GitHub publish, hosted Actions, VPS listener, native app, Android package, real-browser acceptance, or physical two-device test. This checkpoint was built and checked solely in isolated local Linux directories. No data directories outside the disposable test fixtures were synchronized or modified.

**Verified commands:** `go test -race ./...` PASS for four packages; `go vet ./...`, `test -z "$(gofmt -l cmd internal)"`, Go binary build and Node syntax PASS. The Node encrypted Share protocol integration passed. CLI acceptance scripts for encrypted Nearby Send, device identity, mutual identity, signed rotation, session-pinned TLS, one-way additions, two-way additions, foreground additions, durable state initialization/restart/audit, historical planning and read-only watch all passed independently.

**Coverage (Go statements):** `cmd/sync` 44.1%, `internal/deviceid` 82.5%, `internal/lansend` 81.7%, `internal/syncplan` 82.0%. Lower coverage in `cmd/sync` should be addressed before a product-wide release. An earlier combined command timed out while attempting an optional Android cross-compilation; it is **not** counted as completed Android acceptance or a successful combined run. All other checks above were run independently and completed.

**Safety evidence:** Durable CLI now refuses use without a private state, requires matching-filtered initial enrollment, rejects reversed roots/exclusions and corrupt/symlink/mispermissioned history, detects deleted or modified previously shared files across restarts before copying new files, and never resumes a `pending` phase without manual review. Read-only audit reports known-path corruption/deletions, untracked conflicts and pending operations without modifying files. Adversarial tests include a second worker blocked by flock, and known files missing from both folders. Partial file copying and manual recovery remain possible.

**Specification preservation:** The entire original founder-supplied `docs/PRODUCT_SPEC.md` is byte-identical to the uploaded source; SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`. The ZIP-level and extracted per-file checksum results will be recorded alongside the final archive.

## November 3, 2026 — pending recovery local verification

Source-only experimental journal format v2 adds SHA-256-addressed pending intents and explicit zero-copy finalization after complete preflight. New tests cover completed recovery and private backup, refusal of incomplete batches, changed expected/known files, unexpected new files, conflicting roots, held locks, backup collisions, legacy version rejection, and post-recovery deletion resurrection. `tests/pending-recovery-cli.sh` verifies the command-line user flow. Build, race tests, static checks and archive-provenance checks are documented at the final delivery checkpoint. **No GitHub code publication, hosted CI, production recovery, physical-device validation or real user-folder operations are implied.**

### Verified local test results — completed-batch recovery checkpoint

After adding the per-file recovery assessment, I verified this working source using Go 1.23.2 and Node 22.16.0. `test -z "$(gofmt -l cmd internal)"`, `go vet ./...`, `go test -race -count=2 ./...`, `go build ./cmd/sync`, `node --check cmd/sync/web/app.js` and `node tests/encrypted-roundtrip.mjs` **all passed locally**. The complete existing local CLI matrix passed separately: additions-only, bidirectional additions, continuous additions, durable restart/audit, three-way history, read-only watch, LAN Send, persistent identity, mutual authentication, signed key rotation and session-pinned TLS. The new `tests/pending-recovery-cli.sh` passed its unfinished-batch refusal, file-level read-only status report, manual-completion check, explicit zero-copy finalization, exact pending-journal backup and restart deletion guard. The new recovery unit tests cover missing, changed, unexpected and symlink-sensitive path failures, journal version/intent corruption, lock contention and existing backup files.

Go statement coverage: `internal/syncplan` **82.8%**, `internal/deviceid` **82.5%**, `internal/lansend` **81.7%**, `cmd/sync` **43.1%**. These are source-local test measurements, not GitHub-hosted CI. The 33-section uploaded product specification remains byte-identical to `docs/PRODUCT_SPEC.md`, SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`. No physical device, real browser or production acceptance is claimed.

## November 5, 2026 local journal/path hardening checkpoint

**New code:** `internal/syncplan/open_regular_linux.go` (Linux/Android), `open_regular_other.go` (portable fallback), `journal_path_hardening_test.go`, updated inventory, copier, and durable batch logic. These files exist in the local source archive only; do not infer GitHub publication or hosted CI execution.

**Verified locally:** `go test -race ./...`, `go vet ./...`, `go build ./cmd/sync`, JavaScript syntax, Node encrypted Share test, plus additions-only, bidirectional, continuous, durable state, pending recovery, historical, watch, LAN Send, device identity, mutual auth, signed key rotation and pinned TLS shell tests. Tests exercise only ephemeral local files and loopback networking, not physical Android/Linux GUI acceptance. Exact archive digest is recorded separately after final packaging and clean-extraction validation.

**Security boundaries:** descriptor-anchored nofollow reads on Linux/Android do not imply path-race-safe destination writes, atomic snapshots, fully hostile filesystem resistance, native mobile release, or independently validated production security.

## November 5, 2026 — Destination descriptor checkpoint (local evidence)

The Linux/Android local copier now uses pinned directory descriptors for private staging and no-overwrite `linkat` commits, instead of pathname-based destination hardlinks. Regression cases cover symlink destination parents, symlinked roots, traversal names, target creation between stage and commit, stable opened directory handles following pathname substitution, and no leftover staging entries after hash failure. The prior source-read and exact durable journal tests remain in scope.

Locally observed: `go test -race ./...`, `go vet ./...`, Go build, formatting, JS syntax, and command-line backend cross-compilation to Linux ARM64 and Android ARM64 passed. The complete integration tests and fresh-extraction verification are tracked separately in the checkpoint validation report and must not be inferred from cross-build success alone. The `SOURCE_SHA256SUMS.txt` manifest must be regenerated after these changes, before packaging.

Not verified: actual Android app, physical device or platform-specific filesystem semantics, hostile directory relocation confinement, hosted CI, public GitHub source publication, production deployment or Stable status.

### Final local validation of destination-descriptor implementation

On November 5, 2026, the following completed successfully against the modified source: `go test -race ./...` (all four packages); `go vet ./...`; `test -z "$(gofmt -l cmd internal)"`; Go CLI build; Linux ARM64 and Android ARM64 command-line cross-compilation; JavaScript syntax checks; Node encrypted Share round-trip; and **all 12** repository `tests/*.sh` CLI acceptance scripts (additions, bidirectional, continuous, device identity, durable state, historical planning, LAN Send, mutual identity, pending recovery, key rotation, pinned TLS, and read-only watch). Statement coverage for `internal/syncplan` was **82.3%**. The complete 33-section product specification matched the original user-provided text by SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`. A bounded text scan did not find obvious private-key or GitHub/OpenAI token literal patterns; it is not a comprehensive secret scan.

These results were observed in a local container. A build for Android ARM64 is a Go executable only: it is **not** an Android APK, a native application, or a physical-device test. Linux/Android filesystem behavior on physical devices, hostile directory relocation, public hosting, production deployment, hosted GitHub Actions CI, and release readiness remain unverified. The canonical GitHub repository still contains only the original `README.md` at the time of verification; these new source changes were **not** committed or pushed to GitHub.

### November 5, 2026 — Local pre-commit path identity and staging residue checkpoint

Implemented Linux/Android root/directory inode checks immediately before and after the descriptor-relative no-replace destination commit, and a fail-closed scan rule for reserved `.gcsync-stage-*` names (excluding already-skipped subtrees). Added focused tests for replaced root, moved ancestor, renamed directory plus symlink, and crash-residue refusal. An ordinary file-level exclude cannot hide an encountered staging artifact. These are **development checks only**, not proof of atomic confinement under hostile concurrent directory renames. The original 33-section product specification remains unmodified. Full regression and cross-build results for this checkpoint must be established from executed commands and recorded separately from earlier checkpoint results. GitHub publication and hosted CI remain unverified.

### November 5, 2026 — Receiver destination hardening test scope

Source-only regression cases for Linux/Android `SaveNew`: private root enforcement, held-directory staging and removal, no-overwrite, post-open root replacement, symlink replacement, and existing final-file collision; existing encrypted sender/receiver and mutual-auth tests remain in the Go race suite. Local and clean-extraction test evidence is summarized in the delivered archive checkpoint. No physical LAN device, Android APK, or public-service acceptance is inferred.

### November 5, 2026 — Receiver crash-staging read-only audit (local source only)

Configured checks: `go test -race ./internal/lansend`, `bash tests/receiver-residue-cli.sh`, and the unchanged encrypted Share, Nearby Send and local Sync integrations. New negative tests cover stale regular staging files, reserved-name symlinks, unsafe destination permissions, bounded reporting and startup refusal before a network listener. No automatic deletion, physical-device acceptance, GitHub CI or production release is inferred. The final archive and independent extraction checks are recorded with its published local checksum.

## November 5, 2026 — Sender source-open hardening (local/unpublished)

- The Nearby Send sender now uses no-follow directory descriptor file opens on Linux/Android. Tests include source symlinks, parent symlinks, a swapped pathname after opening, FIFO refusal without blocking, missing and directory paths, and successful encrypted loopback transfer.
- Intended validation: `go test -race ./...`, `go vet ./...`, `go build ./cmd/sync`, compile-only cross builds, encrypted Share integration and all CLI scripts. These results must be recorded separately after successful execution; no hosted GitHub CI or physical-device verification is assumed.
- Source files remain mutable in place by a process with local write access; this is not an atomic file snapshot. See [sender-source hardening](SENDER_SOURCE_HARDENING.md).

## November 5, 2026 — Exhaustive source manifest (local/unpublished)

- Added `tools/verify_source_manifest.py` and eight standard-library unit tests. The verifier checks all bundled regular files, not only lines listed in `SOURCE_SHA256SUMS.txt`, and rejects symlinks, missing files, unexpected files, duplicate/malformed entries and digest mismatches.
- CI configuration runs this validation before compilation; no hosted GitHub CI or source publication has occurred. This is not a digital signature or proof of original source authorship.

### Verified local result — November 5, 2026

- `go test -race -count=2 ./...`: PASS across all four Go packages.
- `go vet ./...`, `gofmt` check, local Go build, `node --check` for both JS files: PASS, each in a bounded separate run. An earlier combined test command timed out **after** the four Go race tests; the remaining checks were rerun separately and passed.
- `node tests/encrypted-roundtrip.mjs`: PASS (AES-GCM Share, tampering, download limits and revocation).
- All 14 Nearby Send and local Sync CLI acceptance scripts, including new `tests/sender-source-cli.sh`: PASS. Independent scripts used local synthetic files and loopback listeners only.
- `CGO_ENABLED=0` Go backend cross-compiles for Linux ARM64, Android ARM64, macOS ARM64 and Windows AMD64: PASS; **not** native application or physical-device acceptance.
- `go test -cover`: lansend 81.8% and syncplan 82.2% statement coverage. Coverage is not a claim of comprehensive security acceptance.
- `python3 -B -m unittest discover -s tools -p 'test_*.py'`: eight tests PASS. `python3 -B tools/verify_source_manifest.py` checks the complete local source manifest, PASS after regeneration.
- The original `docs/PRODUCT_SPEC.md` remains byte-identical to the user-provided specification (SHA-256 `38658373f9dd235318290b5f34a5980ec0632e461a9a70bf672e443d660621f9`).
- Hosted GitHub CI, physical-device transfer and production deployment: **not performed**. Verified GitHub main remains README-only at the start of this turn.

## November 5, 2026 — Sender content double-read checkpoint (local)

Added a SHA-256 second-pass content comparison before Nearby Send encryption/upload, keeping the 20 MiB cap and descriptor-anchored source opening. Deterministic tests cover a same-length in-place rewrite with restored mtime, append/truncate detection, stable regular and empty files, and symlink refusal. Does not establish filesystem snapshot atomicity. Final local validation evidence and distributable checksums are recorded in the release handoff for this checkpoint.

## November 7, 2026 — Confidential offline inventory verification target

New tests `internal/syncplan/offline_encryption_test.go` and `tests/confidential-offline-cli.sh` cover encryption/decryption, independently pinned Ed25519 validation, signed challenges, one-use ticket consumption, wrong keys, tampering, strict no-plaintext fallback, no-overwrite, private key modes and metadata non-disclosure. Run `go test -race ./...`, `go vet ./...`, `bash tests/confidential-offline-cli.sh`, and the full integration matrix. Source packaging and live publication claims require separately verified artifact checksums and exact repository readback; this documentation alone is not evidence of test completion.

## November 7, 2026 — confidential inventory padding regression (local)

- `go test -race ./internal/syncplan -run 'TestPaddedConfidential|TestLegacyConfidential|TestConfidential' -count=1` verifies AES-GCM v2 padded-bucket privacy, legacy encrypted v1 authenticated read compatibility, forged version rejection and malformed authenticated length fail-closed.
- `bash tests/confidential-offline-cli.sh` checks the v2 envelope version, 64 KiB ciphertext bucket structure and the existing challenge-bound decryption/one-use ticket flow.
- Run full race/unit/static/CLI checks and exact source-manifest verification on each archive; proposed GitHub CI remains **unhosted** until a permitted source commit exists.

## November 7, 2026 — proposed GitHub CI action provenance

The **unpublished** `.github/workflows/verify.yml` now references exact upstream `actions` organization commit IDs: checkout v4 tag `11d5960a326750d5838078e36cf38b85af677262` and setup-go v5 tag `40f1582b2485089dde7abd97c1529aa768e1baff`, freshly resolved from official GitHub tag references. This avoids relying on mutable major-version tags at CI runtime. This alone is not a complete supply-chain audit or a hosted workflow run.

## November 7, 2026 — Protected offline artifact I/O regression target

The Linux/Android tests in `internal/syncplan/protected_file_linux_test.go` exercise parent symlink rejection, hardlink refusal for symmetric keys, FIFO nonblocking refusal, no-overwrite, private staging permissions and stage cleanup. Target: `go test -race ./internal/syncplan -run TestProtected -count=1`. This local preview still requires full race, integration, cross-platform build, clean-extraction and manifest verification before declaring a completed source checkpoint; hosted CI and physical devices remain unverified.

## November 7, 2026 — device identity-store storage safety (local)

Run `go test -race ./internal/deviceid -run 'TestDeviceIdentity|TestDeviceTrust|TestTrust|TestUntrust' -count=2`, full `go test -race ./...`, and the CLI identity, mutual identity and rotation scripts. Linux tests confirm no-follow rejection of symlinked ancestors, hardlink refusal for private seed/trust files, no-overwrite trust enrollment with a single winner, and descriptor-relative trust removal. These are not physical-device or hostile-kernel acceptance. Proposed GitHub workflow remains unpublished.
