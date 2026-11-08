# One-use offline inventory challenge tickets — experimental local preview

**Status:** locally implemented and tested; not committed to GitHub or accepted on two physical devices. This mode makes no changes to the compared folders, but **does write a private persistent replay marker outside them**.

## Purpose

A random 256-bit request challenge prevents an older signed inventory from satisfying a *different* request, but a previously used challenge could be replayed. This optional local ticket workflow records a newly issued challenge for one trusted peer, one canonical local folder and one exclusion policy. After a fully verified successful comparison, it makes the ticket unusable for later comparisons, including after process restart.

## Prerequisites

1. The comparing device has an initialized private identity directory and has explicitly trusted the exporting peer's Ed25519 public key after independently checking its **complete** `sha256:` fingerprint.
2. Create a **separate existing private 0700 directory** outside the compared local folder to hold request tickets and their spent markers. Use a new ticket filename for every comparison. This is sensitive local state; preserve it and its backups.
3. Both devices agree on any `-exclude` patterns. The exporter does not need the comparing device's private identity or its ticket file.

## Manual example

```sh
# Comparing device: issue a durable challenge bound to trusted peer and local folder.
gcsync -new-inventory-challenge -plan-source /private/local-folder \
  -device-dir /private/local-identity -peer-fingerprint 'sha256:VERIFIED_PEER_FINGERPRINT' \
  -challenge-ticket /private/tickets/request-001.json

# Send ONLY the 64-character challenge from that output to the exporting device.
# Exporting device: sign an offline inventory bound to the supplied challenge.
gcsync -plan-source /private/peer-folder -device-dir /private/peer-identity \
  -inventory-challenge '64-lowercase-hex-challenge' \
  -export-inventory /private/outside/response-001.json

# Transfer response-001.json through an appropriate confidential channel.
# Comparing device: verify trusted signer, challenge, folder, excludes and content;
# then create request-001.json.used *before* returning the read-only report.
gcsync -plan-source /private/local-folder \
  -device-dir /private/local-identity -peer-fingerprint 'sha256:VERIFIED_PEER_FINGERPRINT' \
  -challenge-ticket /private/tickets/request-001.json \
  -compare-inventory /private/response-001.json
```

Repeat identical `-exclude` flags for issuance, peer export, and comparison whenever filters are used. The issuance command prints `oneUseTicketIssued: true`; a successful comparison prints `challengeVerified: true` and `oneUseChallengeConsumed: true`.

## Storage, crash behavior and limitations

- Tickets are new, private `0600` files in a real `0700` parent directory. A ticket contains a public random nonce, pinned peer fingerprint, canonical **absolute local folder path**, exclusion list and timestamp, plus an integrity checksum. This local metadata can be sensitive; the checksum detects accidental corruption but is **not** an authenticity signature.
- Tickets expire **24 hours** after issuance and reject clock rollback beyond five minutes. Local clock integrity is not independently established. An expired ticket cannot be consumed; issue a fresh ticket in a new filename.
- On **Linux/Android**, marker creation opens the entire ticket parent path through no-follow directory descriptors, checks the private `0700` directory, reopens and validates the private `0600`, single-linked ticket inode and checked JSON contents, and publishes `.used` via no-overwrite `linkat` within the same pinned directory descriptor. It syncs the directory before returning success. Path/inode checks cannot prevent a hostile process from relocating an already-open directory **between** checks; after-commit uncertainty requires manual review. Other operating systems retain a weaker checked-path fallback. See [marker commit safety](TICKET_MARKER_COMMIT_SAFETY.md).
- The comparing process verifies the trusted peer's Ed25519 signature, exact signed challenge and local comparison first. On success it **atomically hardlinks** `request-001.json` to `request-001.json.used` with no overwrite, then syncs the directory. Only the process that creates this marker can return a successful comparison. If the process crashes after marker creation, the ticket remains spent; manual creation of a fresh request is required. Failures before the marker leave the ticket available for a corrected response.
- **Keep both the issued ticket and its `.used` hardlink indefinitely**, or until an explicitly designed archival process is implemented. Deleting `.used`, restoring an old filesystem snapshot that lacks it, duplicating an issued ticket under another name, or a malicious process with the same local-account permissions can undo the replay guarantee. The guard is *per ticket pathname*, not a tamper-proof or distributed anti-replay database.
- Hardlinks and directory sync are required. If a filesystem or platform does not support them, consumption fails closed; successful cross-compilation is not proof of runtime compatibility.
- Unchallenged legacy comparison and explicit `-expect-inventory-challenge` without a ticket remain available and **do not consume replay state**. Choose ticket mode whenever one-time use matters. Ticket mode deliberately rejects also passing `-expect-inventory-challenge`, to avoid ambiguous expectations.
- The export is signed, **not encrypted**. Filenames, hashes, sizes and timestamps remain visible; the peer can lie about its own inventory, and local scanning is not an atomic snapshot. This feature never authorizes copying, deleting or overwriting user files, and does not implement network Sync, a trusted clock, or a native app.

## Verification

`go test -race ./internal/syncplan -run 'TestOneUse' -count=1` and `bash tests/one-use-challenge-cli.sh` cover issuance, private file permissions, tampering, expiration, wrong folder/exclusions/challenge, single-winner concurrent consumption, persisted `.used` marker, no-overwrite and CLI downgrades. Local synthetic testing does not substitute for a physical two-device test or an independent security review.
