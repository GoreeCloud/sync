# Fresh-challenge binding for signed offline inventories — experimental preview

**Status:** locally implemented / not published or hosted-CI verified. This is a read-only, manual exchange that does not copy files or create a network connection.

## Why this exists

An Ed25519 signature proves an inventory was signed with a trusted peer key, but an older valid signed file can be replayed. A new 256-bit random **request challenge** lets the comparing device request a signed inventory specifically for this exchange. The exporter must put that challenge inside the signed canonical JSON. The comparer requires the same challenge; otherwise it fails before scanning and comparing local files.

## Workflow

1. On the **comparing device**, run `gcsync -new-inventory-challenge`. Keep the returned 64-character lowercase hexadecimal challenge associated with this request. Create a **new challenge for each exchange**; do not reuse an old challenge.
2. Send the challenge to the **exporting device** by your chosen channel. The challenge is **not a password or encryption key**, but protecting it against substitution avoids denial-of-service confusion.
3. On the **exporting device**, run `gcsync -plan-source /private/peer-folder -device-dir /private/peer-identity -inventory-challenge <fresh-64-hex> -export-inventory /private/outside/response.json`. The signed inventory remains plaintext sensitive metadata and is saved as a new private `0600` file outside the scanned folder. The exporter does not overwrite an existing path.
4. Transfer the signed response privately. **Never** transfer the identity's private seed.
5. On the **comparing device**, independently verify and explicitly trust the exporting identity's full Ed25519 public fingerprint using the existing device-trust workflow. Run `gcsync -plan-source /private/local-folder -device-dir /private/local-identity -peer-fingerprint sha256:<trusted-full-fingerprint> -expect-inventory-challenge <same-fresh-64-hex> -compare-inventory /private/response.json` with the same `-exclude` patterns as the export.
6. Read the JSON output. `challengeVerified: true` means the signed response was bound to this supplied request challenge. The result is still a **read-only claim**; it must never be used as permission for automatic copying or deletion.

## Guarantees and limits

- The nonce generator uses the operating system's cryptographically secure random source. Challenges must be exactly 32 random bytes encoded as 64 canonical lowercase hex characters.
- The signed canonical inventory payload includes an optional `challenge` field. The original experimental version-1 inventory without a challenge remains valid **only for comparisons where no challenge is expected**. If a challenged export is compared without `-expect-inventory-challenge`, it fails closed rather than silently discarding request binding. A legacy unchallenged inventory cannot satisfy a challenged request.
- Signature verification uses the previously trusted peer public key. Challenge matching is checked before reading the local folder and uses a constant-time comparison on the canonical encoded value.
- This **does not** stop replay of the *same response to the same challenge*, and no persistent one-time-use registry is stored. It requires a newly generated challenge per exchange. It does not provide a trusted wall clock, confidentiality, a complete directory snapshot, honest contents from a compromised signer, denial-of-service resistance or cross-device network synchronization.
- Other-party inventory names, hashes, sizes, excludes, capture timestamp and the public challenge remain visible in the signed JSON. Exchange only through an appropriate confidential transport and protect the identity's private directory.
- These features have only been tested locally on synthetic folders and with loopback integration; no physical-device, hosted CI or release acceptance is claimed.

## Optional durable one-use variant (subsequent local checkpoint)

The original standalone `-new-inventory-challenge` plus `-expect-inventory-challenge` workflow above remains stateless and replayable when reusing the same nonce. A newer opt-in `-challenge-ticket` workflow requires an existing private ticket directory and explicitly pinned peer. It writes a spent hardlink marker after an authenticated comparison, so the same ticket cannot be consumed twice across ordinary restarts. It is not rollback-proof and does not encrypt the exported metadata. See [ONE_USE_OFFLINE_TICKETS.md](ONE_USE_OFFLINE_TICKETS.md) for the exact CLI workflow and storage limits.
