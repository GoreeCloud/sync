# Confidential offline inventory exchange — experimental local preview

**Status:** implemented and locally testable only. No hosted CI, native client, physical-device acceptance, or public deployment is claimed.

## Purpose and trust boundaries

The existing Ed25519-signed inventory exposes relative filenames, sizes, hashes, exclusions and capture timestamps in plaintext. This optional AES-256-GCM envelope **encrypts the entire signed JSON inventory** using an independently generated random 256-bit symmetric key, so people without the exchange key cannot read that metadata from the exported file. The exporter signs a canonical inventory **in memory**, then encrypts it; no intermediate plaintext inventory is written to disk. A fresh random 96-bit GCM nonce is generated for every export. The authenticated encryption context is purpose-separated by envelope version. The envelope contains only `version`, `algorithm`, `nonce` and `ciphertext`. **New exports use format v2:** after the Ed25519 signature is generated, the JSON is prefixed with an authenticated 32-bit exact byte count and randomly padded to the next **64 KiB** before encryption. This hides *exact* inventory length for nearby-size inventories but still exposes approximate bucket count. Version 1 unpadded encrypted files remain readable with their original distinct authenticated encryption context; writers do not create new v1 files. Version changes to an existing envelope invalidate authentication.

The decrypting device first verifies AES-GCM, then **independently verifies the existing Ed25519 signature** against its previously trusted, fingerprint-verified peer key. If supplied, it also requires the exact signed request challenge. Optional one-use tickets are spent **only after** successful authenticated decryption, trusted signature verification and local read-only comparison. Plaintext imports are **never accepted** when `-inventory-key-file` is specified, and encrypted imports cannot be read as plaintext.

## Example workflow

Run with Go 1.23+ from the source repository. Use private folders outside either scanned tree. The example assumes peer identities have already been created and the comparing device has explicitly trusted the exporter's Ed25519 public key after independent verification of the **full** `sha256:` fingerprint.

```sh
# Comparing device: once per exchange, create a random secret; never prints the key.
mkdir -m 700 /private/offline-keys
gcsync -new-inventory-key /private/offline-keys/exchange.key

# Move exchange.key (0600) to an independent private 0700 folder on the
# exporting device over a separate CONFIDENTIAL, AUTHENTICATED channel.
# Do not send the key beside the encrypted inventory.

# Comparing device: issue an optional durable one-use signed request.
gcsync -new-inventory-challenge -plan-source /private/local-files \
  -device-dir /private/local-id -peer-fingerprint 'sha256:VERIFIED_PEER_FINGERPRINT' \
  -challenge-ticket /private/tickets/request.json

# Exporting device: enter the public challenge from the response JSON.
gcsync -plan-source /private/peer-files -device-dir /private/peer-id \
  -inventory-challenge '64-character-lowercase-hex-request' \
  -inventory-key-file /private/offline-keys/exchange.key \
  -export-inventory /private/outside/encrypted-inventory.json

# Comparing device: decrypt, verify pinned signer and exact request, compare
# locally, and mark request.json.used before returning success.
gcsync -plan-source /private/local-files -device-dir /private/local-id \
  -peer-fingerprint 'sha256:VERIFIED_PEER_FINGERPRINT' \
  -challenge-ticket /private/tickets/request.json \
  -inventory-key-file /private/offline-keys/exchange.key \
  -compare-inventory /private/inbox/encrypted-inventory.json
```

Use matching `-exclude` flags on issuance, export and comparison. You can omit `-challenge-ticket` and use a stateless `-expect-inventory-challenge`, but that offers no durable single-use protection; omission of both challenge modes accepts only a signed, unchallenged inventory. An encrypted envelope never weakens a required challenge. The key-file mode is optional; legacy plaintext signed inventories continue to work **only when no encryption key is selected**.

## Security and recovery notes

- **Key management:** The 64-character lowercase hex encryption key is written with mode `0600` under an existing **real 0700 parent directory**. The key must remain outside the inventoried folder. It is unencrypted on disk and is a shared secret: anyone with the key and a copy of the envelope can decrypt it. The CLI never prints it. The user must deliver the secret using a separately authenticated, confidential mechanism. No automatic key exchange, OS keystore, access revocation or forward secrecy is claimed. Prefer fresh keys per exchange and delete/archive them only under a deliberate retention policy.
- **Authenticity:** A successful GCM decrypt means the symmetric key matches, **not** that the inventory came from a trusted device. The independent pinned Ed25519 verification is mandatory. A compromised trusted peer can sign false inventories.
- **Limits:** Plaintext is bounded by the existing 16 MiB inventory limit; encrypted envelope input is capped at 24 MiB. Nonce is 96-bit random, authenticated tag is 128-bit. Every export uses a new nonce, but there is no cross-process nonce registry; random-nonce collision risk is very small, not mathematically impossible. Files are created without overwrite, private mode `0600`.
- **Exposure:** v2 reveals the number of 64 KiB buckets of encrypted metadata; it does not hide that an inventory was exchanged, large size changes or traffic patterns. Each export generates new random padding; export files of even the same size have different ciphertext. Plaintext may exist temporarily in process memory and in files separately managed by the user. OS swap, backups, crash dumps, same-user malware, compromised keys, and hostile parent-directory modifications are not ruled out.
- **Consistency/freshness:** Encryption does not make the inventory a filesystem-atomic snapshot, trusted timestamp, or truthful claim. A one-use challenge ticket provides only local replay state subject to `.used` retention and rollback limitations. No file transfer, deletion, overwrite, daemon or network listener is performed by these commands.
- **Lost key / interrupted exchange:** Envelopes cannot be decrypted without the exact secret. A wrong key or tampered envelope fails *without consuming* an optional one-use ticket. If the ticket is spent after successful comparison and the result is lost, issue a new challenge and new key rather than attempting to reuse the spent ticket.
- **Licensing:** The local code has no selected public-distribution license; that repository-level decision still requires an explicit founder-approved assessment before publication.

## Verification

Run `go test -race ./internal/syncplan -run 'TestPaddedConfidential|TestLegacyConfidential|TestConfidential|TestInventoryKey' -count=1` and `bash tests/confidential-offline-cli.sh`. They cover canonical padded v2 encrypted envelopes, legacy v1 encrypted reading, authenticated length and version downgrade, privacy of filenames/fingerprints, success with a trusted signer and signed challenge, wrong-key and ciphertext tampering, strict no-downgrade behavior, private key file modes and symlink refusal, one-use ticket consumption and replay rejection. These local tests do not establish independent security certification or physical-device integration.

## Protected local artifact I/O (Linux/Android only)

The key reader now rejects symlinks in any ancestor and key hardlinks; private exports use descriptor-anchored staging and no-overwrite commit. A crash may leave private staged key material. The Windows/macOS fallback is weaker. See [PROTECTED_OFFLINE_ARTIFACT_IO.md](PROTECTED_OFFLINE_ARTIFACT_IO.md).
