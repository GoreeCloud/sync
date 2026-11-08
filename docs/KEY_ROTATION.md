# GoreeCloud Sync — Explicit, signed device-key rollover

**Status:** Unreleased local development preview. No existing device identity is rotated automatically. No private keys are uploaded, and no remote trust record is changed by this procedure.

My goal is a recoverable, auditable transition between an existing, independently pinned Ed25519 device identity and a new identity without silently escalating trust or destroying recovery material. The workflow below supplies an independently testable cryptographic continuity proof, **not** automatic PKI enrollment, key recovery, or a revocation broadcast.

## Safety prerequisites

- Preserve a verified, access-controlled backup of the old identity and its trust store *before* deliberately retiring its key; only an authorized owner can decide when to delete an old private key. The tool never deletes private keys during rollover.
- Use a distinct, private **new** identity directory. `init` uses no-overwrite creation, `0700` directory and `0600` seed file; its seed is **not encrypted at rest**.
- Verify every peer's existing **full** pinned fingerprint and the new **full** fingerprint independently, e.g. on a trusted local screen or another independently authenticated channel. The signed proof does not eliminate this requirement, especially if the old private key might be compromised.
- Use a trusted local machine for these commands. Do not put identity folders, private signing seeds, downloaded files, or generated credentials into a public source repository.

## Example, using synthetic test identities

On the identity owner (the device changing its signing key):

```sh
# Current identity was previously created in ./identity-old; create a second one.
./gc-sync -device-dir ./identity-next -device-action init
# Produces public old/new records and two signatures ONLY. No private seed output.
./gc-sync -device-dir ./identity-old -device-action rotation-proof \
  -rotation-dir ./identity-next > rotation-proof.json
```

On a peer that **already trusts the old identity** and has independently checked the new fingerprint:

```sh
# Public-only verification; does not add, delete, or overwrite any trust record.
./gc-sync -device-dir ./peer-identity -device-action rotation-verify \
  -rotation-proof ./rotation-proof.json \
  -peer-fingerprint 'sha256:OLD_FULL_64_HEX_DIGITS'

# Explicitly stage the replacement as an *additional* trust pin.
./gc-sync -device-dir ./peer-identity -device-action rotation-trust \
  -rotation-proof ./rotation-proof.json \
  -peer-fingerprint 'sha256:OLD_FULL_64_HEX_DIGITS' \
  -new-fingerprint 'sha256:NEW_INDEPENDENTLY_VERIFIED_FULL_64_HEX_DIGITS'

./gc-sync -device-dir ./peer-identity -device-action list
# Only when the owner has deliberately completed rollover and checked active
# sessions, manually retire the *old peer trust record*:
./gc-sync -device-dir ./peer-identity -device-action untrust \
  -peer-fingerprint 'sha256:OLD_FULL_64_HEX_DIGITS'
```

**Important:** After preparing the proof, the identity owner must deliberately configure future Nearby Send sessions with `-device-dir ./identity-next`. The old identity is not overwritten or selected automatically. Peer-side `rotation-trust` leaves both old and new fingerprints pinned until `untrust` is explicitly invoked; an already running receiver keeps the key it loaded at startup. A full rollover requires manually updating each participating device's trusted pins, testing the replacement identity with a new one-time session, and separately retiring older material when appropriate.

## Proof format and verification

A version-1 `RotationProof` contains only `version`, canonical `old` and `new` Ed25519 public records, and two base64url signatures. Both signatures cover `"GoreeCloud Sync device rotation v1\\0" || 32-byte-old-public-key || 32-byte-new-public-key` (domain-separation text has an actual zero byte), making the old and new signers authorize the exact same ordered transition. Verification requires a previously trusted **old** public key from the local trust directory, exact canonical fingerprints, two valid signatures, two distinct public keys, and the fixed version. The proof is not self-authenticating: an attacker-provided old key in an untrusted JSON document is never accepted as a trust anchor.

The input reader enforces a 4 KiB limit, regular-file / no-symlink requirement, strict known fields, and no trailing JSON. An independently verified new fingerprint is still needed to stage a new pin. Pin creation uses a private staged file and no-overwrite hardlink; if the destination filesystem lacks same-directory hardlinks, it fails closed rather than overwriting.

## Recovery and remaining limitations

- Loss of the old identity **before** generating the proof prevents cryptographic continuity signing. Recovery requires separately verifying a new identity and explicitly trusting it via the existing manual trust process; there is no key escrow.
- Compromise of the old signing seed can forge the old signature. The independent new fingerprint check is necessary to defend against arbitrary silent reassignment. A signed continuity statement does not establish that the old key remains uncompromised.
- A device that trusts the old fingerprint is unaffected until its local trust store is explicitly updated. No gossip, cloud registry, central revocation, historical acceptance ledger, automatic update, automatic key activation, transport TLS or cross-device synchronization is provided.
- `untrust` only removes a local peer pin. It does not delete the peer's private key, invalidate existing one-time transfer keys, cancel an active transfer, or alert other devices. The identity owner controls private seed retention separately.
- The implementation is locally tested using generated test identities. No real-device key rotation, hardware keystore, backup recovery or native app acceptance has been performed.

## Validation

`go test -race ./internal/deviceid` and `bash tests/rotation-cli.sh` cover verification, staged trust, old-pin retention and explicit removal, mismatched fingerprints, tampered signatures/metadata, unknown predecessor, same-key replacement, duplicate pins, invalid JSON, oversized files and symlink rejection. They do not establish production readiness or third-party security certification.
