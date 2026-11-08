# GoreeCloud Sync — Explicit Device Identity and Receiver Verification

**Status:** Unreleased local development preview. This is an explicit per-transfer identity proof foundation, **not** unattended pairing, a mesh trust protocol, or production-ready endpoint security.

## Purpose and current scope

I intend GoreeCloud Sync to make consent and verification understandable before devices exchange data. This prototype adds durable Ed25519 identities and manually maintained pinned public keys for both parties to the existing one-time Nearby Send CLI. No credentials, machines, contact lists, or identity records are imported from GoreeCloud Identity yet.

The implementation currently provides:

- A randomly generated Ed25519 private identity for each manually initialized device. The seed is stored in `identity.json` in a private (`0700`) directory and a private (`0600`) file. Creation is **no-overwrite** and fails when the identity already exists; the private seed is never shown by `-device-action init` or `show`.
- A complete `sha256:<64-hex-digit>` fingerprint of the Ed25519 public key, a base64url public-key representation, and explicit manual peer trust using both values. **The fingerprint must be independently confirmed through a trustworthy channel**; passing two values copied from the same untrusted message authenticates nothing.
- Private, no-overwrite trust records under `trusted/`. Each record is revalidated against its expected filename and public-key fingerprint when loaded. `untrust` explicitly deletes a pin, preventing later pinned transfers using that record.
- An optional `GET /identity?challenge=<random-base64url-nonce>` endpoint on a manually started Nearby Send receiver. The receiver signs a domain-separated transcript containing the sender's fresh 256-bit challenge and SHA-256 of that receiver session's one-time 256-bit transfer key. The key itself and the private signing seed are **never returned** by this endpoint.
- An optional `-device-dir` + `-peer-fingerprint` sender mode. It loads a previously pinned receiver public key and validates the signed challenge **before** sending encrypted file content. Failure refuses the transfer; **no silent fallback** to unpinned Send is allowed.

The existing one-time secret, AES-256-GCM encrypted filename and contents, HMAC request authentication, authenticated receipt, 20 MiB limit, private destination and no-overwrite policy still apply. An identity pin **does not replace** the one-time transfer key.

## Manual local workflow

In a test environment, the receiver initializes its private identity once:

```sh
./gc-sync -device-dir ./receiver-identity -device-action init
./gc-sync -device-dir ./receiver-identity -device-action show
```

The sender separately initializes its own private identity and trust store:

```sh
./gc-sync -device-dir ./sender-identity -device-action init
```

The sender obtains the **receiver public key** (the `publicKey` field in `show`), but also checks the receiver's **full fingerprint** with the device owner over an independent trusted channel. The placeholders below are the public receiver key and the separately verified full fingerprint:

```sh
./gc-sync -device-dir ./sender-identity -device-action trust \
  -trust-public 'RECEIVER_BASE64URL_PUBLIC_KEY' \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'
./gc-sync -device-dir ./sender-identity -device-action list
```

The receiver manually starts an identity-enabled one-time listener (defaults to loopback):

```sh
mkdir -m 700 ./test-received
./gc-sync -receive-dir ./test-received -device-dir ./receiver-identity
```

Its local announcement contains `listen`, `pairingKey`, and `deviceFingerprint`. The pairing key is a **new secret for this one-time receiver process**; exchange it through an appropriate private channel. On the sender, use the actual receiver IP URL and the fingerprint of the previously trusted receiver. **Enter only the pairing key via stdin**, rather than a command-line argument:

```sh
./gc-sync -send-file ./example.txt \
  -send-url http://127.0.0.1:8788/send \
  -device-dir ./sender-identity \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'
```

A receiver may listen on a **specific private LAN IP** only with an explicit `-receive-listen PRIVATE_IP:8788 -allow-lan` option. This path was tested only over loopback in the local development environment, **not** on two physical devices or public networks. The one-time receiver still exits after one successful transfer or five minutes by default (max 30 minutes).

To explicitly remove an earlier pin, without modifying the receiver's key or any already shared file:

```sh
./gc-sync -device-dir ./sender-identity -device-action untrust \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS'
```

There is no automatic trust-on-first-use, no implicit enrollment, no passwordless identity-based transfer without the one-time secret, no trust synchronization, and no trust record overwrite. An existing or revoked pin must be reverified manually before it can be trusted again.

## Explicit mutual identity verification (experimental)

For an additional opt-in receiver-side identity check, I require both participants to **manually exchange and independently verify their complete public-key fingerprints in both directions**. Trusting only the receiver is insufficient. In addition to the sender's existing trust of the receiver, the receiving device must pin the sending device:

```sh
# On the receiving device, using the sender's independently verified public key:
./gc-sync -device-dir ./receiver-identity -device-action trust \
  -trust-public 'SENDER_BASE64URL_PUBLIC_KEY' \
  -peer-fingerprint 'sha256:SENDER_FULL_64_HEX_DIGITS'

# Receiver: require this sender identity for the next one-file transfer.
./gc-sync -receive-dir ./test-received -device-dir ./receiver-identity \
  -require-sender-fingerprint 'sha256:SENDER_FULL_64_HEX_DIGITS'

# Sender: require receiver identity proof AND mutual sender authentication.
# Enter the fresh one-time pairing key from receiver via stdin as before.
./gc-sync -send-file ./example.txt -send-url http://127.0.0.1:8788/send \
  -device-dir ./sender-identity \
  -peer-fingerprint 'sha256:RECEIVER_FULL_64_HEX_DIGITS' -mutual-auth
```

The receiver returns a short-lived-in-process, MAC-protected random `senderTicket` only when it enforces a trusted sender. The sending identity signs a domain-separated transcript covering that ticket, a hash of the one-time pairing key, and the **MAC of the exact encrypted upload**. The receiver validates the ticket and signature against the stored trusted sender public key *before decrypting or saving the file*. The receiver's own proof is checked by the sender first. A mismatch, missing trust, incorrect signature, unsupported receiver policy, or one-sided attempt to downgrade mutual verification fails closed.

The mode is still **not mutual TLS, a signed trusted channel, or an automatic trusted-device pairing protocol**. The peer-identity proofs are at the application layer and cannot prevent an on-path relay of HTTP, force network availability, hide metadata, or replace the manually shared one-time encryption key. The receiver's trust policy is loaded at startup; removing a trust record while the receiver process runs does not revoke that running process. Device certificate lifetimes, key rotation, trust replication, pre-authorization UI, real LAN device testing and GoreeCloud Identity integration remain future work.

## Security model and outstanding work

1. **Local private-key security:** The Ed25519 seed is stored unencrypted within a `0600` JSON file. The process must run as a trusted user on a trusted computer. File permissions do not provide defense against a compromised OS, malware running as the same user, backups, physical access, or theft of an unlocked disk. Hardware-backed keys, optional encrypted key storage, secure rotation and recovery have not been implemented.
2. **Trust ceremony:** The fingerprint must be verified independently. Displaying a fingerprint from the same attacker-controlled channel as the public key does not resist an active man-in-the-middle attacker. The application cannot verify that the human performed this step.
3. **Proof scope:** A pinned receiver signature binds its identity to a fresh sender challenge and the one-time pairing key. In explicit mutual mode, the receiver also requires a pinned sender signature bound to its own nonce/ticket and the exact upload MAC. Neither mode creates a cryptographically secure HTTP transport, prevents network relays, or conceals metadata; an on-path adversary can interrupt traffic.
4. **Trust modes:** By default Nearby Send checks only the shared one-time secret. Receiver-only mode additionally verifies its pinned Ed25519 identity. Explicit mutual mode additionally enforces the pinned sender identity for an individual upload. There is still no centralized device registry, automatic pairing, or durable authorization policy engine.
5. **Explicit revocation:** `untrust` removes a local sender pin for future sessions. It does not revoke the receiver's private key, a pairing key already shared, a transfer already in progress, or trust records on other devices. Key rotation and revocation propagation are separate work.
6. **Network exposure:** No public endpoints, public reverse proxy, internet federation or VPS deployment are supported. Even with pinned identity, only use manually approved test devices and a trusted private LAN. Network-level service hardening, backpressure, transport confidentiality, DoS resistance and cross-device acceptance remain open.
7. **Storage robustness:** Identity and trust records are written by same-directory private temp-file staging, hardlink no-overwrite commit, and directory sync. This requires a filesystem supporting hardlinks. Unexpected local ownership, symlinks or permissive modes are rejected; there is no adversarial concurrent-path/same-user protection, multi-user ACL model, backup, migration, or schema upgrade.

## Verification

Relevant tests are in `internal/deviceid/identity_test.go`, `internal/lansend/transfer_test.go`, `tests/device-identity-cli.sh`, and `tests/mutual-identity-cli.sh`. The CLI suite starts only loopback listeners. It covers no-overwrite key creation, file modes, explicit fingerprint matching, corrupted trust records, fresh proof verification, wrong-identity and wrong-key refusal, unpaired downgrade refusal, actual encrypted loopback transfer, and untrust. These tests do **not** validate real devices, Android/Linux packaging, production deployment, hardware key security, or independently witnessed out-of-band fingerprint exchange.

## Public signed rotation proofs

An experimental **non-destructive key-rollover** protocol is now locally tested. The owner explicitly initializes a replacement Ed25519 identity in a separate private directory and signs a public rotation proof with *both* the old and new keys. An already-trusting peer may verify this against its local old pin and optionally stage the replacement as a second pin, but must also independently verify the full new fingerprint. The original private key and old trust pin remain unchanged; later retirement is a separate manual operation. No key rotation or revocation propagates to other devices. Full commands, threat boundaries and recovery notes are documented in [KEY_ROTATION.md](KEY_ROTATION.md).
