# GoreeCloud Sync — Nearby Send (single-use encrypted CLI preview)

**Status: a manually started encrypted transfer preview, with optional pinned receiver identity verification.** I intend Nearby Send to offer secure transfers between trusted devices without mandatory cloud storage. My present implementation is a deliberately limited **one-file-per-receiver-process** transfer that uses an out-of-band, high-entropy pairing key. An optional separately maintained Ed25519 receiver pin is now supported, but it is not mutually authenticated automatic device pairing, a LocalSend-compatible protocol, automated discovery, or a public service.

## Start a receiver

Install Go 1.23+ and build the application. On the receiving machine:

```sh
go build -o goreecloud-sync ./cmd/sync
mkdir -m 700 "$HOME/GoreeCloud-Received"
# Loopback-only is the default, suitable for testing on one computer:
./goreecloud-sync -receive-dir "$HOME/GoreeCloud-Received"
```

The receiver waits at most **five minutes** by default and exits after that timeout if no valid transfer arrives. Use `-receive-timeout 10m` to change this within the allowed `1s`–`30m` range. A failed authentication does not count as a successful transfer. The receiver prints an initial JSON line containing its `listen` URL and a **fresh, 256-bit `pairingKey`**. The receiver does not proceed until a sender supplies that secret; it prints a second JSON line with the final receipt when successful and then exits. The receiving directory must already be private (`0700` on Unix) if it exists. New files are created privately (`0600`) and **never replace existing names**.

To accept a transfer from another device on the *same trusted, private LAN*, explicitly select the listening interface and opt into network exposure:

```sh
./goreecloud-sync -receive-dir "$HOME/GoreeCloud-Received" \
  -receive-listen 192.168.1.20:8788 -allow-lan -receive-tls
```

Replace `192.168.1.20` with the receiver's actual private LAN IP. Never forward this port to the internet, run it through a public reverse proxy, or use a guest/untrusted Wi-Fi network. A wildcard bind (`0.0.0.0`) is rejected entirely. A literal private interface with `-allow-lan` **requires** `-receive-tls`, using a one-time-key-pinned TLS 1.3 certificate. All transfers were validated locally via **loopback only**; remote-device network behavior remains unverified.

## Send one file

The sender must receive the `pairingKey` through a private, trusted **out-of-band** channel. The sender uses the receiver's LAN IP/port and `/send` path. To avoid putting the key in shell arguments, process listings, the URL, or HTTP headers, enter it on standard input. This is an example of an interactive shell session:

```sh
./goreecloud-sync -send-file ./example.txt \
  -send-url https://192.168.1.20:8788/send
# Paste the receiver's 43-character pairing key, then press Enter.
```

The key should not be put in a committed file, shell history, logs, or a screenshot. The sender reads exactly one key line from standard input and only accepts literal loopback/private/link-local IP destination URLs with an explicit port and `/send`. Hostnames, URL credentials, queries, fragments, public IPs, redirects and HTTP proxies are disabled. Non-loopback send URLs require **HTTPS with a server public key derived from the one-time pairing secret**; HTTP is accepted only on loopback. The sender returns JSON only after verifying a keyed receipt from the receiver. The plaintext HTTP response contains only a success status and authentication tag; it does **not** echo the decrypted filename.

## Security and protocol boundaries

- The receiver generates a new 32-byte random secret per invocation; the secret is **not transmitted with the request**. A derived encryption key protects both filename and bytes with AES-256-GCM and a fresh 96-bit random nonce. Independent derived HMAC-SHA-256 keys authenticate the ciphertext request and the receiver's acknowledgment.
- The encrypted envelope is `GCSL1 || nonce || AES-GCM(ciphertext_and_tag)`; encrypted plaintext encodes a 2-byte filename length, filename, and file bytes. The receiver checks the MAC **before decryption**. Failed authentication, malformed frames, unacceptable filenames, and existing destinations are rejected. Each receiver session accepts at most one successful file.
- Each file must be at most **20 MiB**; the transfer is buffered in memory (not streamed or resumable). No folders, batch transfers, clipboard, discovery, trust-on-first-use, device identity sync, key rotation, offline queue, or fully automated persistent pairing are implemented.
- Transport for non-loopback LAN is now **TLS 1.3 pinned to the fresh out-of-band pairing key**. Loopback HTTP remains available for compatibility. TLS protects request/response metadata but not endpoint IPs/ports, transfer size or timing; compromise of the pairing key compromises this transport identity. This is a single-use, out-of-band-secret transfer, not a fully audited mutual identity/transport-security solution. A malicious network intermediary can block or delay transfers, including by occupying the sole receiver slot, but cannot forge a valid success receipt without the key (under the stated cryptographic assumptions). There is no per-peer rate limit.
- A secret shared through an untrusted channel, a compromised endpoint, a malicious same-user process or a hostile LAN defeats important protections. Key exposure before completion compromises confidentiality. The 43-character key appears in the receiver's **initial stdout JSON** by design, so prevent terminal capture/logging where sensitive; test only with non-sensitive files.
- Received bytes use a private temporary staging file, `fsync`, and a hardlink-based atomic **no-overwrite** commit. This requires hardlink support on the receiver's filesystem and still does not prevent a malicious local process from racing directory paths. A rare `fsync` failure after the link is created can leave a file that the sender treats as unsuccessful; inspect the receiver directory before retrying.
- A single malicious peer can consume receiver resources; bind only on an explicitly trusted private interface and stop the receiver if not in use. **Do not expose Nearby Send publicly**. The LAN listener has not been security-audited, penetration-tested or accepted on real Android/Linux devices.

## Repeatable local verification

```sh
go test -race ./internal/lansend -count=3
bash tests/lan-send-cli.sh
```

`tests/lan-send-cli.sh` starts a **loopback-only** receiver in a fresh temporary directory, sends one file, checks both authenticated receipts, verifies byte-for-byte persistence, observes the receiver exiting, and checks that non-loopback listening is rejected without opt-in. Unit tests cover ciphertext confidentiality/tampering, independent request/receipt authentication, wrong-key rejection, one-time use, no overwrite, unsafe filenames, URL restrictions, and private-directory validation.

## Next acceptance steps

Build a true peer identity system (with authentication of both devices), explicit recipient approval, physical testing and third-party review of the new experimental key-pinned TLS 1.3 transport, pairing and revocation UX, streaming/chunked transfer with interruption recovery, protocol interoperability tests and replay/DoS protections before broadening network use. Connect native Linux and Android applications to these trusted pairing and transfer flows. Nothing here establishes a Stable or production release.

## Optional verified receiver identity

The manual receiver may load a previously initialized Ed25519 device identity with `-device-dir`. The sender may require the signed proof for a previously trusted receiver by providing both `-device-dir` and its full `-peer-fingerprint`. The receiver answers a fresh challenge, signing the challenge and a hash of the **current one-time transfer key**. If the pinned identity is different, absent, or signs a different transfer key, the sender refuses to upload. By default the receiver checks only the one-time key; optional `-require-sender-fingerprint` additionally requires its pinned sender identity with a domain-separated signature over the precise upload. The sender must explicitly opt into `-mutual-auth`, which refuses a one-way receiver. Neither mode is TLS or automatic pairing. See [DEVICE_IDENTITY.md](DEVICE_IDENTITY.md) for step-by-step setup, fingerprint ceremony, trust removal, threat model and tested scope.

## Session-key-pinned TLS (local preview)

Run the receiver with `-receive-tls` to announce an `https://` URL. Non-loopback receivers require `-allow-lan` **and** `-receive-tls`; plaintext HTTP is allowed only on literal loopback addresses. The sender pins the receiver's ephemeral TLS certificate public key derived from the out-of-band one-time secret and refuses arbitrary self-signed certificates. This is separate from pinned persistent device identities. Complete protocol details, failure modes, scope and commands are in [SESSION_TLS.md](SESSION_TLS.md). No actual physical-device or LAN-exposed test has been performed.

## Sender source hardening (November 5, 2026 local checkpoint)

Linux/Android senders now open the full source path through no-follow directory descriptors and refuse symlinks or non-regular files before reading. Other operating systems retain a weaker path preflight. This does not prevent a hostile process from modifying an already-open source file; review [the sender hardening boundary](SENDER_SOURCE_HARDENING.md).

## Crash-staging preflight (November 5, 2026 local checkpoint)

Run `go run ./cmd/sync -audit-receive-dir /path/to/private/inbox` to inspect for leftover reserved `.gcsend-stage-*` plaintext staging entries without reading or deleting their content. The receiver refuses to start when a residue is found; manually review/quarantine artifacts in another private directory before retrying. See [receiver crash recovery](RECEIVER_CRASH_RECOVERY.md). No automatic repair or secure erasure is implemented.
