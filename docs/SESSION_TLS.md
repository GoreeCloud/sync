# GoreeCloud Sync — Session-pinned TLS for Nearby Send

**Maturity: local-only, loopback-tested security development preview. Not deployed and not independently audited.**

I require out-of-band 256-bit secrets for every temporary Nearby Send session. In this preview, I also use that exact fresh secret to authenticate a TLS 1.3 connection, without a public certificate authority, trust-on-first-use certificate, persistent online service, or extra network-accessible setup endpoint.

## Operation

After compiling `go build -o goreecloud-sync ./cmd/sync`, start a receiver on localhost:

```sh
mkdir -m 700 ./received
./goreecloud-sync -receive-dir ./received -receive-listen 127.0.0.1:8788 -receive-tls
```

The receiver announces a `https://127.0.0.1:8788/send` address and its freshly generated `pairingKey`. Share the 43-character key only through a separately authenticated, confidential channel, not a GitHub issue, browser URL, shell argument, shared terminal recording, or insecure messenger. On the sender:

```sh
./goreecloud-sync -send-file ./example.txt -send-url https://127.0.0.1:8788/send
# Enter the key on stdin, then press Enter.
```

For a real, trusted private network, **not yet physically tested**:

```sh
./goreecloud-sync -receive-dir ./received \
  -receive-listen 192.168.1.20:8788 -allow-lan -receive-tls
# Sender uses the announced https://192.168.1.20:8788/send URL.
```

A literal private/link-local interface must be selected. Public and wildcard bindings are rejected, and non-loopback receivers cannot start without TLS. The sender rejects plaintext HTTP URLs outside loopback. For compatibility with old local testing, a manually started loopback-only receiver may still use HTTP; supply `-receive-tls` to enable local HTTPS as well. Neither Share's browser UI nor its localhost-only server mode is changed by this flag.

## What TLS authenticates

- The receiver generates a new cryptographically random pairing secret for each one-time process. A **purpose-separated derived 32-byte Ed25519 seed** creates an ephemeral, in-memory server certificate signing key. It is unrelated to the device's separately pinned persistent Ed25519 identity.
- The TLS certificate is self-signed, valid for a short one-hour interval, and lists the exact bound interface IP as its subject alternative name. Its serial number is random. The receiver uses TLS 1.3.
- The sender derives the *expected* ephemeral public key from the pairing secret entered via stdin and validates the server's certificate key, IP address, validity interval, signature, and negotiated TLS 1.3 protocol. Public CA/TOFU validation is deliberately replaced with **strict application-specific key pinning**; the client never accepts an arbitrary self-signed certificate.
- This protects application-layer HTTP request/response details, including the existing encrypted envelope's headers, from an ordinary passive network observer, and rejects a receiver who does not possess the one-time key. It does **not** conceal source/destination IP, connection size, timing, or other transport metadata. AES-256-GCM file and filename encryption, HMAC request and receipt authentication, pinned persistent-device proof, and optional mutual identity verification continue to operate *inside* TLS.

## Threats and limitations

The pairing key is a **bearer secret** that must be exchanged securely; a person obtaining it can derive the temporary TLS private key and potentially impersonate that session. The sender cannot infer the intended human or device solely from possession of the key; use independently verified persistent device pins and `-mutual-auth` where applicable. The receiver process only handles one file and times out. No certificate is written to disk, and this is not public WebPKI/mTLS. No external certificate validation, platform hardware keystore, PAKE, forward secrecy after endpoint compromise, relay resistance, resumable stream, or active network penetration test is claimed. TLS does not remove same-host malware risks, malicious device key stores, or denial-of-service. No physical two-device LAN acceptance has yet been performed.

## Validation

```sh
go test -race ./internal/lansend
bash tests/secure-lan-cli.sh
```

Unit tests cover a pinned HTTPS round-trip, unrelated certificate rejection before uploading, incorrect pairing key rejection, incorrect certificate interface IP, non-loopback HTTP refusal, wildcard listener refusal, and the existing one-shot transfer properties. The CLI test exercises manual pinned **mutual** Ed25519 device identity over ephemeral pinned TLS, including wrong-key and policy-downgrade failures. All integration tests presently run on loopback. This feature does not justify an internet-facing launch or Stable release.
