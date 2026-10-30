# GoreeCloud Sync — Security design

As the founder, I require privacy-first defaults and verifiable security claims.

Current controls: Syncthing API is restricted to localhost/loopback with an API key and no redirects. LocalSend send requires a local-network IP and HTTPS certificate pinning. An inbound offer is denied unless the user selects a destination and approves the transfer. Uploads use unique per-session tokens, explicit size/filename bounds (including portable filename restrictions), an integrity digest, private temporary files and exclusive destination creation without overwrite.

The LocalSend discovery advertisement is unauthenticated. GoreeCloud Sync now obtains a peer fingerprint from the observed HTTPS registration certificate rather than treating multicast metadata as a certificate pin. This initial HTTPS observation **does not authenticate the peer**: users must independently verify the receiving device's SHA-256 fingerprint before sending. TLS private material is stored in the user's private configuration path, and API keys are never written to preferences. This prototype includes no cloud relay or telemetry.

The native UI now offers Start/Stop Receiving controls and verifies listener binding before declaring startup. However, graceful shutdown does not yet guarantee interruption of every active upload. Receiver session IDs are bearer credentials; cancellation is not yet bound to the sending peer's transport IP. Full active-upload caps, quotas, resource-exhaustion safeguards, persistent trust, and independently verified interoperability remain incomplete.

Before a release, complete rate limits, resource quotas, disk-space checks, restart-safe cancellation, network lifecycle, malicious metadata and file tests, certificate rollover UX, trusted peer persistence, and independent platform integration verification. Do not describe this prototype as production-ready or fully interoperable.
