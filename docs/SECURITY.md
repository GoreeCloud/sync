# GoreeCloud Sync — Security design

As the founder, I require privacy-first defaults and verifiable security claims.

Current controls: Syncthing API is restricted to localhost/loopback with an API key and no redirects. LocalSend send requires a local-network IP and HTTPS certificate pinning. An inbound offer is denied unless the user selects a destination and approves the transfer. Uploads use unique per-session tokens, explicit size/filename bounds, an integrity digest, private temporary files and exclusive destination creation without overwrite.

The LocalSend discovery advertisement is unauthenticated and **does not authenticate the sender**. Users must independently verify the receiving device's SHA-256 fingerprint. TLS private material is stored in the user's private configuration path, and API keys are never written to preferences. This prototype includes no cloud relay or telemetry.

Before a release, complete rate limits, resource quotas, disk-space checks, restart-safe cancellation, network lifecycle, malicious metadata and file tests, certificate rollover UX, trusted peer persistence, and independent platform integration verification. Do not describe this prototype as production-ready or fully interoperable.
