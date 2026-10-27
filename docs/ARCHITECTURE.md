# GoreeCloud Sync — Native architecture

As the founder of GoreeCloud, I want one application for two distinct workflows: continuous, trusted folder replication and explicitly approved nearby transfers.

## Boundaries

**Continuous Sync:** a local-only Syncthing REST adapter reads status, device identities and folder configuration from a separately installed Syncthing process. This milestone does not yet manage that process, pair peers or modify shared folders.

**Nearby Send:** an original Go implementation of a subset of the LocalSend v2 protocol provides HTTPS prepare/upload, per-transfer consent, random session and file tokens, SHA-256 verification, and a multicast discovery scan. A sender verifies the TLS certificate SHA-256 fingerprint and requires user confirmation. Interoperability is not yet certified.

**Native interface:** Fyne desktop application, not a web wrapper. Its semantic colors are derived from current GoreeCloud UI (GC UI) light/dark and Iris references. Native Android, Windows and macOS acceptance remains separate work.

Cross-engine identity correlation must not silently equate a Syncthing device ID with a LocalSend fingerprint. Sync and one-shot transfer directories remain independent until authorized sharing is configured.

## Safety invariants

Inbound receiving is disabled until an inbox is selected. Every transfer requires explicit approval. Existing files are never replaced; completed files receive a new randomized suffix. Partial transfer files are removed. Syncthing API requests cannot target remote hosts. Credentials are not persisted by this UI. LocalSend private certificates belong only in user-private configuration directories.

## Acceptance

Before release: validate genuine LocalSend interoperability, Syncthing lifecycle, UI focus and accessibility, native installations and uninstallation, process/service recovery, network changes, package signing, notices and platform-specific permission behavior. A source compile is not runtime certification.
