# GoreeCloud Sync — local receiver storage security checkpoint

**Date:** November 5, 2026. **Maturity:** experimental source-only preview. **GitHub:** not published; hosted CI and physical-device acceptance are not claimed.

## Change summary

Nearby Send's Linux/Android receiver has been upgraded from pathname-dependent `CreateTemp`/`Link` to a descriptor-pinned private destination. Received plaintext is staged as mode `0600` under the opened private directory using `openat(O_NOFOLLOW | O_EXCL)` and published with atomic no-overwrite `linkat`. Destination root device/inode and permission are checked immediately before and after publication. Existing final files are never replaced, and stage cleanup is descriptor-relative even if a pathname was substituted.

On other OSes the existing guarded path-based fallback remains; the preview does not assert parity. A malicious same-account process may move an opened directory between identity checks. If an error occurs after a successful hardlink, the file can remain present; the error and user review must not be treated as a rollback. An abrupt process crash may leave `.gcsend-stage-*` residue requiring manual review. No automatic cleanup or destructive recovery was added.

## Test requirements and verification boundaries

Run the new targeted `TestReceiverStage*` and `TestReceiverRejectsUnsafeDirAndCleansStage` cases, race tests across all four Go packages, `go vet`, Go formatting/build checks, existing Nearby Send/TLS/mutual identity CLI acceptance, and local encryption/Sync regressions. Linux/Android ARM64 **cross-compilation** is not proof of physical platform behavior or release readiness. No public-facing service, production deployment, or native Android APK is included.

The original founder-provided complete 33-section specification at `docs/PRODUCT_SPEC.md` must remain byte-for-byte unchanged. This checkpoint does not implement full conflict-aware network Sync, streaming/resumable file transport, cross-device discovery, trusted client provisioning, or a Stable release.

The review-only GitHub workflow now verifies the source-wide SHA-256 manifest before compiling. That manifest detects unrecorded file changes but is included with the same source tree and is **not** a publisher signature or independent supply-chain guarantee. It must be regenerated as part of each reviewed source change.
