# GoreeCloud Sync — Roadmap

As GoreeCloud's founder, I prioritize real native functionality, reliable private transfers, and maintainable source over a superficial merger of two existing applications.

## M0 — Initial native prototype
- [x] Create the public `GoreeCloud/sync` repository.
- [x] Add original native desktop navigation and a read-only local Syncthing adapter.
- [x] Add HTTPS LocalSend-style sender/receiver, approval, certificate pinning and integrity checks.
- [x] Add initial unit and loopback transfer tests.
- [x] Verify isolated Linux desktop startup liveness under Xvfb (CI smoke test).
- [ ] Verify full desktop launch, keyboard navigation and visual compliance.
- [ ] Verify communication with official LocalSend clients.

## M1 — Nearby transfers
- [x] Read the observed certificate fingerprint from HTTPS registration rather than multicast metadata; out-of-band user verification remains required.
- [x] Provide opt-in native Start/Stop Receiving controls and verify port binding before reporting success.
- [ ] Verify the receiver lifecycle on physical devices and against official LocalSend clients.
- [ ] Complete protocol v2.2 discovery, HTTP registration and fallback.
- [ ] Trusted-device identity store, certificate rotation warnings and user-controlled pairing.
- [ ] Cancel, progress, per-file state, concurrent sessions and bounded resource use.
- [ ] Receiver start/stop, low-space behavior, device permissions and reconnect.
- [ ] Clipboard/text transfer, file sharing and native notifications.

## M2 — Continuous sync
- [x] Provide read-only, aggregate Syncthing engine diagnostics without exposing device IDs or folder paths.
- [ ] Package and manage an appropriately licensed Syncthing core per OS.
- [ ] Native service lifecycle and update strategy.
- [ ] Pair trusted devices, add/share folders, choose receive/send directions.
- [ ] Resolve conflicts, version history, selective folders, bandwidth and metering.
- [ ] Validate offline recovery and multi-device convergence.

## M3 — Native releases
- [ ] Linux, Windows and macOS packages, OS-specific integration and accessibility.
- [ ] Native Android app/service and scoped-storage integration; deliver standalone APK in Google Drive `GoreeCloud/Artifacts`.
- [ ] Evaluate iOS/iPadOS feasibility before declaring support.
- [ ] GC UI refinement, onboarding, localization, security review and signed releases.

Check a task only with the appropriate implementation and verification evidence.
