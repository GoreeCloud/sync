# GoreeCloud Sync

**Status: native desktop prototype, not a production release.**

As GoreeCloud's founder, I want to combine two complementary privacy-first workflows into a single native application: persistent, trusted folder synchronization and intentional nearby file transfers. I call the result **GoreeCloud Sync**.

The current repository contains an original Go/Fyne desktop interface—not a browser wrapper—and two adapters:

- **Continuous Sync**: a read-only adapter to a separately installed, locally running [Syncthing](https://syncthing.net/) instance. It displays service status, devices and folders using the loopback REST API.
- **Nearby Send**: a subset of the [LocalSend](https://localsend.org/) v2 transfer protocol implemented in Go, including HTTPS sending and opt-in receiving, user approval, certificate fingerprint checks, size/filename checks and streamed file integrity verification.

This is an **integration prototype**, not a literal merger or redistribution of upstream Syncthing and LocalSend code. Syncthing still runs independently; LocalSend discovery/interoperability and the remaining native functionality require more work.

## Building from source

A Go toolchain and native Fyne dependencies are required. On Linux, a C compiler, OpenGL, X11 and Wayland development headers are needed; see the [Fyne setup guide](https://docs.fyne.io/started/).

```sh
go mod download
go test -race ./internal/...
go vet ./...
go run ./cmd/goreecloud-sync
```

In the **Sync** tab, enter the local Syncthing address (default `http://127.0.0.1:8384`) and API key. The app does not persist the key. **Nearby** scans for HTTPS peers and derives their fingerprints from the actual peer TLS certificates; independently verify the displayed fingerprint with the receiving device before proceeding. Discovery alone does not establish identity. To receive, select an inbox and approve individual incoming offers. Don't enable receiving on untrusted networks.

## Architecture and milestones

- [Architecture and implementation boundaries](docs/ARCHITECTURE.md)
- [Engineering milestones and unfinished work](docs/ROADMAP.md)
- [Current security model and unresolved risks](docs/SECURITY.md)
- [Local engine diagnostics](docs/LOCAL_ENGINE_DIAGNOSTICS.md)

As the founder, I require native OS deliverables to be verified separately. No Android APK exists yet. When an Android APK is built for installation, deliver the standalone APK in the authorized Google Drive `GoreeCloud/Artifacts` folder; GitHub Actions ZIPs are not Android installer deliveries.

## Ownership and third-party attribution

The GoreeCloud integration code in this repository is original work. No upstream source trees are copied here. Syncthing and LocalSend retain their independent copyright, licensing, protocol and trademark obligations. Bundling those engines in a future combined distribution requires a documented dependency-by-dependency licensing and notice review. This public repository does not assert a license grant for GoreeCloud-original code; verify the applicable licensing terms before reuse.

**Do not represent source compilation, automated tests or protocol resemblance as complete native runtime certification or LocalSend interoperability.**
