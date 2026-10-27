# GoreeCloud Sync

Native privacy-first desktop prototype combining Syncthing continuous folder synchronization and LocalSend-style direct transfers under one app.

This is a development prototype, not a tested release. Syncthing must currently run separately. The LocalSend implementation is partial and does not yet have complete interoperability.

## Development

`go test ./internal/...`

`go run ./cmd/goreecloud-sync`

See docs for the architecture, release gates and roadmap.
