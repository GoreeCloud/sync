# GoreeCloud Sync — Local Engine Diagnostics

As GoreeCloud's founder, I require health inspection without exposing personal sync metadata.

## Current implementation

The native desktop project connects only to a separately running local Syncthing REST API. The optional `goreecloud-sync-check` command reads status, device and folder lists; it does not modify configuration or start Syncthing. Its JSON output contains only online status, uptime, device/folder counts and paused counts.

The API key is required and is not included in output. The REST URL must resolve to loopback (`127.0.0.1`, `::1` or localhost); redirects are disabled.

## Development usage

Set `GCSYNC_API_URL` to the loopback Syncthing REST endpoint and provide `GCSYNC_API_KEY` through a secure local environment. Then run `go run ./cmd/goreecloud-sync-check`. The default URL is `http://127.0.0.1:8384`. The command will report an error if the engine is unavailable or credentials are missing.

Environment variables can be visible to privileged users or process inspection tools. Do not put API keys in source files, committed scripts, shared terminal transcripts or logs.

## Acceptance boundaries

This is a read-only diagnostic, not a bundled daemon, active service manager, pairing tool or verified production monitor. Engine lifecycle, device trust management, folder configuration, notifications, native packaging and representative device testing remain outstanding.
