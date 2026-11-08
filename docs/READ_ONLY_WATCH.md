# Read-only local Sync observation (experimental)

I am developing GoreeCloud Sync to make changing files understandable **before** enabling any automatic replication or deletion. This experimental command is a foreground, read-only **polling** tool. It reports a complete current comparison initially and whenever that comparison materially changes.

## Usage

```sh
# Monitor two distinct, non-overlapping local directories.
go run ./cmd/sync -plan-source ./source -plan-target ./target -watch

# Change the scan interval from its 5s default (minimum 1s, maximum 1h).
go run ./cmd/sync -plan-source ./source -plan-target ./target -watch -watch-interval 10s -exclude '*.tmp'

# Observe change/conflict classes relative to an existing private baseline.
go run ./cmd/sync -plan-source ./source -plan-target ./target -baseline ./baseline.json -watch
```

Stop with `Ctrl+C` or `SIGTERM`. This process **does not continue when stopped**, and it does not run as a system service, daemon, scheduler, or persistent agent. Do not expose this command to a remote caller.

## Output

Each line of standard output is a complete JSON object, suitable for parsing as NDJSON. The first event is `type: "snapshot", sequence: 1`; subsequent events use `type: "changed"` and increment the sequence. `readOnly` is always `true`. `mode` is `two-way` or `three-way`. `observedAt` records the observation time in UTC; `plan` contains the complete, sorted inventory comparison, including file paths and SHA-256 digests. No event is emitted when consecutive scans produce identical results.

The three-way mode supports historical statuses including unilateral modification, deletion, convergence, and conflict. The saved baseline is loaded and pinned at the beginning; a change or disappearance during observation terminates the command rather than silently changing the meaning of reported deletions and conflicts.

## Safety boundaries and limits

- **No writes** to observed files; no copying, overwriting, deletion propagation, conflict resolution, or baseline updates. `-watch` is rejected with `-apply-additions` or `-capture-baseline`.
- Two distinct non-overlapping roots are required. Exclusions are opt-in and are applied equally to source and target. Symlinks and special files in the included scan are rejected, not traversed.
- Every scan hashes complete files. Large folders can consume substantial storage I/O and CPU. The minimum interval is deliberately 1 second; the default is 5 seconds. Do not use on expensive or live production datasets without reviewing resource costs.
- Each scan is sequential across two folders, **not an atomic filesystem snapshot**. Rapid intermediate edits can be missed between polls; changes during a scan may cause it to terminate. Event counts are not a durable change history or exactly-once event stream.
- JSON output includes relative filenames and file digests; treat it as potentially sensitive metadata. Pipe it to a private destination only when appropriate. Output is not encrypted or persisted by GoreeCloud Sync.
- A saved baseline binds to the same canonical local source and target paths, their direction, and exclusions. It is not a cross-device common-history identity.
- The watch exits with an error on invalid state or scan failure; it deliberately does not silently continue with potentially misleading output.

This functionality is a local observation prototype, **not** a Syncthing-compatible continuous replication engine, network transport, native GUI, backup, or Stable release.

## Local verification

`go test -race ./...` and `bash tests/watch-cli.sh` cover detection, historical conflict classes, baseline tamper rejection, cancellation, excluded paths, disabled write modes, and non-overwrite behavior. They do not establish performance limits or production readiness on large datasets.
