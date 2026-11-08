# Nearby Send — receiver crash-stage inspection (unpublished local preview)

**Status:** November 5, 2026 local development checkpoint. No hosted CI or real-device acceptance.

Nearby Send decrypts a single file into a private `0600` staging entry before its no-overwrite publication. If the process or device crashes, a reserved `.gcsend-stage-*` file can remain and **may contain partial or complete plaintext**. It is not a valid completed receipt and must never be propagated automatically.

## Read-only inspection and manual recovery

```sh
# Does not create directories, open listeners, read file content, or delete anything.
go run ./cmd/sync -audit-receive-dir /path/to/private/inbox
```

The command accepts an existing real private (`0700`) receiver folder and outputs one JSON report with `status`, `stageResidueCount`, `stageResidues` (at most 32 names), and `namesTruncated`. It exits **0** when clear, **2** when manual review is required, and with an error for unsafe or unreadable folders. Even a malformed staging name or a symbolic link with the reserved prefix is treated as suspicious. All non-stage filenames and file bytes are omitted.

The one-shot receiver refuses to start when the audit finds residue, before printing a pairing key or binding any listener. `SaveNew` checks again before writing; on Linux/Android its held directory handle performs another residue check just before allocating the new stage. None of these checks remove a previously staged file or repair incomplete transfers.

If an artifact is reported, **stop all receivers using the folder, inspect the name and metadata, and determine whether recovery is necessary**. Preserve evidence or move an artifact to a separately private quarantine only after owner review. Do not assume a stage file is complete, trusted, or authenticated solely because it exists. Never bulk-delete user folders or weaken directory permissions to bypass the audit. Re-run the read-only audit before starting a new receiver.

## Limits

- A privileged or same-account malicious local process can race with audits or rename opened directories. These scans are not a sandbox, lock, atomic snapshot, or adversarial concurrency guarantee.
- Receiver staging uses `0600` by default and a `0700` private root. Confidential plaintext may nonetheless be recoverable from filesystem snapshots, backups, or an abnormal crash. No secure erase promise is made.
- This does not resume interrupted transfers, verify the staged plaintext, or change the one-time encryption protocol. The inspection is manual and local; cross-device recovery is not implemented.
- No automatic deletion is performed. The ordinary one-shot success path still removes its temporary stage file after creating the final file.

## Tests

Run `go test -race ./internal/lansend` and `bash tests/receiver-residue-cli.sh`. The CLI test exercises a read-only clean audit, fail-closed startup with residue, no announcement/listener, unchanged residue content, invalid mode combinations, manual quarantine, and clean re-audit.
