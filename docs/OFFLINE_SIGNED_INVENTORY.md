# Signed offline folder comparison — experimental local preview

## Purpose and threat boundary

This CLI-only feature lets two devices exchange a **read-only claim** about files without starting a listener or performing replication. It is a stepping stone toward future authenticated peer synchronization, **not** a network protocol, versioned backup or auto-copy plan.

The exported JSON includes experimental version 1 and may optionally include a fresh challenge for request binding (see [fresh-challenge workflow](OFFLINE_INVENTORY_CHALLENGE.md)); it includes a full SHA-256 Ed25519 public-key fingerprint, a self-reported UTC capture time, canonical exclusions, and sorted `{path, size, sha256}` entries. It contains no file payloads, private seed or absolute root pathname. **The filenames, sizes, hashes, exclusions and capture time are plaintext sensitive metadata.** Handle and transport the JSON confidentially.

## Manual workflow

1. On each device, create a `0700` identity directory and run `-device-action init -device-dir /private/identity` once. Protect `identity.json` (private unencrypted seed, mode `0600`).
2. Obtain the exporting device's **public** Ed25519 key and independently verify its complete `sha256:` fingerprint via a trusted channel. On the comparing device, explicitly pin it using `-device-action trust -device-dir /private/local-identity -trust-public <base64url-key> -peer-fingerprint <verified-full-sha256-fingerprint>`.
3. On the exporting device, run `-plan-source /path/to/files -device-dir /private/peer-identity -export-inventory /private/outside/files.json` (optionally repeat `-exclude '*.tmp'`, etc.). The output must be outside the scanned tree; a new private `0600` file is created without overwrite.
4. Send **only the signed JSON** to the comparing device through a channel appropriate for its sensitivity. Never send your local identity seed or its private directory.
5. On the comparing device, run `-plan-source /path/to/local-files -device-dir /private/local-identity -peer-fingerprint <verified-full-sha256-fingerprint> -compare-inventory /private/files.json`, repeating the **exact same exclusions**.
6. Review the JSON report. `source-only` = local-only; `target-only` = signed peer snapshot-only; `different` = divergent claimed hashes. No write or network action is taken. Changes to the peer folder after export are **not** reflected.

## Recommended request-bound exchange

For a new exchange, prefer `-new-inventory-challenge`, then pass the generated challenge to the exporter with `-inventory-challenge`, and require it on the comparing device using `-expect-inventory-challenge`. A matching challenge is signed with the inventory; responses for other requests and legacy responses are refused. Generate a **fresh** challenge for every exchange. Detailed examples and limitations: [OFFLINE_INVENTORY_CHALLENGE.md](OFFLINE_INVENTORY_CHALLENGE.md).

## What is verified

- The peer key is loaded from the existing **explicit local trust store**, not from the untrusted inventory. Ed25519 signature is verified over canonical inventory JSON with a distinct domain label and SHA-256 digest.
- Input is bounded to 16 MiB and 100,000 files, must be a regular file, and is rejected for trailing JSON, unknown fields, unsafe or duplicate paths, noncanonical hashes, unsorted entries, or exclusion mismatches.
- Exported files are `0600`, written using a staged fsync and a no-overwrite hardlink; unsupported filesystems fail closed. The export parent must already exist; output inside the scanned source is forbidden.
- The scan reuses local SHA-256 inventory safety checks, including existing no-symlink handling and per-file before/after checks. It does **not** lock an entire folder or capture an atomic directory snapshot.

## What is **not** verified

- **Freshness and replay:** The timestamp is self-reported and not trusted. Unchallenged valid snapshots remain replayable. Opt-in 256-bit challenge binding rejects a response to a *different* request, but does not prevent reuse of the *same* signed response for the *same* challenge. No durable replay ledger, trusted clock or version vector exists.
- **Accuracy and compromise:** A compromised or malicious trusted signer can sign any inventory claim. A valid signature is not a guarantee that file contents exist or can be transferred.
- **Confidentiality:** Signing does not encrypt the JSON. Transfer it separately using a confidential channel. Hashes of known files may reveal content correlations.
- **Storage attacks:** The scan is not a stable filesystem snapshot; hostile in-place mutation, symlink/path races by local privileged writers, and output-parent changes are not fully prevented.
- **Automatic synchronization:** This comparison must never authorize copying, overwriting or deleting files without a separately designed, authenticated, version-aware and reviewed protocol. There is no live listener, peer discovery, continuous watcher or background job in this mode.
- **Releases:** This is locally tested experimental source, not hosted CI, deployed service, independent security certification, physical-device validation or native application acceptance.
