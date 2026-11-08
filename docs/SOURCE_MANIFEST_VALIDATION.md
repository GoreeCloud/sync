# Source manifest completeness and verification

**Status:** November 5, 2026 local candidate, not published to GitHub or verified in hosted CI.

The `SOURCE_SHA256SUMS.txt` file is a sorted listing of SHA-256 digests and relative paths for every source file, except itself. It is generated when a source package is assembled. The proposed GitHub verification workflow checks it before running build and integration tests.

```sh
python3 -B -m unittest discover -s tools -p 'test_*.py'
python3 -B tools/verify_source_manifest.py
```

The `-B` option avoids creating Python bytecode caches that are not part of a source package. The verifier rejects corrupt, malformed, duplicate or unsafe manifest entries, altered and missing content, and any unexpected regular file or symlink in the package. `.git/` metadata and the checksum manifest itself are excluded. Unlike `sha256sum -c`, this ensures the manifest enumerates every packaged file.

For intentional source changes, regenerate the manifest from a reviewed file tree, excluding `.git/` and the manifest itself. Run the verification immediately afterward. **Do not regenerate a manifest solely to silence an unexplained mismatch or unexpected file.** Review such differences for malicious or accidental content first.

**Trust limitation:** The manifest is not signed. Attackers able to change both source bytes and the manifest can produce a self-consistent but malicious bundle. Obtain package SHA-256 values from a trusted independent channel, review the exact source, and independently verify official GitHub commits and hosted CI once publication is allowed. No deployment, provenance signature, or hosted CI acceptance is claimed.
