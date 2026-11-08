# GoreeCloud Sync — Manual publication and verification checklist

**Status:** Prepared instructions only; no GitHub push or hosted CI was completed when this local source bundle was assembled.

I require the source for GoreeCloud Sync to be maintained in my public repository [`GoreeCloud/sync`](https://github.com/GoreeCloud/sync) using the authorized GitHub identity associated with `admin@goreecloud.com`. I require a reviewed, verifiable commit before any claims of GitHub publication, hosted CI, integration, or release maturity.

The repository was verified as public on November 3, 2026. Its `main` and `feat/initial-share-foundation` development branch pointed at the same initial placeholder commit (`c99a060338ddd08944173e129e7cbeaac4f51e4a`). The connected GitHub commit operation was blocked by a platform safety check in an earlier interaction; do **not** circumvent that restriction. This checklist is for a future separately authorized operation through a permitted environment, not an instruction to bypass a control.

## Preflight before publishing

1. Authenticate as the intended `GoreeCloud` owner and verify the repository URL and current branch head in the live GitHub API or the repository page. Stop if the head has changed and inspect the changes first.
2. Extract the source bundle in a fresh directory and compare the published ZIP SHA-256 checksum to the accompanying checksum file. Do not execute an archive blindly or copy credential/private files.
3. Inspect the original full [`PRODUCT_SPEC.md`](PRODUCT_SPEC.md) and implementation docs. Verify no secrets, live server paths, private device identifiers, credentials, tokens, downloaded files, `.env` files, or large generated artifacts are about to enter a public repository.
4. Run the exact commands in [`VALIDATION.md`](VALIDATION.md), including the race detector, static analysis, protocol roundtrip, additions-only CLI, Nearby Send CLI, and pinned-identity and mutual-identity CLI. Record platform and test results accurately.
5. Do not import third-party code or licenses without provenance, compatibility and security review. The founder has now selected MIT (`SPDX: MIT`) for the original preview source, authored in local `LICENSE`; the license is not committed publicly yet. Verify rights and notices before distribution.

## Publication through an allowed workflow

Use an authorized Git client or a platform-approved connector only if that action is permitted, the repository and identity are verified again, and no safety check blocks the operation. Commit the reviewed project files onto a **development branch**, not directly into a production deployment path. Review every staged file and diff before making the public commit. Push the branch and read back the exact changed tree and commit SHA from GitHub. Open a pull request only after publication succeeds; hosted CI cannot be claimed without a run for that exact commit.

The GitHub CI workflow is configured to run Go format, race, vet, build, browser JavaScript syntax, encrypted Share integration, safe additions-only CLI loopback Nearby Send CLI and pinned-identity, mutual-identity and signed rotation CLI tests. A local green suite does not imply hosted Actions passed. Verify all checks and the same commit SHA independently.

## Canonical project synchronization

After successful source publication, update the **existing** `GoreeCloud/GoreeCloud-Github-Repositories.md` in the connected Google Drive folder, rather than creating a duplicate. Preserve the current five-file maximum root governance and verify file identity, actual contents, role, description and status. Update the existing Todoist task only to reflect verified progress. Do not deploy this development preview to a public VPS or reverse proxy.

## Additional prepublication acceptance for experimental recovery v2

Before approving the new development branch, inspect `internal/syncplan/durable_recovery.go`, the intent verification rules and new `tests/pending-recovery-cli.sh`. The journal version changed from experimental v1 to **v2**, and older local preview checkpoints do not migrate. A publication or rollout plan must communicate this incompatibility to anyone who used the earlier preview. No production state migration, filesystem backup or automatic healing mechanism is part of the source package. Run the full hosted CI matrix including the newly configured pending-recovery CLI test, and inspect the exact committed SHA before merge or release.

## Repository-specific license release gate

MIT (`SPDX: MIT`) was selected for this repository and authored in the local `LICENSE` file, but is **not yet committed** to `GoreeCloud/sync`. Refer to [PUBLICATION_LICENSE_GATE.md](PUBLICATION_LICENSE_GATE.md) for the rationale, scope, rights checks and default-branch readback requirements before a permitted review-branch publication. Do not mistake public repository visibility for a reuse grant or the locally verified patch for a merged commit.
