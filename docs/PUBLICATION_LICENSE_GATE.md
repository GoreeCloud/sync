# GoreeCloud Sync — MIT license selection and publication gate

**Decision:** MIT License, SPDX identifier `MIT`, selected November 7, 2026 on founder delegation for this individual repository. **Implementation status:** complete license text authored in the **local** repository-root [`LICENSE`](../LICENSE), with `Copyright (c) 2026 GoreeCloud`. **Publication status:** pending. Live `GoreeCloud/sync` main remains README-only as last verified on November 7, 2026; the license is **not yet committed** and no public license-detection or hosted CI result is claimed.

## Why MIT for this repository

GoreeCloud Sync is an original early-stage, self-hosted personal utility (encrypted Share, manually paired Nearby Send and experimental local/offline Sync). The founder prioritizes a simple, low-maintenance, permissive grant so that others can study, reuse, modify and distribute the implementation while preserving copyright and license notices. Unlike GPL/AGPL, MIT does not obligate recipients to publish the source to their modifications or hosted services. Compared with Apache-2.0, MIT is shorter and has fewer notice/administrative terms, but does **not** contain the same express patent-license language. This is a per-repository decision, **not** an ecosystem-wide license rule.

The standardized license is the [OSI-approved MIT License](https://opensource.org/license/mit), SPDX identifier [`MIT`](https://spdx.org/licenses/MIT). Its full unmodified grant/conditions/disclaimer appears in the local `LICENSE`; only the standard copyright-year/holder field is completed. No new custom license wording is imposed.

## Scope and provenance checks

- The preview Go module declares `github.com/GoreeCloud/sync` with Go 1.23 and **zero third-party `require` directives**. The bundled browser page references only its own local JavaScript and CSS, and the packaging source did not contain vendor bundles, outside binaries or fonts. This is a bounded observation, not a complete authorship audit.
- The original 33-section founder-supplied product specification is maintained unchanged at `docs/PRODUCT_SPEC.md`. Before public release, verify its rights and any quotations or assets; the repository MIT text does **not** override rights belonging to others.
- No matching existing upstream codebase or identified separately licensed dependency was found in this local review. Future imports, external code, imagery, fonts, packages and contributions must be individually checked for compatible grants and preserved notices before inclusion.
- Copyright label `GoreeCloud` represents the founder-controlled project name, but the underlying legal ownership/rights remain the founder's responsibility to affirm before public release. This document does not make a legal determination.

## What remains before public license compliance

1. Confirm ownership or redistribution permission for each original code/document contribution and any later imported material, including the product specification. Preserve independently licensed third-party notices.
2. Verify root `LICENSE`, README, and any package/metadata identification in the exact proposed Git diff. Run manifest checks, tests, and a pre-publication secret/provenance review.
3. Resolve the earlier platform safety restriction through a **permitted** GitHub workflow; do not bypass it. Publish the reviewed files to the authorized `GoreeCloud/sync` repo and read back the resulting commit tree.
4. After a permitted merge, confirm `LICENSE` on `main` contains the exact MIT text and review GitHub's detected repository license; only then mark repository-level license adoption verified. Validate hosted CI against the exact commit.
5. Synchronize the existing authorized Todoist task and relevant canonical documentation with **actual** repository state, not this local source draft.

**Until publication succeeds**, `GoreeCloud/sync` is still a README-only public repository without a committed MIT license; this local review artifact does not change that live state. MIT licensing does not establish product security, maturity, operational readiness or permission to deploy.
