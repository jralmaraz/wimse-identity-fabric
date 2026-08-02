# Standards Tracking Policy

This document explains how the WIMSE Identity Fabric PoC tracks the IETF and OpenID
standards it implements, and records the decisions made about which standards to follow.

## Tracking Mechanisms

### 1. IETF Datatracker API (primary — revision detection)

`scripts/check_standards.py` polls `https://datatracker.ietf.org/api/v1/doc/document/<id>/`
daily via GitHub Actions. When `rev` in the API response differs from `last_known_rev` in
`standards-baseline.json`, a labelled GitHub issue is opened automatically.

### 2. RSS/Atom Feeds (supplement — for non-Datatracker publications)

Standards without a Datatracker entry (e.g. OpenID Federation 1.0, which is published by
OIDF rather than IETF) are tracked via the OpenID Foundation RSS feed
(`https://openid.net/feed/`). The checker matches items by keyword and records the
latest GUID so reruns don't re-alert.

### 3. WG-level Atom Feeds (discovery — unknown drafts)

The checker also polls the IETF WG-level Atom feeds:
- WIMSE WG: `https://datatracker.ietf.org/group/wimse/documents/feed/`
- OAuth WG: `https://datatracker.ietf.org/group/oauth/documents/feed/`

Any draft ID found in the feed that is **not already in `standards-baseline.json`** is
reported as a "new draft discovered" in the GitHub issue. This prevents missing a
newly-chartered draft that is immediately relevant.

### 4. GitHub Repository Watching (precision supplement — human-driven)

Each tracked standard has a `source_repo` field in `standards-baseline.json` pointing
to the editors' GitHub repository. The Datatracker only reflects formally submitted
revisions; the GitHub repo contains in-progress editor copies and active design
discussions.

**Decision**: Watch these repos for **Issues and Pull Requests only** — not all commits.
Commit-level watching produces excessive noise (editor toolchain changes, formatting
fixes, CI tweaks). Issues and PRs expose breaking design changes before they appear in
a new `-xx` revision, giving early warning for any structural impact on this PoC.

| WG / Publisher | GitHub Organization / Repo |
|---|---|
| IETF WIMSE WG (WIT, WPT, mTLS, HTTP-sig) | `github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol` |
| IETF WIMSE WG (Architecture) | `github.com/ietf-wg-wimse/draft-ietf-wimse-arch` |
| IETF WIMSE WG (Identifiers) | `github.com/ietf-wg-wimse/draft-ietf-wimse-identifier` |
| IETF OAuth WG (Transaction Tokens) | `github.com/oauth-wg/oauth-transaction-tokens` |
| IETF OAuth WG (Identity Chaining) | `github.com/oauth-wg/oauth-identity-chaining` |
| IETF OAuth WG (SPIFFE Client Auth) | `github.com/oauth-wg/oauth-spiffe-client-authentication` |
| IETF OAuth WG (SD-JWT base) | `github.com/oauth-wg/oauth-selective-disclosure-jwt` |
| OpenID Foundation | Issues: `github.com/openid/federation` |

---

## Standard Inclusion Decisions

### Included

| Standard | Why included |
|---|---|
| WIT (workload-creds) | Core WIMSE credential — everything else builds on it |
| WPT | Per-request proof of possession — closes the confused deputy gap |
| Identifiers | Governs SPIFFE URI format used in every sub claim |
| mTLS binding | Transport-layer workload authentication |
| WIMSE Architecture | Defines the overall token exchange model |
| DPoP (RFC 9449) | Proof-of-possession for access tokens — used in exchange flows |
| OpenID Federation 1.0 | Cross-org trust chain resolution |
| Txn-Token | User context propagation through multi-hop call chains; WPT tth binding |
| SPIFFE Client Auth | Allows WIT to authenticate directly to OAuth AS — eliminates shared secrets |
| Identity Chaining | RFC 8693 cross-domain token exchange with JWT authorization grant |

### Excluded — SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`)

**Decision**: Do not add SD-JWT VC to the tracked baseline.

**Rationale**: SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`, currently at rev-17) adds a
**Verifiable Credential** layer (vct claim, status lists, Issuer-Holder-Verifier ceremony)
on top of the base SD-JWT format. This model is designed for **human credentials**
(national IDs, diplomas, employee badges) where a human holder selectively presents
claims to a human-facing verifier.

This project already implements selective disclosure for workload tokens in `pkg/sdwit`,
using the base SD-JWT format (`draft-ietf-oauth-selective-disclosure-jwt`). The VC layer
adds no value for machine-to-machine authentication: the relying parties are automated
systems that either need all claims or are already using the WIT validator selectively.

Adding SD-JWT VC would introduce the Issuer-Holder-Verifier model into a machine-to-machine
authentication stack, increasing complexity without a corresponding security or interoperability
benefit for workload or AI agent identity.

**Revisit trigger**: If a future WIMSE draft explicitly adopts SD-JWT VC as the preferred
credential format for cross-org human-delegated agent authorization, reconsider.

---

## Baseline File

`standards-baseline.json` at the repository root is the single source of truth. Fields:
- `last_known_rev` / `implemented_rev`: track spec version vs implementation version
- `source_repo`: GitHub URL for issues/PR watching (see above)
- `wg_feeds`: WG-level Atom feeds for new draft discovery
- `rss_url` / `rss_keywords` / `last_rss_guid`: RSS tracking for OIDF publications

The GitHub Actions workflow `.github/workflows/standards-tracker.yml` runs daily,
calls `scripts/check_standards.py`, and opens a labelled issue on any change.
