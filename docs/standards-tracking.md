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

---

## Due-Diligence Checklist for Every Standards Tracker Finding

When the automated workflow opens a standards-update issue (new draft discovered or
revision bump), the following checklist **must** be completed before the issue is closed.
This ensures threat-model coverage is maintained and the demo stays accurate.

### 1. Triage — relevance assessment

- [ ] **Classify priority**: High (breaking / new scenario) / Medium (monitor / compliance) / Low (not applicable)
- [ ] **Identify affected packages**: list every `pkg/`, `internal/`, or `cmd/` path that implements this standard
- [ ] **Identify affected demo chapters**: list every chapter in `demo/index.html` that references or demonstrates this standard

### 2. Diff review — breaking changes

- [ ] **Token type (`typ` header)**: Has the `typ` value changed? If yes, update all `tok.Header["typ"]` assignments and `typ != X` checks
- [ ] **Required claims**: Have any claims been added (`REQUIRED` in the new revision)? Update `Claims` structs and validators
- [ ] **Deprecated claims**: Have any claims been removed? Remove from struct and update tests
- [ ] **Algorithm constraints**: Has the allowed algorithm set changed? Update `WithValidMethods([]string{...})`
- [ ] **Audience / issuer semantics**: Any changes to `aud`, `iss`, or `sub` validation rules?

### 3. Threat model review

For every code change resulting from this standard update, verify:

- [ ] **Algorithm confusion**: new signing method acceptable? Does `WithValidMethods` still restrict to ES256 (or explicitly chosen set)?
- [ ] **`alg: none` attack**: Is `WithValidMethods` enforced in every new `jwt.NewParser(...)` call?
- [ ] **Missing `exp`**: Is `WithExpirationRequired()` present so tokens without `exp` are rejected?
- [ ] **Missing `iat`**: Is `WithIssuedAt()` present to detect far-future or replayed tokens?
- [ ] **Typ header confusion**: Is the `typ` header validated inside the key function (before key material is returned)?
- [ ] **Replay attack**: Does the updated token have a `jti` claim? Is replay protection (in-memory map or distributed store) wired in?
- [ ] **Scope / audience escalation**: Can an attacker present a token intended for one resource at a different endpoint? Is `aud` validated?
- [ ] **Key confusion (public-key-as-symmetric)**: All parsers use `*ecdsa.PublicKey` return type — never `[]byte` for ES256
- [ ] **Proof-of-possession**: If the spec introduces a `cnf` claim or PoP token, is the binding verified (WPT `wth`, DPoP `cnf.jkt`)?

### 4. Animated demo — required for every implemented standard

Every standard that is **implemented** (not just monitored) **must** have an animated demo
in `demo/index.html`. A text description alone is not sufficient.

- [ ] **Animated flow exists?** Check whether the relevant demo chapter has an SVG animation, step-by-step flow, or live interactive demo that shows the protocol exchange.
  - If **yes**: verify the animation still accurately reflects the updated claims / flow after the spec change. Update packet labels, arrow paths, or step descriptions as needed.
  - If **no**: create one — a minimal SVG with animated packets or `vstep` highlights is acceptable. The animation must show: the token being issued, the proof being generated, the validation step, and the result. Use the same pattern as Ch3 (WPT), Ch8 (Token Exchange), or Ch12 (SPIFFE Client Auth).
- [ ] Update the **spec-ref strip** in the affected demo chapter with the new draft revision
- [ ] Update the **Standards Tracker** section (if a standards tab is present): row rev + Impl. commit
- [ ] Update `docs/standards-tracking.md` **Included / Excluded** table if the decision changes
- [ ] Update the **README** standards list if a new standard is added
- [ ] Update **`standards-baseline.json`**: set `implemented_rev` and `last_known_rev` to the new revision

### 5. Test coverage

- [ ] Add or update a test case that specifically validates the changed claim / header / behaviour
- [ ] Verify the **negative test** (wrong `typ`, wrong `alg`, missing claim) still fails with a clear error
- [ ] Run `go test ./...` — all tests pass

### 6. Commit and close

- [ ] Commit with message pattern: `fix/feat(standard): align <pkg> with <draft-id>-<rev>`
- [ ] Push — verify CI passes (race detector + `go vet`)
- [ ] Post a summary comment on the issue listing: what changed, what was implemented, which demo chapters were updated
- [ ] Close the issue
