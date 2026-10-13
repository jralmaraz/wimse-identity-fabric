# CLAUDE.md — WIMSE Identity Fabric

## What this is
Reference implementation of the WIMSE (Workload Identity in Multi-Service Environments) stack —
WIT, WPT, mTLS, SD-WIT, token exchange, OID-FED, identity chaining, SPIFFE Client Auth, and WAG.
Not AI-agent-specific (see wimse-agent-fabric for that layer).

- **Repo**: https://github.com/jralmaraz/wimse-identity-fabric
- **Module**: `github.com/jralmaraz/wimse-identity-fabric`
- **Local dir**: `~/claude-work/wimse-identity-fabric/`
- **Go**: `/opt/homebrew/bin/go` (v1.26+); always `export PATH=/opt/homebrew/bin:$PATH`
- **Live demo**: https://wimse-identity-fabric.pages.dev
- **Cloudflare Pages production**: https://wimse-identity-fabric.pages.dev

## Package structure
| Package | Purpose |
|---|---|
| `pkg/wit/` | Workload Identity Token (WIT) — issuer, validator, claims |
| `pkg/wpt/` | Workload Proof Token (WPT) — DPoP-style proof binding |
| `pkg/keys/` | EC P-256/JWK helpers, ECKeyPair; `Public` is `*ecdsa.PublicKey` (pointer, not value) |
| `pkg/httpsig/` | HTTP message signing (draft-ietf-httpbis-message-signatures) |
| `pkg/spiffeclientauth/` | OAuth JWT bearer client_assertion using WIT |
| `pkg/identitychaining/` | jwt-authz-grant cross-domain token exchange |
| `pkg/txntoken/` | Transaction Tokens (draft-ietf-oauth-transaction-tokens) |
| `pkg/sdwit/` | Selective Disclosure WIT (SD-JWT) |
| `pkg/federation/` | OpenID Federation 1.0 — entity config, trust chain |
| `pkg/caep/` | Continuous Access Evaluation Protocol events |
| `pkg/ssf/` | Shared Signals Framework |
| `pkg/wag/` | Workload Authorization Grant (draft-carleton-workload-authz-grant-01) |
| `internal/exchange/` | Token exchange service |
| `internal/idp/` | IdP server |
| `internal/workload/` | Workload helpers |
| `cmd/demo-wasm/` | WASM entry point (all demo functions) |
| `demo/` | Browser demo: `index.html` (cinematic journey) + `enterprise.html` + `wimse.wasm` |

## Demo — cinematic journey (index.html)
14 chapters, each as `<section class="chapter" id="chN">`.
Navigation: `CH_TITLES` (long) and `CH_SHORT` (short) arrays drive the dot nav — both must have exactly 14 entries.
`goChapter(n)` guard: `n > 14` (was `n > 13` before Ch14 was added; never revert).

| Ch | Topic |
|---|---|
| 1 | WIT — Workload Identity Token |
| 2 | mTLS — mutual TLS |
| 3 | DPoP — Proof of Possession |
| 4 | Token Exchange (RFC 8693) |
| 5 | WPT — Workload Proof Token |
| 6 | Identity Chaining |
| 7 | Transaction Tokens |
| 8 | SD-WIT — Selective Disclosure |
| 9 | SPIFFE Client Auth |
| 10 | OID-FED — OpenID Federation |
| 11 | CAEP/SSF |
| 12 | HTTP Message Signing |
| 13 | SET / Security Event Tokens |
| 14 | WAG — OAuth Bridge |

## Demo — enterprise view (enterprise.html)
16 scenarios accessible via side nav (`showScene(id)`).
Scenarios 13–16 complete the OAuth integration story:
- Sc13 `scene-spiffeclientauth` — SPIFFE Client Auth
- Sc14 `scene-identitychaining` — Identity Chaining
- Sc15 `scene-standards-vs` — WIMSE vs Existing Standards
- Sc16 `scene-wag` — WAG OAuth Bridge

## WAG package (`pkg/wag/`)
Implements draft-carleton-workload-authz-grant-01.
- `PlatformIssuer.Issue(GrantOptions)` → `wag+jwt` (ES256, `typ: wag+jwt`)
- `AuthorizationServer.Exchange(grantJWT, scope)` → `*TokenResponse`
- `AuthorizationServer.RegisterPlatform(PlatformRegistration)` — one-time per platform
- Replay protection via `consumeJTI()`: tracks jti → expiry, evicts expired entries
- `DistinguishingClaim/Value` supports multi-tenant platforms sharing one issuer ID
- Refresh tokens never issued (draft §5)
- 9 tests in `pkg/wag/wag_test.go`

## Key JWT invariants
All JWT parsers: `WithValidMethods(["ES256"])` + `WithExpirationRequired()` + `WithIssuedAt()` + `typ` header check inside key func.
Use `jwt.WithAudience` (singular) — not `jwt.WithAudiences`.

## WASM constraints
- `js.ValueOf` panics on struct pointers — return only bool/int/float64/string/`[]interface{}`/`map[string]interface{}`
- Typed slices (`[]string` etc.) inside `map[string]interface{}` kill the goroutine; always use `[]interface{}`
- WASM output file: `demo/wimse.wasm` (built from `cmd/demo-wasm/`)
- `wagDemo()` function registered as `"wagDemo": js.FuncOf(wagDemo)` in main()

## govulncheck
Pinned at v1.6.0 everywhere — do not upgrade without updating all projects.
`go get toolchain@go1.27.2` (or later) required to clear stdlib vulns in Go 1.27.x.

## ECKeyPair type
`keys.ECKeyPair.Public` is `*ecdsa.PublicKey` (pointer). Pass it directly to `RegisterPlatform` — do NOT take `&platformKey.Public` (that yields `**ecdsa.PublicKey`).

## Scope separation rule
**This repo** = workload identity broadly (WIT, WPT, OID-FED, token exchange, WAG, AIMS §6–9).
**wimse-agent-fabric** = AI-agent-specific (AgentToken, CB4A, x402, AIMS §10–11).

## Git workflow
Never commit to `main`. Branch → PR → Cloudflare Pages preview → merge.
Branch prefixes: `feat/`, `fix/`, `chore/`, `docs/`.
PR preview URL: `https://<pr-number>.wimse-identity-fabric.pages.dev`

## Common commands
```bash
export PATH=/opt/homebrew/bin:$PATH
cd ~/claude-work/wimse-identity-fabric

go test ./... -race -count=1
GOOS=js GOARCH=wasm go build -o demo/wimse.wasm ./cmd/demo-wasm/
go install golang.org/x/vuln/cmd/govulncheck@v1.6.0 && govulncheck ./...
```
