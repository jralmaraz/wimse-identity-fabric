# WIMSE Identity Fabric — Proof of Concept

A Go implementation of the **IETF WIMSE** (Workload Identity in Multi-System Environments) standard, built as an incremental five-phase PoC. It demonstrates the complete workload identity stack: token issuance, workload-to-workload authentication over mutual TLS, cross-trust-domain token exchange, and selective disclosure credentials aligned with the IETF SPICE working group.

## Table of Contents

- [Overview](#overview)
- [IETF Spec Reference](#ietf-spec-reference)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Running the Tests](#running-the-tests)
- [Phase 1 — Token Library](#phase-1--token-library)
- [Phase 2 — Identity Provider](#phase-2--identity-provider)
- [Phase 3 — Workload-to-Workload Authentication](#phase-3--workload-to-workload-authentication)
- [Phase 4 — Token Exchange (Cross-Trust-Domain)](#phase-4--token-exchange-cross-trust-domain)
- [Phase 5 — Selective Disclosure WIT (SPICE)](#phase-5--selective-disclosure-wit-spice)
- [Token Formats](#token-formats)
- [Security Properties](#security-properties)
- [Deployment](#deployment)
  - [Local Development](#local-development)
  - [VM Deployment (GCP + AWS)](#vm-deployment-gcp--aws)
  - [Kubernetes](#kubernetes)
  - [Cloud Provider Managed](#cloud-provider-managed)
- [Design Decisions](#design-decisions)

---

## Overview

Modern cloud-native deployments span multiple trust domains — different clouds, clusters, and platforms — each with its own identity system. WIMSE defines how workloads (services, jobs, functions) prove their identity to each other without relying on a single shared secret or a centralised identity broker at request time.

This PoC implements two complementary mechanisms:

| Mechanism | What it proves | Where it lives |
|---|---|---|
| **mTLS** (mutual TLS) | Transport-layer identity via X.509 URI SAN | TLS handshake |
| **WIT + WPT** | Application-layer identity + per-request proof-of-possession | HTTP headers |

The two layers are deliberately independent. mTLS proves *which process* made the connection; the WIT proves *which workload identity* that process holds, signed by a trusted IdP; the WPT proves the holder still controls the private key that corresponds to the WIT's `cnf` claim — at this specific request, to this specific target, only once.

Phase 5 extends WIT with **selective disclosure** (SD-JWT format, IETF SPICE WG), allowing a workload to reveal only a subset of its claims to different verifiers — without breaking the WPT proof-of-possession binding.

---

## IETF Spec Reference

| Draft / RFC | Implemented in | Key requirements |
|---|---|---|
| `draft-ietf-wimse-workload-creds-02` | Phases 1, 2, 3 | WIT `typ: wit+jwt`, `sub`, `exp`, `cnf.jwk` (with `alg`) |
| `draft-ietf-wimse-wpt-01` | Phases 1, 3 | WPT `typ: application/wpt+jwt`, `aud`=target URI, `wth`=SHA-256(WIT), `jti` |
| `draft-ietf-wimse-identifier-03` | Phases 1–4 | Workload IDs: absolute URIs, `spiffe://` or `wimse://` schemes |
| `draft-ietf-wimse-mutual-tls-02` | Phases 1, 3 | X.509 URI SAN, EC P-256, TLS 1.3+ |
| `draft-ietf-wimse-arch-08` | Phase 4 | Token exchange at trust-domain boundaries |
| `draft-ietf-oauth-selective-disclosure-jwt` (RFC 9278) | Phase 5 | SD-JWT format, `_sd` hashes, disclosure strings |
| `draft-ietf-spice-sd-cwt-08` | Phase 5 (reference) | CBOR analog; `cnf` key binding identical to SD-JWT |
| `draft-mw-wimse-transitive-attestation-00` | Phase 5 (reference) | SPICE as privacy shield layer in WIMSE attestation chains |

---

## Architecture

### Single trust domain (Phases 2–3)

```
                      ┌─────────────────────────────────────────┐
                      │           Trust Domain: cloud-a.example  │
                      │                                         │
                      │  ┌──────────┐        ┌──────────────┐  │
                      │  │  IdP-A   │        │  Workload B  │  │
                      │  │ /wit/issue│        │  /api/echo   │  │
                      │  │ /jwks.json│        │  (protected) │  │
                      │  └────┬─────┘        └──────┬───────┘  │
                      │       │ ① issue WIT          │          │
                      │  ┌────▼──────────────────────┼───────┐  │
                      │  │         Workload A         │       │  │
                      │  │  holds: WIT, EC key pair   │       │  │
                      │  │  ② generate WPT per-request│       │  │
                      │  │  ③ mTLS + WIT + WPT ───────►       │  │
                      │  └────────────────────────────┘       │  │
                      └─────────────────────────────────────────┘
```

### Cross-trust-domain (Phase 4)

```
  cloud-a.example                                  cloud-b.example
  ┌──────────────┐    POST /token/exchange    ┌───────────────────┐
  │  Workload A  │──────────────────────────► │ Token Exchange Svc│
  │  WIT from    │   {token: <WIT-A>}         │                   │
  │  IdP-A       │◄──────────────────────────  │ 1. validate WIT-A │
  │              │   {token: <WIT-B>}         │ 2. apply policy   │
  └──────┬───────┘                            │ 3. issue WIT-B    │
         │                                    └───────────────────┘
         │  mTLS + Workload-Identity-Token: WIT-B
         │  Workload-Proof-Token: WPT (signed with A's key)
         ▼
  ┌──────────────┐
  │  Workload B  │  ← trusts IdP-B, accepts WIT-B
  │  /api/echo   │
  └──────────────┘
```

### Selective disclosure (Phase 5 — SPICE integration)

```
  Issuer (IdP)                Holder (Workload A)          Verifier (Workload B)
  ─────────────────────────────────────────────────────────────────────────────
  Issue SD-WIT
  ┌ JWT (always visible) ──────────────────────────────────────────────────────
  │  iss, iat, exp, cnf.jwk, _sd=[hash(sub), hash(roles), hash(trust_domain)]
  └────────────────────────────────────────────────────────────────────────────
  Disclosures: ~enc(sub)~enc(roles)~enc(trust_domain)~
                    │
                    │  Holder selects what to reveal (Present())
                    ▼
  Presentation to lower-trust service:
  ┌ JWT unchanged ──────────────────────────────────────────────────────────────
  │  iss, iat, exp, cnf.jwk, _sd=[hash(sub), hash(roles), hash(trust_domain)]
  └─────────────────────────────────────────────────────────────────────────────
  Disclosures: ~enc(sub)~            ← roles and trust_domain hidden
                    │
                    │  Verifier sees: sub (disclosed) + cnf.jwk (always)
                    │  Cannot learn: roles, trust_domain (no disclosures provided)
                    │  Still validates: WPT signed with key from cnf.jwk
                    ▼
  200 OK — caller identity verified, roles intentionally withheld
```

---

## Project Structure

```
wimse-identity-fabric/
│
├── pkg/                          Phase 1 + Phase 5 — pure library, no HTTP
│   ├── keys/
│   │   ├── ec.go                 EC P-256 key generation, JWK (de)serialization,
│   │   │                         SaveECPrivateKey / LoadECPrivateKey (PEM files)
│   │   ├── ec_test.go
│   │   ├── mtls.go               CA generation, workload cert issuance, TLS helpers,
│   │   │                         SaveCABundle / LoadCABundle / LoadCACertPool
│   │   └── mtls_test.go
│   ├── wit/
│   │   ├── claims.go             WITClaims struct + ConfirmationKey
│   │   ├── helpers.go            generateJTI()
│   │   ├── issuer.go             Issuer.Issue()
│   │   ├── validator.go          Validator.Validate() — sig/exp/iss/typ + cnf key
│   │   └── wit_test.go
│   ├── wpt/
│   │   ├── claims.go             WPTClaims (wth, ath)
│   │   ├── helpers.go            generateJTI(), hashToken()
│   │   ├── generator.go          Generate()
│   │   ├── validator.go          Validator + jti replay store
│   │   └── wpt_test.go
│   └── sdwit/                    Phase 5 — SD-JWT-VC Workload Identity Token
│       ├── claims.go             VerifiedClaims, SelectiveClaims, package doc
│       ├── helpers.go            newSalt(), buildDisclosure(), hashDisclosure()
│       ├── issuer.go             Issuer.Issue() → <JWT>~<disc1>~<disc2>~...~
│       ├── validator.go          Validator.Validate() — verifies + unpacks disclosures
│       ├── presentation.go       Present(), RevealedClaims(), FullPresentation()
│       └── sdwit_test.go
│
├── internal/                     Phases 2–4 — HTTP services
│   ├── idp/                      Phase 2 — Identity Provider
│   │   ├── config.go
│   │   ├── handler.go            IssueHandler, JWKSHandler
│   │   ├── server.go
│   │   └── idp_test.go
│   ├── workload/                 Phase 3 — auth middleware + outbound client
│   │   ├── middleware.go         WIMSEAuth() Gin middleware
│   │   ├── client.go             Client — auto-attaches WIT+WPT headers
│   │   ├── server.go             NewProtectedRouter(), EchoHandler()
│   │   └── workload_test.go
│   └── exchange/                 Phase 4 — Token Exchange Service
│       ├── policy.go             TrustPolicy — issuers, subjects, rewrite rules
│       ├── handler.go            ExchangeHandler
│       ├── server.go
│       └── exchange_test.go
│
├── cmd/                          Runnable binaries
│   ├── gen-ca/main.go            Generates CA cert + key PEM files
│   ├── gen-cert/main.go          Issues workload cert from existing CA
│   ├── idp/main.go               Identity Provider server
│   ├── workload-a/main.go        Caller workload — fetches WIT, calls Workload B
│   ├── workload-b/main.go        Callee workload — mTLS + WIMSE-protected /api/echo
│   └── token-exchange/main.go   Cross-domain token exchange bridge
│
└── infra/                        VM + cloud deployment (see Deployment section)
    ├── terraform/
    │   ├── main.tf               GCP e2-micro + AWS t3.micro VMs
    │   ├── variables.tf
    │   ├── outputs.tf
    │   └── terraform.tfvars.example
    └── scripts/
        ├── provision.sh          Build → generate certs → terraform → upload → start
        ├── e2e-test.sh           Smoke tests against live VMs
        ├── gcp-startup.sh        GCP VM bootstrap (systemd units)
        └── aws-startup.sh        AWS VM bootstrap (systemd units)
```

---

## Prerequisites

- **Go 1.21+** (tested with 1.25/1.26)
- No other runtime dependencies; all dependencies are fetched via `go mod`

```bash
git clone <repo>
cd wimse-identity-fabric
go mod download
```

---

## Running the Tests

```bash
# All packages, all phases (44 tests)
go test ./... -v -count=1

# Just the token library (Phases 1 + 5)
go test ./pkg/... -v -count=1

# Just the HTTP services (Phases 2–4)
go test ./internal/... -v -count=1

# Phase 5 only
go test ./pkg/sdwit/... -v -count=1
```

Expected output — all packages pass:

```
ok  github.com/example/wimse-identity-fabric/pkg/keys
ok  github.com/example/wimse-identity-fabric/pkg/wit
ok  github.com/example/wimse-identity-fabric/pkg/wpt
ok  github.com/example/wimse-identity-fabric/pkg/sdwit
ok  github.com/example/wimse-identity-fabric/internal/idp
ok  github.com/example/wimse-identity-fabric/internal/workload
ok  github.com/example/wimse-identity-fabric/internal/exchange
```

---

## Phase 1 — Token Library

`pkg/keys`, `pkg/wit`, `pkg/wpt` — pure library code with zero HTTP dependencies.

### `pkg/keys` — Cryptographic primitives

#### EC key pairs

```go
// Generate a new EC P-256 key pair
kp, err := keys.GenerateECKeyPair()

// Serialize the public key as a JWK (RFC 7517)
// X and Y coordinates are left-padded to 32 bytes per RFC 7518 §6.2.
// Alg is always set to "ES256" as required by the workload-creds draft.
jwk, err := keys.PublicKeyToJWK(kp.Public, "my-key-id")

// Deserialize back, validating that the point is on the P-256 curve
pub, err := keys.JWKToPublicKey(jwk)

// Persist and reload (for stable IdP signing keys across restarts)
err = keys.SaveECPrivateKey("/opt/wimse/keys/idp.key", kp.Private)
priv, err := keys.LoadECPrivateKey("/opt/wimse/keys/idp.key")
```

#### mTLS certificates

The same EC P-256 key pair that goes into the WIT `cnf.jwk` is also used as the workload's mTLS private key. This co-locates cryptographic material, making it straightforward to correlate transport and application identities.

```go
// Self-signed CA for a trust domain (or generate via cmd/gen-ca)
ca, err := keys.GenerateCA("cloud-a.example")
keys.SaveCABundle(ca, "/opt/wimse/ca.crt", "/opt/wimse/ca.key")

// Issue a workload certificate (or use cmd/gen-cert)
wc, err := ca.IssueWorkloadCert(
    "spiffe://cloud-a.example/workload-a",
    kp.Public,
    &keys.CertOptions{
        IPAddresses: []net.IP{net.ParseIP("34.100.x.x")}, // VM external IP
    },
)

// Build TLS configs for server and client
serverTLS, err := keys.NewServerTLSConfig(ca.CertPool(), wc, kp.Private)
clientTLS, err := keys.NewClientTLSConfig(ca.CertPool(), wc, kp.Private)
```

All TLS configs enforce **TLS 1.3 minimum** (`tls.VersionTLS13`).

---

### `pkg/wit` — Workload Identity Token

A WIT is a signed JWT (`alg: ES256`, `typ: wit+jwt`) issued by a trust domain's IdP. It asserts the workload's identity and embeds the workload's public key in a `cnf.jwk` claim.

#### Issuing a WIT

```go
issuer := wit.NewIssuer("https://idp.cloud-a.example", idpPrivateKey, time.Hour)

token, err := issuer.Issue(wit.IssueOptions{
    Subject:     "spiffe://cloud-a.example/workload-a",
    TrustDomain: "cloud-a.example",
    WorkloadKey: workloadPublicKey, // embedded in cnf.jwk
})
```

The issued JWT:

```json
// Header
{"alg":"ES256","typ":"wit+jwt"}

// Payload
{
  "iss": "https://idp.cloud-a.example",
  "sub": "spiffe://cloud-a.example/workload-a",
  "iat": 1753574400,
  "exp": 1753578000,
  "jti": "a1b2c3...",
  "trust_domain": "cloud-a.example",
  "cnf": { "jwk": { "kty":"EC","crv":"P-256","x":"...","y":"...","alg":"ES256" } }
}
```

#### Validating a WIT

```go
validator := wit.NewValidator("https://idp.cloud-a.example", idpPublicKey)
result, err := validator.Validate(token)
// result.Claims      *wit.Claims
// result.WorkloadKey *ecdsa.PublicKey  — extracted from cnf.jwk
```

The validator checks: correct `alg`, correct `typ`, valid signature, not expired, `iss` matches, and `cnf.jwk` is a valid P-256 point.

---

### `pkg/wpt` — Workload Proof Token

A WPT is a short-lived JWT (`alg: ES256`, `typ: application/wpt+jwt`) signed by the **workload's own private key**. It proves possession of the key at this specific request.

```go
wptToken, err := wpt.Generate(wpt.GenerateOptions{
    TargetURI:   "https://api.cloud-b.example/orders",
    WIT:         witToken,
    WorkloadKey: workloadPrivateKey,
    TTL:         5 * time.Minute,
})
```

WPT payload:

```json
{
  "aud": ["https://api.cloud-b.example/orders"],
  "iat": 1753574400,
  "exp": 1753574700,
  "jti": "unique-per-request",
  "wth": "<base64url(sha256(WIT compact string))>"
}
```

```go
validator := wpt.NewValidator()
claims, err := validator.Validate(wpt.ValidateOptions{
    WPTString:         wptToken,
    WITString:         witToken,
    WorkloadPublicKey: workloadPublicKey,
    RequestURI:        "https://api.cloud-b.example/orders",
    CheckReplay:       true,
})
```

---

## Phase 2 — Identity Provider

`internal/idp` — a Gin HTTP service that issues WITs and serves the IdP's public key as JWKS.

### Endpoints

#### `POST /wit/issue`

```json
// Request
{ "subject": "spiffe://cloud-a.example/svc/billing",
  "trust_domain": "cloud-a.example",
  "public_key": {"kty":"EC","crv":"P-256","x":"...","y":"...","alg":"ES256"} }

// Response
{ "token": "<compact WIT JWT>" }
```

Errors: `400` (missing subject / invalid key), `403` (subject not in allow-list).

#### `GET /.well-known/jwks.json`

Returns the IdP's EC P-256 public key as a JWKS. Relying parties cache this and validate WITs without contacting the IdP per-request.

#### `GET /health`

Returns `{"status":"ok"}`.

### Tests (7)

| Test | What it checks |
|---|---|
| `TestIssue_HappyPath` | POST returns a valid WIT that validates against the IdP's key |
| `TestIssue_MissingSubject` | 400 when subject is absent |
| `TestIssue_InvalidPublicKey` | 400 for a JWK with an invalid EC point |
| `TestIssue_SubjectNotAllowed` | 403 when subject is not in the allow-list |
| `TestJWKS_ReturnsIdPPublicKey` | JWKS response contains a valid ES256 key |
| `TestJWKS_ValidatesWIT` | Key from JWKS can verify a token issued by this IdP |
| `TestHealth` | 200 from /health |

---

## Phase 3 — Workload-to-Workload Authentication

`internal/workload` — Gin middleware and HTTP client for end-to-end WIMSE authentication.

### HTTP Headers

```
Workload-Identity-Token: <compact WIT JWT>
Workload-Proof-Token:    <compact WPT JWT>
```

### `WIMSEAuth` Middleware

```go
r := gin.New()
r.Use(workload.WIMSEAuth(witValidator, wptValidator))
```

Steps performed on every request:
1. Read `Workload-Identity-Token` header — `401` if missing
2. Validate WIT (sig, exp, iss, typ) — `401` if invalid
3. Extract workload public key from `cnf.jwk`
4. Read `Workload-Proof-Token` header — `401` if missing
5. Build request URI (`scheme://host/path`) for audience validation
6. Validate WPT (sig, exp, aud==URI, wth==SHA-256(WIT), jti replay) — `401` if invalid
7. Inject `*wit.Claims` into Gin context under `"wimse_wit_claims"`

### Full mTLS + WIT + WPT call flow

```
Workload A                                         Workload B
─────────────────────────────────────────────────────────────
1. TLS ClientHello
   └─► ServerHello + server cert (URI SAN: spiffe://…/workload-b)
   ◄── server validates A's client cert (URI SAN: spiffe://…/workload-a)
   [TLS 1.3 handshake complete]

2. GET /api/echo HTTP/1.1
   Workload-Identity-Token: <WIT>   signed by IdP-A
   Workload-Proof-Token:    <WPT>   signed by workload-a's key
                                    aud = "https://…/api/echo"
                                    wth = sha256(WIT)
                                    jti = unique

3. Middleware validates:
   ✓ WIT sig, exp, iss, typ
   ✓ WPT sig (workload key from cnf.jwk)
   ✓ WPT aud == request URI
   ✓ WPT wth == sha256(WIT)
   ✓ WPT jti not seen before

4. 200 OK {"caller":"spiffe://cloud-a.example/workload-a","echo":"ok"}
```

### Tests (9)

| Test | What it checks |
|---|---|
| `TestMiddleware_HappyPath` | Valid WIT+WPT → 200, caller identity in body |
| `TestMiddleware_MissingWIT` | 401 when `Workload-Identity-Token` absent |
| `TestMiddleware_MissingWPT` | 401 when `Workload-Proof-Token` absent |
| `TestMiddleware_InvalidWIT` | 401 for a tampered WIT |
| `TestMiddleware_InvalidWPT` | 401 for a zeroed WPT signature |
| `TestMiddleware_WPTAudienceMismatch` | 401 when WPT aud ≠ request URI |
| `TestMiddleware_ReplayAttack` | Second use of the same WPT → 401 |
| `TestClient_AttachesHeaders` | Both WIMSE headers present on outbound requests |
| `TestEndToEnd_WorkloadAtoB` | Full A→B call with mTLS + WIT + WPT → 200 |

---

## Phase 4 — Token Exchange (Cross-Trust-Domain)

`internal/exchange` — a bridge service that accepts a WIT from domain A and issues a new WIT from domain B.

### Why this is needed

Workload B validates WITs against **IdP-B's** public key. A token from IdP-A fails B's signature check. The Token Exchange Service trusts both IdPs, validates the inbound WIT with IdP-A's key, applies a trust policy, and re-issues a semantically equivalent WIT with IdP-B's signing key. The workload's own `cnf.jwk` is preserved, so the same private key signs WPTs before and after the exchange.

### Configuration

```go
cfg := &exchange.ExchangeConfig{
    Policy: &exchange.TrustPolicy{
        AllowedIssuers: map[string]*ecdsa.PublicKey{
            "https://idp.cloud-a.example": idpAPublicKey,
        },
        SubjectMap: map[string]string{
            "spiffe://cloud-a.example/svc/billing": "spiffe://cloud-b.example/ext/billing",
        },
    },
    TargetIssuer: wit.NewIssuer("https://idp.cloud-b.example", idpBPrivateKey, time.Hour),
}
```

### Tests (7)

| Test | What it checks |
|---|---|
| `TestExchange_HappyPath` | WIT-A → WIT-B, validated with IdP-B's key |
| `TestExchange_SubjectRewrite` | Subject translated via SubjectMap |
| `TestExchange_UnknownIssuer` | 403 when iss not in AllowedIssuers |
| `TestExchange_InvalidWIT` | 401 for a zeroed signature |
| `TestExchange_ExpiredWIT` | 401 for expired source token |
| `TestExchange_SubjectNotAllowed` | 403 when sub not in AllowedSubjects |
| `TestEndToEnd_CrossDomain` | A exchanges WIT-A for WIT-B, calls B's endpoint → 200 |

---

## Phase 5 — Selective Disclosure WIT (SPICE)

`pkg/sdwit` — extends the WIT credential format with **selective disclosure** based on the SD-JWT standard (RFC 9278). This is the WIMSE integration point for the IETF SPICE working group.

### Motivation

A plain WIT reveals all claims (`sub`, `trust_domain`, `roles`) to every verifier. In a multi-service environment, a workload may not want to expose its full identity to every downstream service. SD-JWT solves this: the IdP issues a single credential with all claims, but the workload can choose which claims to reveal to each verifier.

### SD-WIT Format

An SD-WIT is a tilde-separated string:

```
<Issuer-signed JWT>~<Disclosure1>~<Disclosure2>~...~
```

The Issuer-signed JWT carries:
- Always-visible: `iss`, `iat`, `exp`, `jti`, `cnf.jwk`, `aud`, `_sd_alg`
- Selective hashes: `_sd: [sha256(disc1), sha256(disc2), ...]`

Each disclosure is `base64url(JSON(["salt", "claim_name", value]))`.

```json
// JWT header
{"alg": "ES256", "typ": "wit+sd-jwt"}

// JWT payload (all claims selective)
{
  "iss":     "https://idp.cloud-a.example",
  "iat":     1753574400,
  "exp":     1753578000,
  "jti":     "a1b2c3...",
  "cnf":     {"jwk": {"kty":"EC","crv":"P-256","x":"...","y":"...","alg":"ES256"}},
  "_sd_alg": "sha-256",
  "_sd":     ["bWx2...hash_of_sub", "aXp3...hash_of_roles", "dGQ4...hash_of_td"]
}

// Disclosures (appended after ~)
WyJzYWx0...", "sub",          "spiffe://cloud-a.example/workload-a"]
WyJzYWx0...", "trust_domain", "cloud-a.example"]
WyJzYWx0...", "roles",        ["admin","billing"]]
```

### API

#### Issuing an SD-WIT

```go
issuer := sdwit.NewIssuer("https://idp.cloud-a.example", idpPrivateKey, time.Hour)

fullToken, err := issuer.Issue(sdwit.IssueOptions{
    Subject:     "spiffe://cloud-a.example/workload-a",
    TrustDomain: "cloud-a.example",
    Roles:       []string{"admin", "billing"},
    WorkloadKey: workloadPublicKey,
    // Mark claims as selectively disclosable.
    // Claims not listed here go directly in the JWT payload (always visible).
    Selective: sdwit.SelectiveClaims{
        Sub:         true,
        TrustDomain: true,
        Roles:       true,
    },
})
// fullToken = "<JWT>~enc(sub)~enc(trust_domain)~enc(roles)~"
```

#### Presenting a subset

```go
// Holder wants to reveal only sub to a lower-trust service.
presentation, err := sdwit.Present(fullToken, []string{"sub"})
// presentation = "<JWT>~enc(sub)~"  — trust_domain and roles stripped

// Inspect what a presentation reveals before sending it.
names, err := sdwit.RevealedClaims(presentation)
// names = ["sub"]
```

#### Validating a presentation

```go
v := sdwit.NewValidator("https://idp.cloud-a.example", idpPublicKey)
claims, err := v.Validate(presentation)
// claims.Subject     = "spiffe://cloud-a.example/workload-a"  (disclosed)
// claims.TrustDomain = ""      — not included in this presentation
// claims.Roles       = nil     — not included in this presentation
// claims.WorkloadKey = <key>   — always available from cnf.jwk
```

### WPT compatibility

The WPT `wth` claim hashes the **full SD-WIT string** (including all disclosures) that the Holder possesses. This means:
- WPT generation uses the full token, not a presentation
- Different presentations of the same token have different hashes
- The Holder always passes the full SD-WIT to `wpt.Generate`, and the corresponding full SD-WIT as `Workload-Identity-Token` to the verifier

```go
// The WPT is bound to the full SD-WIT the Holder holds.
wptToken, err := wpt.Generate(wpt.GenerateOptions{
    TargetURI:   "https://api.cloud-b.example/orders",
    WIT:         fullToken,   // full SD-WIT, not a filtered presentation
    WorkloadKey: workloadPrivateKey,
})
```

### SPICE alignment

| SPICE concept | SD-WIT equivalent |
|---|---|
| Issuer → Holder → Verifier flow | IdP → Workload → Target service |
| `cnf` key confirmation | Identical — cnf.jwk always visible for WPT binding |
| Selective disclosure hashes (`_sd`) | Same mechanism; JSON/JOSE encoding |
| Key Binding Token (KBT) | Served by WPT (per-request, request-URI bound) |
| SD-CWT (CBOR variant) | Not implemented; would use `crypto/cbor` + `go-cose` |
| `draft-mw-wimse-transitive-attestation` | SD-CWT used as privacy shield layer |

### Tests (11)

| Test | What it checks |
|---|---|
| `TestSDWIT_HappyPath_NoSelectiveDisclosure` | Issue + validate with no selective claims |
| `TestSDWIT_SelectivePresentation_SubOnly` | Issue with all selective; present only sub; verifier sees sub, not roles/td |
| `TestSDWIT_SelectivePresentation_AllRevealed` | Full presentation reveals all selective claims |
| `TestSDWIT_PartialSelective_RolesOnly` | Only roles selective; sub+td always visible; present without roles hides them |
| `TestSDWIT_TypHeader` | JWT typ header is `wit+sd-jwt` |
| `TestSDWIT_Expired` | Reject expired SD-WIT |
| `TestSDWIT_WrongKey` | Reject wrong IdP signing key |
| `TestSDWIT_TamperedJWT` | Reject zeroed JWT signature |
| `TestSDWIT_TamperedDisclosure` | Reject disclosure whose hash is not in _sd |
| `TestSDWIT_WthBinding` | Full vs. limited presentation produce different wth values |
| `TestSDWIT_EndToEnd` | Full SPICE flow: issue → present subset → validate → privacy confirmed |

---

## Token Formats

### Workload Identity Token (WIT) — `typ: wit+jwt`

```
Header:  {"alg":"ES256","typ":"wit+jwt"}
Payload: {
  "iss": <IdP issuer URI>,
  "sub": <workload identity URI>,    // spiffe:// or wimse://
  "aud": [<audiences>],
  "iat": <unix timestamp>,
  "exp": <unix timestamp>,
  "jti": <random 128-bit base64url>,
  "trust_domain": <optional>,
  "cnf": { "jwk": {"kty":"EC","crv":"P-256","x":"...","y":"...","alg":"ES256"} }
}
Signature: ES256 with IdP's private key
```

### Workload Proof Token (WPT) — `typ: application/wpt+jwt`

```
Header:  {"alg":"ES256","typ":"application/wpt+jwt"}
Payload: {
  "aud": [<target request URI>],
  "iat": <unix timestamp>,
  "exp": <unix timestamp>,           // default TTL: 5 minutes
  "jti": <random 128-bit base64url>, // unique per request
  "wth": <base64url(SHA-256(WIT))>   // binds WPT to a specific WIT
}
Signature: ES256 with workload's private key (same as cnf.jwk in WIT)
```

### SD-WIT (SD-JWT-VC) — `typ: wit+sd-jwt`

```
<JWT header+payload+signature>~<Disclosure1>~<Disclosure2>~...~

JWT header:  {"alg":"ES256","typ":"wit+sd-jwt"}
JWT payload: {
  "iss": <IdP issuer URI>,
  "aud": [<optional audiences>],   // always visible
  "iat": <unix timestamp>,
  "exp": <unix timestamp>,
  "jti": <random>,
  "cnf": {"jwk": {...}},           // always visible
  "_sd_alg": "sha-256",
  "_sd": [<hash1>, <hash2>, ...]   // SHA-256 hashes of selective disclosures
}
Each Disclosure: base64url(JSON(["<16-byte-salt>", "<claim_name>", <value>]))
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Workload authentication** | WIT/SD-WIT signed by trusted IdP; relying party validates via JWKS |
| **Proof of key possession** | WPT signed with the workload's private key; public key in `cnf.jwk` |
| **Request binding** | WPT `aud` must equal the full request URI |
| **Token binding** | WPT `wth` = SHA-256(WIT); the two tokens are cryptographically linked |
| **Replay protection** | WPT `jti` tracked in-memory per validator instance |
| **Transport identity** | mTLS with X.509 URI SAN (`spiffe://` or `wimse://` scheme) |
| **Algorithm agility** | Restricted to ES256; other algorithms are rejected at parse time |
| **Forward secrecy** | TLS 1.3 minimum enforced on all connections |
| **Short-lived proofs** | WPT TTL defaults to 5 minutes |
| **Selective disclosure** | SD-WIT hides claim values behind SHA-256 hashes; verifier cannot learn undisclosed claims |
| **Disclosure integrity** | Every disclosure hash must appear in `_sd`; injected disclosures are rejected |

---

## Deployment

### Deployment Options Comparison

| Option | mTLS | Complexity | Cost estimate | Best for |
|---|---|---|---|---|
| **Local** | ✓ in-process | Minimal | Free | Development, unit testing |
| **VMs (GCP + AWS)** | ✓ native | Low | ~$5/month | PoC demos, cross-cloud testing |
| **Kubernetes** | ✓ via cert-manager or SPIRE | Medium | Cluster cost | Production-like staging |
| **Cloud Run + Lambda** | Requires L4 LB for mTLS | Low (managed) | Pay-per-use | Serverless (with caveats) |

---

### Local Development

#### Phase 2 — IdP only

```bash
# The --issuer flag sets the iss claim. Use the server's own URL so workloads
# can use the same value without extra configuration.
go run ./cmd/idp --trust-domain cloud-a.example --issuer http://localhost:8080 --port 8080

curl -s localhost:8080/.well-known/jwks.json | jq .
curl -s localhost:8080/health
```

#### Phase 3 — Workload A → Workload B (plain HTTP, no mTLS)

```bash
# Terminal 1
go run ./cmd/idp --trust-domain cloud-a.example --issuer http://localhost:8080 --port 8080

# Terminal 2
go run ./cmd/workload-b --idp http://localhost:8080 --issuer http://localhost:8080 --port 9001

# Terminal 3
go run ./cmd/workload-a --idp http://localhost:8080 --target http://localhost:9001 --port 9000

# Terminal 4
curl -s localhost:9000/call-b | jq .
# → {"caller":"spiffe://cloud-a.example/workload-a","echo":"ok"}
```

#### Phase 3 — with local mTLS

```bash
# Generate CA and workload certificates
go run ./cmd/gen-ca   --trust-domain cloud-a.example --cert-out /tmp/ca.crt --key-out /tmp/ca.key
go run ./cmd/gen-cert --uri spiffe://cloud-a.example/workload-a \
  --ca-cert /tmp/ca.crt --ca-key /tmp/ca.key \
  --cert-out /tmp/wl-a.crt --key-out /tmp/wl-a.key --ip 127.0.0.1
go run ./cmd/gen-cert --uri spiffe://cloud-b.example/workload-b \
  --ca-cert /tmp/ca.crt --ca-key /tmp/ca.key \
  --cert-out /tmp/wl-b.crt --key-out /tmp/wl-b.key --ip 127.0.0.1 --dns localhost

# Terminal 1
go run ./cmd/idp --trust-domain cloud-a.example --issuer http://localhost:8080

# Terminal 2 — Workload B listens on 9443 with mTLS when cert files are provided
go run ./cmd/workload-b \
  --idp http://localhost:8080 --issuer http://localhost:8080 \
  --ca-cert /tmp/ca.crt --cert-file /tmp/wl-b.crt --key-file /tmp/wl-b.key \
  --tls-port 9443

# Terminal 3 — Workload A uses mTLS client cert to connect to B
go run ./cmd/workload-a \
  --idp http://localhost:8080 --target https://localhost:9443 --port 9000 \
  --ca-cert /tmp/ca.crt --cert-file /tmp/wl-a.crt --key-file /tmp/wl-a.key

curl -s localhost:9000/call-b | jq .
```

#### Phase 4 — Cross-domain exchange

```bash
# Terminal 1 — IdP-A
go run ./cmd/idp --trust-domain cloud-a.example --issuer http://localhost:8080 --port 8080

# Terminal 2 — IdP-B
go run ./cmd/idp --trust-domain cloud-b.example --issuer http://localhost:8081 --port 8081

# Terminal 3 — Token Exchange bridges A → B
go run ./cmd/token-exchange \
  --source-idp http://localhost:8080 --source-issuer http://localhost:8080 \
  --target-issuer http://localhost:8081 --port 8090

# Terminal 4 — Workload B trusts IdP-B
go run ./cmd/workload-b --idp http://localhost:8081 --issuer http://localhost:8081 --port 9001
```

---

### VM Deployment (GCP + AWS)

This path runs the full PoC across two real cloud providers with native mTLS — no PaaS TLS termination.

```
GCP e2-micro (us-central1)          AWS t3.micro (us-east-1)
├── cmd/idp (port 8080)             └── cmd/workload-b (port 9443, mTLS)
├── cmd/workload-a (port 9000)
└── cmd/token-exchange (port 8090)
```

The CA key **never leaves your laptop**. Only the CA cert and workload certs (with VM IP SANs) are uploaded to the VMs.

#### Prerequisites

- `gcloud` CLI authenticated (`gcloud auth login`)
- `aws` CLI configured (`aws configure`)
- Terraform ≥ 1.5 in PATH
- An existing AWS EC2 key pair (`aws ec2 describe-key-pairs`)

#### Quick start

```bash
# 1. Configure Terraform variables
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# Edit: gcp_project, aws_key_pair_name, ssh_public_key_path

# 2. Run the master provisioning script
AWS_KEY=~/.ssh/your-aws-key.pem infra/scripts/provision.sh
# This script:
#   - Builds gen-ca and gen-cert locally
#   - Generates a CA (once — never overwritten)
#   - Runs terraform apply → gets GCP_IP + AWS_IP
#   - Generates workload certs with actual IP SANs
#   - Cross-compiles Linux/amd64 binaries
#   - Uploads binaries + certs via gcloud scp / scp
#   - Writes env files on each VM with correct IPs
#   - Starts systemd services

# 3. Run end-to-end smoke tests
infra/scripts/e2e-test.sh
```

#### Key design decisions for VMs

- **Systemd services** wait for binaries via `ExecStartPre` loop — services enable at boot, start when `provision.sh` uploads the binary
- **IdP signing key** persists via `--key-file /opt/wimse/keys/idp-signing.key` — the key survives VM restarts without rotating tokens
- **Firewall rules** open only the needed ports (`8080`, `8090`, `9000` on GCP; `9443` on AWS)
- **CA key stays local** — only certs are distributed; a compromised VM cannot issue new workload certs

---

### Kubernetes

Kubernetes introduces native workload identity primitives that complement WIMSE. The recommended pattern layers them:

```
K8s ServiceAccount JWT   → authenticates the pod to the WIMSE IdP
WIMSE WIT                → application-layer identity (cross-cluster, cross-cloud)
mTLS (cert-manager)      → transport-layer identity
```

#### Option A: cert-manager (simplest)

cert-manager manages workload certificates automatically, replacing the manual `gen-cert` workflow.

```yaml
# 1. Create a CA secret from the CA generated by gen-ca
kubectl create secret tls wimse-ca --cert=infra/ca/ca.crt --key=infra/ca/ca.key -n wimse

# 2. Issuer backed by that CA
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: { name: wimse-ca, namespace: wimse }
spec:
  ca:
    secretName: wimse-ca

# 3. Certificate for workload-b
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: workload-b-cert, namespace: wimse }
spec:
  secretName: workload-b-tls
  issuerRef: { name: wimse-ca }
  uris: ["spiffe://cloud-b.example/workload-b"]
  duration: 24h
  renewBefore: 1h
```

```yaml
# 4. workload-b Deployment mounts the cert
apiVersion: apps/v1
kind: Deployment
metadata: { name: workload-b, namespace: wimse }
spec:
  template:
    spec:
      containers:
      - name: workload-b
        image: wimse/workload-b:latest
        args:
        - --idp=http://wimse-idp:8080
        - --issuer=https://idp.cloud-a.example
        - --ca-cert=/certs/ca.crt
        - --cert-file=/certs/tls.crt
        - --key-file=/certs/tls.key
        - --tls-port=9443
        volumeMounts:
        - name: tls, mountPath: /certs
      volumes:
      - name: tls
        secret: { secretName: workload-b-tls }
```

```yaml
# 5. Service — use NodePort or LoadBalancer (NOT ClusterIP with Ingress)
# for mTLS passthrough (Ingress controllers terminate TLS)
apiVersion: v1
kind: Service
metadata: { name: workload-b, namespace: wimse }
spec:
  type: LoadBalancer                # L4 — preserves mTLS to pod
  selector: { app: workload-b }
  ports:
  - name: mtls, port: 9443, targetPort: 9443, protocol: TCP
```

#### Option B: SPIRE (production-grade)

[SPIFFE/SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) provides automatic SVID (certificate) rotation and integrates with cloud-native attestation plugins (AWS IID, GCE metadata, Kubernetes node/pod selectors).

```
SPIRE Agent (DaemonSet)
  ├── Attests pod identity via K8s node + pod selector
  ├── Issues X.509 SVIDs (replaces gen-cert + cert-manager)
  └── Rotates certs automatically (no cert-manager needed)

SPIRE Server
  └── Issues SVIDs signed by the SPIRE CA
      └── WIMSE IdP trusts the SPIRE CA for mTLS client cert validation
```

With SPIRE, workload certificates are mounted via the SPIFFE Workload API (Unix domain socket or CSI driver), eliminating Kubernetes Secrets for private keys.

#### GKE-specific: Workload Identity Federation

On GKE, pods can use Google-signed service account tokens to authenticate to the WIMSE IdP instead of pre-shared secrets:

```
K8s Pod (service account: wimse-workload-a)
  │
  ├── Projected volume: K8s ServiceAccount token (audience: wimse-idp)
  │
  └── POST /wit/issue  {sa_token: <k8s_token>}
        └── IdP validates SA token via K8s TokenReview API
            └── Issues WIT for spiffe://cloud-a.example/workload-a
```

This eliminates the `AllowedSubjects` allow-list in favour of K8s RBAC — only pods with the right ServiceAccount can obtain a WIT.

#### EKS-specific: IRSA (IAM Roles for Service Accounts)

The same pattern applies on EKS: IRSA tokens can authenticate pods to the WIMSE IdP via OIDC federation, then the IdP issues WITs. This avoids managing long-lived credentials for IdP authentication.

---

### Cloud Provider Managed

PaaS offerings (Cloud Run, AWS Lambda, Azure Container Apps) **terminate TLS before the application process** — native mTLS is not possible. Options:

| Approach | mTLS preserved | Notes |
|---|---|---|
| **L4 (TCP) Load Balancer** | Yes | GCP Network LB / AWS NLB in TCP mode; pods must have public IPs or use NEGs |
| **Service mesh sidecar** | Yes (at sidecar) | Istio / Linkerd handles mTLS; app-layer WIT+WPT still applies |
| **Disable mTLS, WIT+WPT only** | N/A | Valid for environments where transport security is provided by VPC + service mesh |
| **GKE / EKS on VMs** | Yes | Managed K8s with L4 LB is the easiest production path |

#### Cloud Run + WIT+WPT (no mTLS)

If mTLS is not required (e.g. intra-VPC traffic is trusted at the network level), Cloud Run works directly:

```bash
# Deploy IdP to Cloud Run (ephemeral key — for persistent key, mount a Cloud Storage bucket)
gcloud run deploy wimse-idp \
  --image wimse/idp:latest \
  --set-env-vars IDP_TRUST_DOMAIN=cloud-a.example,IDP_ISSUER=https://idp.cloud-a.example \
  --allow-unauthenticated --region us-central1

# Deploy workload-b (no --cert-file → plain HTTP on 9001, no mTLS)
gcloud run deploy wimse-workload-b \
  --image wimse/workload-b:latest \
  --set-env-vars IDP_URL=https://wimse-idp-xxx.run.app,IDP_ISSUER=https://idp.cloud-a.example
```

WIT + WPT validation still works in full; only the mTLS transport layer is absent.

#### GCP + AWS with L4 Load Balancers (mTLS preserved)

For production deployments that need mTLS across clouds:

```bash
# GCP: Network Load Balancer (TCP mode) in front of GKE pods
gcloud compute forwarding-rules create wimse-wb \
  --load-balancing-scheme=EXTERNAL \
  --ports=9443 \
  --backend-service=wimse-workload-b \
  --ip-protocol=TCP   # TCP mode = no TLS termination

# AWS: Network Load Balancer with TCP listener
aws elbv2 create-listener \
  --load-balancer-arn $NLB_ARN \
  --protocol TCP --port 9443 \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN
```

---

## Design Decisions

**Single key pair for mTLS and WIT `cnf.jwk`**
Each workload uses one EC P-256 key pair for both its X.509 certificate (mTLS) and the `cnf.jwk` claim in its WIT (application-layer). This co-locates cryptographic material and keeps key management simple.

**`Alg: "ES256"` always set in JWK**
The WIMSE workload-creds draft requires the `alg` field in `cnf.jwk`. Validators enforce `WithValidMethods([]string{"ES256"})`, so algorithm substitution attacks are impossible.

**Left-padding X/Y to 32 bytes**
RFC 7518 §6.2 requires EC coordinates padded to the full key size. When a coordinate's `big.Int` has a leading zero byte, Go's `Bytes()` omits it. `PublicKeyToJWK` explicitly left-pads to 32 bytes before base64url encoding.

**WPT TTL: zero means default, negative means expired**
`TTL: 0` in `Generate` uses the 5-minute default. A negative value (e.g. `-time.Second`) produces an already-expired token for tests. The check is `if ttl == 0` rather than `if ttl <= 0`.

**`wpt.Validator` is stateful — one per server**
The replay store (`map[string]time.Time` behind a mutex) lives in the `Validator` instance. It maps each JTI to the token's expiry time. On every check, entries whose expiry has passed are swept out first, bounding memory to JTIs within their validity window.

**`peekIssuer` in token exchange decodes without verification**
The exchange handler looks up the correct public key *before* verifying the signature. It decodes the base64url payload, extracts `iss`, finds the key, and only then calls the full validator.

**WPT signature tamper tests replace the entire signature segment**
ECDSA-P256 signatures encode to 86 base64url characters. The last character encodes only 2 bits of data; flipping just the last char may produce the same decoded bytes. Tests replace the entire third JWT segment with 86 zero characters to guarantee a mismatch.

**IdP signing key persistence via `--key-file`**
If `--key-file` points to an absent file, the IdP generates a new key and saves it. If the file exists, it is loaded. Without `--key-file`, an ephemeral key is used (valid for local testing; tokens become unverifiable after restart).

**SD-WIT wth binding uses the full token (all disclosures)**
The WPT `wth` hashes the complete SD-JWT string the Holder possesses (all disclosures). This means the WPT is bound to a specific presentation. If the Holder generates different filtered presentations for different services, each gets a different WPT. This is the correct security model: the proof-of-possession is scoped to what was actually sent.

**CA private key never sent to VMs**
The `provision.sh` script generates all workload certificates locally using `gen-cert`, then uploads only the cert PEM (and workload private key) to the target VM. The CA private key stays on the operator's machine.
