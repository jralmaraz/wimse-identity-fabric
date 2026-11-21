# Local multi-cloud WIMSE lab

Runs a cross-cloud microservice call chain entirely in local Docker containers, with
[Floci](https://floci.io) emulating AWS and GCP. Every transaction appears live in an
observer UI with its decoded tokens and verification steps.

```bash
make lab-up            # docker compose up --build -d
open http://localhost:8080
make lab-down
```

No Docker? `make lab-local` runs the same services as plain processes. Attestation then
uses dev-only join tokens and the cloud steps are skipped. The WIMSE flow is identical.

## What it demonstrates

```
                 aws-vpc  (trust domain aws.wimse.local)          gcp-vpc  (trust domain gcp.wimse.local)
   ┌──────────────────────────────────────────────────┐   ┌───────────────────────────────────────────┐
   │  floci-aws :4566   STS · IAM · DynamoDB           │   │  floci-gcp :4588   IAM · STS · Cloud KMS   │
   │  issuer-aws        WIT · Txn-Token · RFC 8693     │   │  issuer-gcp        WIT · RFC 8693           │
   │  orders  (entry)   ledger                         │   │  payments                                   │
   └─────────┬───────────────▲────────────────────────┘   └───────▲──────────────────┬─────────────────┘
             │               │            interconnect           │                  │
             └───────────────┼───────── WIT+WPT+Txn-Token ───────┘                  │
                             └───────────────────── WIT+WPT+Txn-Token ──────────────┘
```

One `POST /checkout` produces this chain (all of it visible in the observer):

| # | From → to | What happens | Spec |
|---|---|---|---|
| 0 | workload → own issuer | **Attestation.** orders/ledger present a presigned `sts:GetCallerIdentity` URL for their task role. The issuer executes it against Floci STS and matches the role. payments is identified by Docker container label **and** its GCP service account. The request itself is a JWS signed by the workload key, so the issuer binds a key the caller provably holds into `cnf.jwk`. | workload-creds §5 |
| 1 | client → orders | End-user request at the edge (user authentication is out of scope) | — |
| 2 | orders → issuer-aws | orders authenticates with WIT + WPT and gets a **Txn-Token** (`sub`=user, `rctx.req_wl`=orders, `azd`=purchase details) | oauth-transaction-tokens |
| 3 | orders (AWS) → payments (GCP) | `Workload-Identity-Token` + `Authorization: WPT` + `Txn-Token`. payments verifies the **AWS** WIT through its federated trust bundle, plus the WPT (`aud`, `wth`, `tth`, `jti`), the Txn-Token and its own policy | workload-creds-02, wpt-02 |
| 4 | payments → issuer-gcp → Floci GCP | RFC 8693 exchange: WIT + WPT → 5-minute JWT (aud = WIF provider) → GCP STS → federated access token → **Cloud KMS encrypt** | RFC 8693, arch §token exchange |
| 5 | payments (GCP) → ledger (AWS) | Same headers, now with the **GCP** WIT; the Txn-Token is forwarded unchanged and bound with `tth` | wpt-02 |
| 6 | ledger → issuer-aws → Floci AWS | RFC 8693 exchange → `AssumeRoleWithWebIdentity` (role `ledger-data`, trusts issuer-aws as OIDC provider) → **DynamoDB PutItem** | RFC 8693 |

The WIT is never handed to a cloud as a bearer token. Cloud federation always goes through
the issuer's token-exchange endpoint, which mints an audience-restricted JWT.

### Attack suite

**Run attack suite** in the UI (or `POST :8080/api/run/attacks`) replays and forges tokens
captured from the last real orders → payments call:

| Attack | Expected | Why it fails |
|---|---|---|
| Stolen WIT used as bearer token | 401 | no `Authorization: WPT` proof |
| Exact replay of WIT + WPT | 401 | `jti` already seen |
| Captured proof sent to ledger | 401 | WPT `aud` is payments' URI |
| Stolen WIT + attacker-signed WPT | 401 | signature ≠ key in `cnf.jwk` |
| Txn-Token amount changed | 401 | `tth` no longer matches |
| WIT for `orders` minted by a rogue key | 400 | not signed by aws.wimse.local anchors |
| WIT from `evil.example` | 400 | trust domain not federated |
| orders calls ledger directly | 403 | authenticated, but ledger's policy only allows payments |

Status codes follow the drafts: WIT errors → 400 (workload-creds §5.2); WPT errors → 401
with `WWW-Authenticate: WPT` (wpt-02); policy denials → 403. Bodies are RFC 9457 problem
details that list every check.

## Components

| Path | Role |
|---|---|
| `cmd/lab-issuer` | Per-trust-domain issuer: `/attest`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/txn-token`, `/token` (RFC 8693). Uses `pkg/wit` and `pkg/txntoken`. |
| `cmd/lab-workload` | orders / payments / ledger (`ROLE=`). |
| `cmd/lab-observer` | Live UI (SSE) and attack runner. **Receives raw tokens: lab only.** |
| `cmd/lab-bootstrap` | Seeds Floci: IAM task roles, OIDC provider, `ledger-data` role, DynamoDB table, GCP service account, KMS key. |
| `internal/lab` | Trust bundle (trust domain → anchors, never discovered from `iss`), `Verifier` (net/http), `Agent` (attest, WPT per request, Txn-Token, exchange), event emitter. |
| `internal/lab/attest` | Attestors `aws-sts`, `docker`, `gcp-iam`, `join-token`, combined with plans like `ATTESTORS=docker+gcp-iam,docker`. |
| `internal/lab/cloud` | Dependency-free SigV4 (tested against the AWS published vectors), STS/IAM/DynamoDB and GCP IAM/STS/KMS clients. |
| `config/*-registrations.json` | Issuer-side workload registrations (like SPIRE entries). |

## Caveats

- **Emulator fidelity.** The cloud clients speak the real wire protocols and were tested
  against a mock that answers in AWS and GCP formats, but not against Floci itself.
  Floci documents real SigV4/IAM enforcement only for some services, so trust policies on
  `ledger-data` may not be enforced. The issuer's own checks (attestation, WIT, WPT, policy)
  don't depend on Floci. If a Floci API differs, the observer shows that step in red and
  the WIMSE flow carries on. `issuer-aws` falls back to Docker attestation, and GCP base
  URLs can be overridden with `GCP_IAM_URL` / `GCP_STS_URL` / `GCP_KMS_URL`.
- **Docker socket.** Issuers mount `/var/run/docker.sock` read-only and run as root for the
  Docker attestor. That's fine on a laptop and must not be copied anywhere else.
- **Draft churn.** The lab tracks workload-creds-02 and wpt-02 through `pkg/wit` and
  `pkg/wpt`. When those packages change, the lab follows.
