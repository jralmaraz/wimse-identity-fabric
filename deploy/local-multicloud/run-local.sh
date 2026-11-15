#!/usr/bin/env bash
# run-local.sh — run the WIMSE multi-cloud lab as plain processes (no Docker,
# no emulators). Attestation falls back to dev-only join tokens and cloud
# steps are skipped; the WIMSE flow (WIT, WPT, Txn-Token, federation,
# token exchange, attacks) is identical to the compose stack.
#
#   ./deploy/local-multicloud/run-local.sh         # build, start, run checkout + attacks, keep running
#   BIN=/path/to/prebuilt ./run-local.sh           # use prebuilt binaries
#   open http://localhost:8080
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CFG="$ROOT/deploy/local-multicloud/config"
BIN="${BIN:-$ROOT/bin}"
LOGS="${LOGS:-$(mktemp -d)}"
mkdir -p "$LOGS"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  mkdir -p "$BIN"
  for c in lab-issuer lab-workload lab-observer; do (cd "$ROOT" && go build -o "$BIN/$c" "./cmd/$c"); done
fi

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

start() { # name, binary, env...
  local name=$1 bin=$2; shift 2
  env "$@" "$BIN/$bin" >"$LOGS/$name.log" 2>&1 &
  PIDS+=($!)
}

DOMAINS="aws.wimse.local=http://localhost:8081,gcp.wimse.local=http://localhost:8082"
COMMON=(OBSERVER_URL=http://localhost:8080 CLOUD=off)

start observer lab-observer PORT=8080 ORDERS_URL=http://localhost:9001 PAYMENTS_URL=http://localhost:9002 LEDGER_URL=http://localhost:9003
start issuer-aws lab-issuer "${COMMON[@]}" PORT=8081 TRUST_DOMAIN=aws.wimse.local PUBLIC_URL=http://localhost:8081 SERVICE_NAME=issuer-aws \
  TRUST_DOMAINS=aws.wimse.local=http://localhost:8081 REGISTRATIONS_FILE="$CFG/aws-registrations.json" ATTESTORS=join-token \
  TXN_AUDIENCE=urn:wimse-lab:shop EXCHANGE_AUDIENCES=sts.amazonaws.com
start issuer-gcp lab-issuer "${COMMON[@]}" PORT=8082 TRUST_DOMAIN=gcp.wimse.local PUBLIC_URL=http://localhost:8082 SERVICE_NAME=issuer-gcp \
  TRUST_DOMAINS=gcp.wimse.local=http://localhost:8082 REGISTRATIONS_FILE="$CFG/gcp-registrations.json" ATTESTORS=join-token \
  EXCHANGE_AUDIENCES=//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/wimse-lab/providers/issuer-gcp
sleep 1
start orders lab-workload "${COMMON[@]}" ROLE=orders PORT=9001 SELF_URL=http://localhost:9001 ISSUER_URL=http://localhost:8081 \
  TRUST_DOMAINS="$DOMAINS" EVIDENCE=join-token JOIN_TOKEN=dev-only-orders-6f1d \
  PAYMENTS_URL=http://localhost:9002 LEDGER_URL=http://localhost:9003
start payments lab-workload "${COMMON[@]}" ROLE=payments PORT=9002 SELF_URL=http://localhost:9002 ISSUER_URL=http://localhost:8082 \
  TRUST_DOMAINS="$DOMAINS" EVIDENCE=join-token JOIN_TOKEN=dev-only-payments-27be \
  POLICY=/charge=spiffe://aws.wimse.local/ns/shop/sa/orders TXN_ISSUER=http://localhost:8081 TXN_AUDIENCE=urn:wimse-lab:shop \
  LEDGER_URL=http://localhost:9003
start ledger lab-workload "${COMMON[@]}" ROLE=ledger PORT=9003 SELF_URL=http://localhost:9003 ISSUER_URL=http://localhost:8081 \
  TRUST_DOMAINS="$DOMAINS" EVIDENCE=join-token JOIN_TOKEN=dev-only-ledger-93ac \
  POLICY=/entries=spiffe://gcp.wimse.local/ns/shop/sa/payments TXN_ISSUER=http://localhost:8081 TXN_AUDIENCE=urn:wimse-lab:shop \
  EXPECT_ORIGIN=spiffe://aws.wimse.local/ns/shop/sa/orders

echo "logs: $LOGS"
for i in $(seq 1 30); do curl -sf localhost:9001/health >/dev/null && curl -sf localhost:9003/health >/dev/null && break; sleep 0.5; done
sleep 1

echo "==> checkout"
curl -s -X POST localhost:9001/checkout -H 'Content-Type: application/json' \
  -d '{"user":"alice@example.com","item":"wimse-handbook","amount":"42.00"}'
echo
echo "==> attack suite"
curl -s -X POST localhost:8080/api/run/attacks
echo
if [[ -n "${EXIT_AFTER_DEMO:-}" ]]; then exit 0; fi
echo "Observer: http://localhost:8080  (Ctrl-C to stop)"
wait
