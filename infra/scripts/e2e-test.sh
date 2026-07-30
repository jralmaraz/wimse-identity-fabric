#!/usr/bin/env bash
# e2e-test.sh — Run end-to-end tests against deployed VMs.
# Run from the repo root after provision.sh completes.
set -euo pipefail

TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"

cd "$TF_DIR"
GCP_IP="$(terraform output -raw gcp_ip)"
AWS_IP="$(terraform output -raw aws_ip)"

IDP_URL="http://${GCP_IP}:8080"
WORKLOAD_A_URL="http://${GCP_IP}:9000"
EXCHANGE_URL="http://${GCP_IP}:8090"

PASS=0
FAIL=0

check() {
  local label="$1" expected="$2" actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo "  PASS  $label"
    ((PASS++))
  else
    echo "  FAIL  $label (expected to find: $expected)"
    echo "         got: $actual"
    ((FAIL++))
  fi
}

echo "==> WIMSE End-to-End Tests"
echo "    GCP: $GCP_IP  |  AWS: $AWS_IP"
echo ""

# ── Test 1: IdP JWKS endpoint ────────────────────────────────────────────────
echo "--- IdP ---"
JWKS=$(curl -sf "${IDP_URL}/.well-known/jwks.json")
check "JWKS contains EC key" '"kty":"EC"' "$JWKS"
check "JWKS has ES256 alg"   '"alg":"ES256"' "$JWKS"

# ── Test 2: IdP health ───────────────────────────────────────────────────────
HEALTH=$(curl -sf "${IDP_URL}/health")
check "IdP /health returns ok" "ok" "$HEALTH"

# ── Test 3: Issue WIT ────────────────────────────────────────────────────────
echo ""
echo "--- WIT issuance ---"
# Build a minimal JWK for the test (use the IdP's own public key for convenience)
TEST_JWK=$(echo "$JWKS" | python3 -c "import sys,json; keys=json.load(sys.stdin)['keys']; print(json.dumps(keys[0]))" 2>/dev/null || \
           echo '{"kty":"EC","crv":"P-256","x":"test","y":"test","alg":"ES256"}')

WIT_RESP=$(curl -sf -X POST "${IDP_URL}/wit/issue" \
  -H "Content-Type: application/json" \
  -d "{\"subject\":\"spiffe://cloud-a.example/e2e-test\",\"public_key\":${TEST_JWK}}" 2>&1 || true)
check "WIT issued"            '"token"' "$WIT_RESP"

# ── Test 4: Workload A → B call ───────────────────────────────────────────────
echo ""
echo "--- Workload-to-Workload (A → B via mTLS + WIT + WPT) ---"
CALL_B=$(curl -sf "${WORKLOAD_A_URL}/call-b" 2>&1 || true)
check "call-b returns caller sub"    "spiffe://"   "$CALL_B"
check "call-b returns echo response" '"echo"'       "$CALL_B"

# ── Test 5: Token Exchange ───────────────────────────────────────────────────
echo ""
echo "--- Token Exchange ---"
EXCH_HEALTH=$(curl -sf "${EXCHANGE_URL}/health" 2>&1 || true)
check "exchange /health" "ok" "$EXCH_HEALTH"

if echo "$WIT_RESP" | grep -q '"token"'; then
  TOKEN_A=$(echo "$WIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || \
            echo "$WIT_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
  EXCH_RESP=$(curl -sf -X POST "${EXCHANGE_URL}/token/exchange" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"${TOKEN_A}\"}" 2>&1 || true)
  check "exchange returns new token" '"token"' "$EXCH_RESP"
else
  echo "  SKIP  token exchange (WIT issuance failed)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "==> Results: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
