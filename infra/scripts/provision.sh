#!/usr/bin/env bash
# provision.sh — Build, generate credentials, provision VMs, and start services.
#
# Prerequisites:
#   - go ≥ 1.21 in PATH
#   - terraform ≥ 1.5 in PATH
#   - gcloud CLI authenticated (gcloud auth login)
#   - AWS CLI configured (aws configure)
#   - terraform.tfvars set in infra/terraform/ with gcp_project and aws_key_pair_name
#   - SSH key pair whose public key matches ssh_public_key_path variable
#
# Usage:
#   cd infra/scripts
#   AWS_KEY=~/.ssh/my-aws-key.pem ./provision.sh
#
# Environment variables:
#   AWS_KEY   — path to the .pem file for the AWS EC2 key pair  (required)
#   GCP_ZONE  — GCP zone (default: us-central1-a)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$REPO_ROOT/infra"
TF_DIR="$INFRA/terraform"
BIN_DIR="$INFRA/bin"
CA_DIR="$INFRA/ca"
CERT_DIR="$INFRA/certs"

GCP_ZONE="${GCP_ZONE:-us-central1-a}"
AWS_KEY="${AWS_KEY:-}"

if [[ -z "$AWS_KEY" ]]; then
  echo "ERROR: AWS_KEY must be set to the path of your AWS .pem key file" >&2
  exit 1
fi

IDP_TRUST_DOMAIN="cloud-a.example"
IDP_ISSUER="https://idp.${IDP_TRUST_DOMAIN}"
WORKLOAD_A_SUBJECT="spiffe://${IDP_TRUST_DOMAIN}/workload-a"
WORKLOAD_B_URI="spiffe://cloud-b.example/workload-b"
TARGET_IDP_ISSUER="https://idp.cloud-b.example"

# ── Step 1: Build local utilities ────────────────────────────────────────────
echo "==> Building local utilities..."
mkdir -p "$BIN_DIR/local"
go build -o "$BIN_DIR/local/gen-ca"   "$REPO_ROOT/cmd/gen-ca"
go build -o "$BIN_DIR/local/gen-cert" "$REPO_ROOT/cmd/gen-cert"
echo "    gen-ca and gen-cert built"

# ── Step 2: Generate CA (once — never overwrite) ──────────────────────────────
echo "==> Generating CA..."
mkdir -p "$CA_DIR" "$CERT_DIR"
if [[ ! -f "$CA_DIR/ca.crt" ]]; then
  "$BIN_DIR/local/gen-ca" \
    --trust-domain "$IDP_TRUST_DOMAIN" \
    --cert-out "$CA_DIR/ca.crt" \
    --key-out  "$CA_DIR/ca.key"
  echo "    CA generated at $CA_DIR"
else
  echo "    CA already exists, skipping (delete $CA_DIR to rotate)"
fi

# ── Step 3: Terraform apply ───────────────────────────────────────────────────
echo "==> Running terraform apply..."
cd "$TF_DIR"
terraform init -upgrade -input=false
terraform apply -auto-approve -input=false
GCP_IP="$(terraform output -raw gcp_ip)"
AWS_IP="$(terraform output -raw aws_ip)"
echo "    GCP VM IP: $GCP_IP"
echo "    AWS VM IP: $AWS_IP"
cd "$REPO_ROOT"

# ── Step 4: Generate workload certs (with actual IP SANs) ─────────────────────
echo "==> Generating workload certificates..."
"$BIN_DIR/local/gen-cert" \
  --uri      "$WORKLOAD_A_SUBJECT" \
  --ca-cert  "$CA_DIR/ca.crt" \
  --ca-key   "$CA_DIR/ca.key" \
  --cert-out "$CERT_DIR/workload-a.crt" \
  --key-out  "$CERT_DIR/workload-a.key" \
  --ip       "127.0.0.1,${GCP_IP}"

"$BIN_DIR/local/gen-cert" \
  --uri      "$WORKLOAD_B_URI" \
  --ca-cert  "$CA_DIR/ca.crt" \
  --ca-key   "$CA_DIR/ca.key" \
  --cert-out "$CERT_DIR/workload-b.crt" \
  --key-out  "$CERT_DIR/workload-b.key" \
  --ip       "127.0.0.1,${AWS_IP}" \
  --dns      "localhost"
echo "    Workload certs generated"

# ── Step 5: Cross-compile Linux/amd64 binaries ────────────────────────────────
echo "==> Cross-compiling Linux binaries..."
mkdir -p "$BIN_DIR/linux"
for cmd in idp workload-a workload-b token-exchange; do
  GOOS=linux GOARCH=amd64 go build -o "$BIN_DIR/linux/$cmd" "$REPO_ROOT/cmd/$cmd"
  echo "    Built $cmd"
done

# ── Step 6: Upload to GCP VM ──────────────────────────────────────────────────
echo "==> Uploading to GCP VM (${GCP_IP})..."

gcp_scp() {
  gcloud compute scp --zone="$GCP_ZONE" --quiet "$@" "debian@wimse-gcp:$1"
}

# Wait for SSH
echo "    Waiting for GCP SSH..."
until gcloud compute ssh --zone="$GCP_ZONE" --quiet debian@wimse-gcp --command="true" 2>/dev/null; do
  sleep 5
done

gcloud compute scp --zone="$GCP_ZONE" --quiet \
  "$BIN_DIR/linux/idp" \
  "$BIN_DIR/linux/workload-a" \
  "$BIN_DIR/linux/token-exchange" \
  "debian@wimse-gcp:/tmp/"

gcloud compute scp --zone="$GCP_ZONE" --quiet \
  "$CA_DIR/ca.crt" \
  "$CERT_DIR/workload-a.crt" \
  "debian@wimse-gcp:/tmp/"

gcloud compute scp --zone="$GCP_ZONE" --quiet \
  "$CERT_DIR/workload-a.key" \
  "debian@wimse-gcp:/tmp/"

# Install files and write env files on GCP VM
gcloud compute ssh --zone="$GCP_ZONE" --quiet debian@wimse-gcp --command="$(cat <<SCRIPT
set -euo pipefail
sudo install -m 755 /tmp/idp          /opt/wimse/idp
sudo install -m 755 /tmp/workload-a   /opt/wimse/workload-a
sudo install -m 755 /tmp/token-exchange /opt/wimse/token-exchange
sudo install -m 644 /tmp/ca.crt       /opt/wimse/certs/ca.crt
sudo install -m 644 /tmp/workload-a.crt /opt/wimse/certs/workload-a.crt
sudo install -m 600 /tmp/workload-a.key /opt/wimse/keys/workload-a.key
rm -f /tmp/idp /tmp/workload-a /tmp/token-exchange /tmp/ca.crt /tmp/workload-a.crt /tmp/workload-a.key

# Write env files
sudo tee /opt/wimse/idp.env > /dev/null <<ENV
IDP_TRUST_DOMAIN=${IDP_TRUST_DOMAIN}
IDP_ISSUER=${IDP_ISSUER}
IDP_PORT=8080
ENV

sudo tee /opt/wimse/workload-a.env > /dev/null <<ENV
IDP_URL=http://127.0.0.1:8080
TARGET_URL=https://${AWS_IP}:9443
WORKLOAD_SUBJECT=${WORKLOAD_A_SUBJECT}
WORKLOAD_A_PORT=9000
ENV

sudo tee /opt/wimse/token-exchange.env > /dev/null <<ENV
SOURCE_IDP_URL=http://127.0.0.1:8080
SOURCE_IDP_ISSUER=${IDP_ISSUER}
TARGET_IDP_ISSUER=${TARGET_IDP_ISSUER}
EXCHANGE_PORT=8090
ENV

sudo systemctl daemon-reload
sudo systemctl restart wimse-idp wimse-workload-a wimse-token-exchange
SCRIPT
)"
echo "    GCP VM configured and services started"

# ── Step 7: Upload to AWS VM ──────────────────────────────────────────────────
echo "==> Uploading to AWS VM (${AWS_IP})..."

aws_ssh() { ssh -i "$AWS_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "ec2-user@${AWS_IP}" "$@"; }
aws_scp() { scp -i "$AWS_KEY" -o StrictHostKeyChecking=no "$@" "ec2-user@${AWS_IP}:/tmp/"; }

echo "    Waiting for AWS SSH..."
until aws_ssh "true" 2>/dev/null; do sleep 5; done

aws_scp "$BIN_DIR/linux/workload-b" "$CA_DIR/ca.crt" "$CERT_DIR/workload-b.crt" "$CERT_DIR/workload-b.key"

aws_ssh "$(cat <<SCRIPT
set -euo pipefail
sudo install -m 755 /tmp/workload-b    /opt/wimse/workload-b
sudo install -m 644 /tmp/ca.crt        /opt/wimse/certs/ca.crt
sudo install -m 644 /tmp/workload-b.crt /opt/wimse/certs/workload-b.crt
sudo install -m 600 /tmp/workload-b.key /opt/wimse/keys/workload-b.key
rm -f /tmp/workload-b /tmp/ca.crt /tmp/workload-b.crt /tmp/workload-b.key

sudo tee /opt/wimse/workload-b.env > /dev/null <<ENV
IDP_URL=http://${GCP_IP}:8080
IDP_ISSUER=${IDP_ISSUER}
WORKLOAD_B_TLS_PORT=9443
ENV

sudo systemctl daemon-reload
sudo systemctl restart wimse-workload-b
SCRIPT
)"
echo "    AWS VM configured and service started"

# ── Step 8: Wait for services to be healthy ───────────────────────────────────
echo "==> Waiting for services to be ready..."

wait_http() {
  local url="$1" label="$2"
  echo -n "    $label "
  for i in $(seq 1 30); do
    if curl -sf "$url" > /dev/null 2>&1; then
      echo "OK"
      return 0
    fi
    echo -n "."
    sleep 3
  done
  echo " TIMEOUT"
  return 1
}

wait_http "http://${GCP_IP}:8080/.well-known/jwks.json" "IdP JWKS"
wait_http "http://${GCP_IP}:9000/call-b"                "Workload A → B"
wait_http "http://${GCP_IP}:8090/health"                "Token Exchange /health"

echo ""
echo "==> Deployment complete!"
echo ""
echo "  IdP JWKS:       http://${GCP_IP}:8080/.well-known/jwks.json"
echo "  Workload A→B:   curl http://${GCP_IP}:9000/call-b"
echo "  Token Exchange: curl -X POST http://${GCP_IP}:8090/token/exchange \\"
echo "                    -H 'Content-Type: application/json' \\"
echo "                    -d '{\"token\":\"<WIT from IdP>\"}'"
