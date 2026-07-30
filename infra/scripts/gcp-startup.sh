#!/bin/bash
# GCP VM startup script — runs as root at first boot.
# Creates directories and systemd service stubs that wait for binaries
# to be uploaded by provision.sh before starting.
set -euo pipefail

WIMSE_DIR=/opt/wimse

mkdir -p "$WIMSE_DIR/certs" "$WIMSE_DIR/keys"
chmod 700 "$WIMSE_DIR/keys"

# ── IdP service ──────────────────────────────────────────────────────────────
cat > /etc/systemd/system/wimse-idp.service << 'EOF'
[Unit]
Description=WIMSE Identity Provider
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/wimse/idp.env
ExecStartPre=/bin/bash -c 'until [ -x /opt/wimse/idp ]; do sleep 2; done'
ExecStart=/opt/wimse/idp \
  --trust-domain ${IDP_TRUST_DOMAIN} \
  --issuer       ${IDP_ISSUER} \
  --port         ${IDP_PORT} \
  --key-file     /opt/wimse/keys/idp-signing.key
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── Workload A service ────────────────────────────────────────────────────────
cat > /etc/systemd/system/wimse-workload-a.service << 'EOF'
[Unit]
Description=WIMSE Workload A
After=wimse-idp.service
Requires=wimse-idp.service

[Service]
Type=simple
EnvironmentFile=/opt/wimse/workload-a.env
ExecStartPre=/bin/bash -c 'until [ -x /opt/wimse/workload-a ]; do sleep 2; done'
ExecStart=/opt/wimse/workload-a \
  --idp      ${IDP_URL} \
  --target   ${TARGET_URL} \
  --subject  ${WORKLOAD_SUBJECT} \
  --port     ${WORKLOAD_A_PORT} \
  --ca-cert  /opt/wimse/certs/ca.crt \
  --cert-file /opt/wimse/certs/workload-a.crt \
  --key-file  /opt/wimse/keys/workload-a.key \
  --idp-wait 3m
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── Token Exchange service ────────────────────────────────────────────────────
cat > /etc/systemd/system/wimse-token-exchange.service << 'EOF'
[Unit]
Description=WIMSE Token Exchange Service
After=wimse-idp.service
Requires=wimse-idp.service

[Service]
Type=simple
EnvironmentFile=/opt/wimse/token-exchange.env
ExecStartPre=/bin/bash -c 'until [ -x /opt/wimse/token-exchange ]; do sleep 2; done'
ExecStart=/opt/wimse/token-exchange \
  --source-idp     ${SOURCE_IDP_URL} \
  --source-issuer  ${SOURCE_IDP_ISSUER} \
  --target-issuer  ${TARGET_IDP_ISSUER} \
  --port           ${EXCHANGE_PORT} \
  --idp-wait       3m
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wimse-idp wimse-workload-a wimse-token-exchange
systemctl start  wimse-idp wimse-workload-a wimse-token-exchange || true
# Services will block in ExecStartPre until binaries appear via provision.sh.

echo "GCP startup script complete — waiting for binaries from provision.sh"
