#!/bin/bash
# AWS VM user-data script — runs as root at first boot.
# Creates directories and a systemd service stub that waits for the binary.
set -euo pipefail

WIMSE_DIR=/opt/wimse

mkdir -p "$WIMSE_DIR/certs" "$WIMSE_DIR/keys"
chmod 700 "$WIMSE_DIR/keys"

# ── Workload B service ────────────────────────────────────────────────────────
cat > /etc/systemd/system/wimse-workload-b.service << 'EOF'
[Unit]
Description=WIMSE Workload B
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/wimse/workload-b.env
ExecStartPre=/bin/bash -c 'until [ -x /opt/wimse/workload-b ]; do sleep 2; done'
ExecStart=/opt/wimse/workload-b \
  --idp       ${IDP_URL} \
  --issuer    ${IDP_ISSUER} \
  --tls-port  ${WORKLOAD_B_TLS_PORT} \
  --ca-cert   /opt/wimse/certs/ca.crt \
  --cert-file /opt/wimse/certs/workload-b.crt \
  --key-file  /opt/wimse/keys/workload-b.key \
  --idp-wait  3m
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wimse-workload-b
systemctl start  wimse-workload-b || true

echo "AWS startup script complete — waiting for binary from provision.sh"
