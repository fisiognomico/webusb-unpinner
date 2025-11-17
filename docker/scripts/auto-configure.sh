#!/bin/bash
# docker/scripts/auto-configure.sh

set -e

# Wait for services to be ready
sleep 15

# Get container IP
CONTAINER_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Wait for mitmproxy certificate to be generated
while [ ! -f /root/.mitmproxy/mitmproxy-ca-cert.pem ]; do
    echo "Waiting for mitmproxy certificate..."
    sleep 2
done

# Read the CA certificate
CA_CERT=$(cat /root/.mitmproxy/mitmproxy-ca-cert.pem)

# Create configuration file
cat > /app/static/proxy-config.json <<EOF
{
  "address": "${CONTAINER_IP}",
  "port": ${PROXY_PORT:-8080},
  "caCertificate": $(echo "$CA_CERT" | jq -Rs .)
}
EOF

echo "Proxy configuration generated at /app/dist/proxy-config.json"
