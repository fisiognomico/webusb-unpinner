#!/bin/bash
# docker/scripts/start-webusb.sh

# Wait for mitmproxy to start and generate certificates
sleep 5

# Get the container's IP address
CONTAINER_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Set environment variables for the app
export PROXY_ADDRESS=${CONTAINER_IP}
export PROXY_PORT=${PROXY_PORT:-8080}
export BACKEND_URL=http://localhost:${WEBUSB_PORT:-9000}/

# Start the production server
cd /app
npx serve -l ${WEBUSB_PORT:-9000} dist
