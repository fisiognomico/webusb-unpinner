# Dockerfile
FROM node:18-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    jq \
    iproute2 \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy in a virtual environment
RUN python3 -m venv /opt/mitmproxy \
    && /opt/mitmproxy/bin/pip install --upgrade pip \
    && /opt/mitmproxy/bin/pip install mitmproxy

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Build the application
RUN npm run build

# Create certificate directory
RUN mkdir -p /root/.mitmproxy

# Copy startup scripts
COPY docker/scripts /scripts
RUN chmod +x /scripts/*.sh

# Copy supervisor configuration
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports
# 8080 - mitmproxy
# 8081 - mitmweb (optional web interface)
# 9000 - WebUSB unpinner dev server
EXPOSE 8080 8081 9000

# Environment variables with defaults
ENV PROXY_PORT=8080 \
    WEBUSB_PORT=9000 \
    MITMWEB_PORT=8081 \
    MITMWEB_HOST=172.20.0.10 \
    AUTO_CONFIGURE=true

# Start services via supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
