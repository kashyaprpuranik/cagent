# =============================================================================
# AI Devbox - Data Plane Container
# Ubuntu dev environment with Docker for running infrastructure services
# =============================================================================

FROM ubuntu:24.04

LABEL maintainer="DevOps Team"
LABEL description="AI Agent Development Environment with Infrastructure"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Create non-root user (will run as this user for dev work)
RUN groupadd -g 1000 aiuser && \
    useradd -m -u 1000 -g aiuser -s /bin/bash aiuser && \
    usermod -aG sudo aiuser

# Install dev tools + Docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Dev essentials
    ca-certificates \
    curl \
    git \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    python3-dev \
    sudo \
    # Docker dependencies
    apt-transport-https \
    gnupg \
    lsb-release \
    iptables \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Install Docker
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/*

# Add aiuser to docker group
RUN usermod -aG docker aiuser

# Create directories
RUN mkdir -p /workspace /opt/infrastructure && \
    chown -R aiuser:aiuser /workspace

# Copy infrastructure configs and compose file
COPY configs/ /opt/infrastructure/configs/
COPY services/ /opt/infrastructure/services/
COPY docker-compose.yml /opt/infrastructure/docker-compose.yml

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Workspace is the default working directory
WORKDIR /workspace

# Expose any needed ports (optional, for debugging)
# EXPOSE 9901

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
