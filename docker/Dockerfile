# SecureCode Sentinel - Isolated Static Analyzer Image
FROM python:3.11-slim

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install minimal system dependencies required for static analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install pinned versions of Bandit and Semgrep
RUN pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.99.0

# Create unprivileged non-root user and group (sentinel: 10001:10001)
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /bin/false sentinel

# Create rules directory and copy security rules
WORKDIR /rules
COPY rules/semgrep/python-security.yml /rules/python-security.yml

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    chown -R sentinel:sentinel /rules /entrypoint.sh

# Switch to unprivileged non-root user
USER sentinel:sentinel

WORKDIR /tmp

ENTRYPOINT ["/entrypoint.sh"]
