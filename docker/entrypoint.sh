#!/bin/sh
set -e

# SecureCode Sentinel Entrypoint for Containerized Static Analyzers
# Executed strictly with unprivileged non-root user (10001:10001)

if [ "$1" = "whoami" ]; then
    whoami
    exit 0
fi

# Execute passed analyzer command directly
exec "$@"
