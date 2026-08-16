import os
from typing import List

# Centralized System Security Configuration

# Source code limits
MAX_SOURCE_SIZE_BYTES = 500 * 1024  # 500 KB limit
MAX_FILENAME_LENGTH = 255

# Subprocess & Analyzer timeouts
ANALYZER_TIMEOUT_SECONDS = int(os.getenv("ANALYZER_TIMEOUT_SECONDS", "30"))

# Analyzer Execution Mode ("local" | "docker")
ANALYZER_MODE = os.getenv("ANALYZER_MODE", "local").lower().strip()

# Docker Container Isolation Configuration
DOCKER_ANALYZER_IMAGE = os.getenv("DOCKER_ANALYZER_IMAGE", "securecode-sentinel-analyzer:latest")
DOCKER_MEMORY_LIMIT = os.getenv("DOCKER_MEMORY_LIMIT", "512m")
DOCKER_CPU_LIMIT = os.getenv("DOCKER_CPU_LIMIT", "1.0")
DOCKER_PIDS_LIMIT = int(os.getenv("DOCKER_PIDS_LIMIT", "64"))
DOCKER_TIMEOUT_SECONDS = int(os.getenv("DOCKER_TIMEOUT_SECONDS", "30"))
DOCKER_TMPFS_SIZE = os.getenv("DOCKER_TMPFS_SIZE", "64m")
DOCKER_USER = os.getenv("DOCKER_USER", "10001:10001")

# CORS & Frontend Origins
DEFAULT_FRONTEND_ORIGIN = "http://localhost:5173"
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", DEFAULT_FRONTEND_ORIGIN)

ALLOWED_ORIGINS: List[str] = [
    FRONTEND_ORIGIN,
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Security Headers Configuration
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
}
