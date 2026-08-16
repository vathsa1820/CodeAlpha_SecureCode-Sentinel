# SecureCode Sentinel — Deployment & Production Guide 🚀

This document details the production deployment options, architecture, environment configuration, and security guidelines for **SecureCode Sentinel** v0.1.0.

---

## 🏗️ System Architecture Overview

```
             ┌──────────────────────────────────────────────┐
             │       Frontend (Static React/Vite App)       │
             │   (Vercel, Netlify, Cloudflare Pages, S3)    │
             └──────────────────────┬───────────────────────┘
                                    │ HTTP(S) API Requests
                                    ▼
             ┌──────────────────────────────────────────────┐
             │         FastAPI Backend Application          │
             │   (Uvicorn, Gunicorn, App Runner, VPS)       │
             └──────────────────────┬───────────────────────┘
                                    │
                         Analyzer Runner Factory
                                    │
             ┌──────────────────────┴──────────────────────┐
             │                                             │
             ▼                                             ▼
[ANALYZER_MODE=local]                       [ANALYZER_MODE=docker]
Host System Execution                       Isolated Docker Sandbox
(Bandit / Semgrep CLI)                      (Non-Root 10001:10001)
                                            (--network=none)
                                            (--read-only root)
                                            (--cpus 1.0, --memory 512m)
```

---

## ⚙️ Supported Execution Modes

SecureCode Sentinel supports two distinct execution runner modes configured via `ANALYZER_MODE`:

### Mode 1: Local Host Execution (`ANALYZER_MODE=local`) — Default
- **Environment**: Executes Bandit and Semgrep directly on the host system Python environment.
- **Use Case**: Development, local testing, or lightweight cloud hosting environments where Docker Engine access is not available.
- **Security Properties**: Source code is written to isolated temporary files with strict permissions and deleted immediately in `finally:` cleanup blocks.

### Mode 2: Docker Container Sandbox (`ANALYZER_MODE=docker`)
- **Environment**: Executes Bandit and Semgrep inside an unprivileged Docker container (`securecode-sentinel-analyzer:latest`).
- **Use Case**: Production environments processing untrusted user source code requiring strong container process and network isolation.
- **Host Requirement**: Requires the backend host system to have Docker Engine installed and accessible by the FastAPI server process.

---

## 🌐 Frontend Static Deployment

The frontend is a standard single-page application (SPA) built with React and Vite. It compiles down to static HTML, CSS, and JS assets.

### Build Commands:
```bash
cd frontend
npm ci
npm run build
```
Output directory: `frontend/dist/`

### Deployment Target Options:
- **Cloudflare Pages / Vercel / Netlify**: Configure build command `npm run build` and publish directory `dist`.
- **Nginx / Apache / S3 + CloudFront**: Upload contents of `frontend/dist/` directly to your web server root.

### Production Environment Variables:
Create `.env` or set environment variables in your deployment platform:
```ini
VITE_API_BASE_URL=https://api.yourdomain.com
```

---

## 🐍 Backend Deployment Options

The backend is a FastAPI ASGI application running on Python 3.11+.

### 1. Direct Host / Virtual Machine Deployment (Gunicorn + Uvicorn)

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start production server with 4 worker processes
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### 2. Docker Analyzer Container Image Setup (When using `ANALYZER_MODE=docker`)

Build the static analyzer image on the host where the backend process executes:

```bash
# Build the isolated static analyzer image
docker build -t securecode-sentinel-analyzer:latest -f docker/Dockerfile .
```

Verify non-root user execution:
```bash
docker run --rm --network=none --read-only --user=10001:10001 securecode-sentinel-analyzer:latest whoami
# Output must return: sentinel
```

---

## 🔐 Environment Configuration Reference

### Backend Configuration Variables (`.env`)

| Variable | Default Value | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind host address for API server. |
| `PORT` | `8000` | Port number for API server. |
| `ANALYZER_MODE` | `local` | Execution mode: `local` or `docker`. |
| `DOCKER_ANALYZER_IMAGE` | `securecode-sentinel-analyzer:latest` | Container image tag for Docker sandbox. |
| `DOCKER_MEMORY_LIMIT` | `512m` | RAM cap for analyzer container instances. |
| `DOCKER_CPU_LIMIT` | `1.0` | CPU limit for analyzer container instances. |
| `DOCKER_PIDS_LIMIT` | `64` | Process limit for analyzer container instances. |
| `DOCKER_TIMEOUT_SECONDS` | `30` | Execution timeout in seconds per analyzer. |
| `DOCKER_TMPFS_SIZE` | `64m` | Writable tmpfs size for container `/tmp`. |
| `DOCKER_USER` | `10001:10001` | Non-root UID:GID user for container execution. |
| `FRONTEND_ORIGIN` | `http://localhost:5173` | Allowed CORS origin for frontend requests. |

---

## 🔒 Production Security Checklist

1. **CORS Restriction**: Always set `FRONTEND_ORIGIN` to your exact frontend domain (e.g. `https://app.yourdomain.com`). Never use `*` wildcards with credentialed requests.
2. **Reverse Proxy & TLS**: Run FastAPI behind Nginx, Caddy, or an AWS Application Load Balancer with TLS/SSL termination (`https://`).
3. **Docker Daemon Access**: When using `ANALYZER_MODE=docker`, ensure only the backend application user has permission to execute Docker commands. Never mount the host Docker socket into an unprivileged web container.
4. **Temporary File Permissions**: Ensure host temporary directories (`/tmp` or `%TEMP%`) have restricted permissions (`0700`).
