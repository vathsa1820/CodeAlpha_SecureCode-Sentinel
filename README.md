# SecureCode Sentinel 🛡️

> **Static Application Security Testing (SAST) & Secure Coding Review Platform**  
> *Version 0.1.0*

SecureCode Sentinel is a modern web-based Static Application Security Testing (SAST) and Secure Coding Review platform. It allows security engineers and developers to analyze Python source code for security vulnerabilities, correlate findings across multiple engines (Bandit & Semgrep), calculate deterministic risk scores, map findings to CWE and OWASP Top 10 standards, provide actionable remediation guidance, generate audit reports, and execute static analyzers inside hardened Docker sandboxes.

---

## ✨ Key Features

- **Multi-Engine SAST**: Parallel static security scanning powered by **Bandit** (AST security linter) and **Semgrep** (semantic pattern matcher).
- **Non-Execution Security Guarantee**: Submitted code is treated strictly as static text; code is **NEVER** imported, executed, compiled, or evaluated.
- **Finding Correlation & Deduplication**: Merges overlapping scanner outputs into logical vulnerability objects with combined analyzer evidence snippets.
- **Deterministic Risk Scoring**: Formula-based scoring engine calculating 0–100 security scores and categorical risk levels (`MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Enriched Security Standards Mapping**: Maps findings to **CWE** (Common Weakness Enumeration) and **OWASP Top 10:2021** categories.
- **Actionable Remediation Guidance**: Detailed security explanations, impact summaries, and compliant code fix recommendations.
- **Security Review Reports & History**: Generates structured audit reports with executive summaries, severity percentages, and session scan history.
- **Containerized Sandbox Mode**: Optional Docker-based analyzer isolation (`ANALYZER_MODE=docker`) running non-root (`10001:10001`), network-isolated (`--network=none`), and read-only (`--read-only`).
- **Hardened System Security**: Strict input validation, path traversal blocking, security headers (`CSP`, `HSTS`, `X-Content-Type-Options`), CORS policy, and zero stack-trace leaks.

---

## 🏗️ System Architecture

```
                                  ┌──────────────────────────────┐
                                  │   React + Tailwind Frontend  │
                                  └──────────────┬───────────────┘
                                                 │
                                           REST API (FastAPI)
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │   FastAPI Security Gateway   │
                                  │ (Validation / Size Limits)   │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │   Analyzer Runner Factory    │
                                  └──────────────┬───────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        │                                                 │
                        ▼                                                 ▼
           [ANALYZER_MODE=local]                             [ANALYZER_MODE=docker]
          LocalHost Execution                               Docker Sandbox Execution
      (Bandit & Semgrep Subprocesses)                    (Non-Root, Network-None Container)
                        │                                                 │
                        └────────────────────────┬────────────────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │ Finding Normalizer & Correlator
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │  Risk Scoring & Remediation  │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │  Report Engine & History API │
                                  └──────────────────────────────┘
```

---

## 🔒 Security Architecture & Non-Execution Guarantee

> **CRITICAL SECURITY GUARANTEE:**  
> Submitted Python source code is **NEVER** executed, imported, compiled, or dynamically evaluated (`exec`, `eval`, `importlib`).  
> Source code submitted to SecureCode Sentinel is written to an isolated temporary file in a controlled directory and processed **STRICTLY** as static text by Bandit and Semgrep. Temporary files are destroyed immediately following static analysis.

### System Hardening Controls:
- **Payload Size Capping**: Limits code input to 500 KB (`MAX_SOURCE_SIZE_BYTES = 512,000`).
- **Filename Validation**: Enforces `^[a-zA-Z0-9_\-\.]+\.py$` regex, rejecting directory traversal (`..`), path separators (`/`, `\`), and shell metacharacters.
- **Subprocess Safety**: Enforces `shell=False` for all subprocess executions; input parameters are passed as explicit argument arrays.
- **Timeout Protection**: Enforces 30-second execution timeouts on analyzer processes.
- **Security Headers**: Middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and strict caching policies.

---

## 🐳 Docker Analyzer Sandbox (`ANALYZER_MODE=docker`)

When configured with `ANALYZER_MODE=docker` in `.env`, analyzers execute inside an unprivileged, isolated container with the following runtime constraints:

```bash
# Docker CLI Security Hardening Flags
docker run --rm \
  --network=none \
  --read-only \
  --user=10001:10001 \
  --tmpfs=/tmp:rw,noexec,nosuid,size=64m \
  --cpus=1.0 \
  --memory=512m \
  --pids-limit=64 \
  -v /tmp/sentinel_xyz/source.py:/tmp/source.py:ro \
  securecode-sentinel-analyzer:latest bandit -f json -r /tmp/source.py
```

- **Unprivileged Non-Root Execution**: Runs strictly as user `sentinel` (`10001:10001`).
- **Zero Network Access**: `--network=none` prevents outbound data exfiltration.
- **Read-Only Root Filesystem**: `--read-only` prevents container filesystem modification.
- **Resource Bounds**: Caps execution at 1 CPU core, 512 MB RAM, 64 PIDs, and 30s timeout.

---

## 📊 Risk Scoring Engine

SecureCode Sentinel uses a deterministic mathematical formula to convert findings into a 0–100 security score:

$$\text{security\_score} = \max\left(0, \min\left(100, \text{round}\left(\frac{100}{1 + 0.08 \times \sum \text{weight}(f)}\right)\right)\right)$$

| Severity | Weight | Score Range | Categorical Risk Level |
|---|---|---|---|
| **CRITICAL** | 10 | 90 – 100 | `MINIMAL` |
| **HIGH** | 7 | 75 – 89 | `LOW` |
| **MEDIUM** | 4 | 55 – 74 | `MEDIUM` |
| **LOW** | 1 | 30 – 54 | `HIGH` |
| **INFO** | 0 | 0 – 29 | `CRITICAL` |

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11 / 3.13, FastAPI, Pydantic v2, Pytest, Uvicorn.
- **Static Scanners**: Bandit `1.7.10`, Semgrep `1.99.0`.
- **Frontend**: React 18, Vite, JavaScript (ESNext), Tailwind CSS, Lucide React icons.
- **Containerization**: Docker, Docker Compose, Debian slim base (`python:3.11-slim`).
- **CI/CD & Quality**: GitHub Actions, custom static security checkers, secret scanner.

---

## 📁 Project Structure

```
securecode-sentinel/
├── .github/workflows/
│   └── ci.yml               # GitHub Actions CI workflow
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI entry point & security headers
│   │   ├── config.py        # Centralized configuration & environment settings
│   │   ├── models/          # Pydantic models (findings, reports, health)
│   │   ├── analyzers/       # Static analyzers & runner abstraction
│   │   │   ├── execution/   # Local vs Docker runner abstraction
│   │   │   ├── bandit_analyzer.py
│   │   │   ├── semgrep_analyzer.py
│   │   │   ├── normalizer.py
│   │   │   └── correlator.py
│   │   ├── scoring/         # Deterministic risk scoring engine
│   │   ├── remediation/     # Remediation guidance & KB mapping
│   │   ├── reports/         # Report generation & history service
│   │   └── routes/          # REST API route handlers
│   ├── tests/               # Pytest test suite (59 test cases)
│   └── requirements.txt     # Python backend dependencies
├── frontend/
│   ├── src/                 # React components, pages, services, styles
│   ├── package.json         # Frontend dependencies & scripts
│   └── package-lock.json    # Committed npm lockfile
├── docker/
│   ├── Dockerfile           # Unprivileged static analyzer image
│   └── entrypoint.sh        # Non-root entrypoint script
├── docs/
│   ├── DEMO_GUIDE.md        # 3-minute product walkthrough guide
│   └── RELEASE_CHECKLIST.md # Release audit & verification checklist
├── rules/                   # Custom Semgrep security rule definitions
├── samples/                 # Test sample files (vulnerable vs secure)
├── scripts/                 # Security check, secret scan, verification scripts
│   ├── security_check.py
│   ├── secret_scan.py
│   ├── verify_docker_security.py
│   ├── verify.py
│   └── verify.ps1
├── .env.example             # Environment variable template
├── docker-compose.yml       # Docker Compose setup
├── README.md                # Project documentation
└── SECURITY.md              # Security policy & disclosure guidelines
```

---

## 💻 Installation & Local Setup

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
# Activate virtual environment (Linux/macOS)
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```

### 3. One-Command Developer Verification

To run the complete verification suite (security audit, secret scan, Dockerfile check, 59 pytest tests, and frontend build):

```bash
# Python cross-platform runner
python -m scripts.verify

# PowerShell (Windows)
.\scripts\verify.ps1
```

---

## 📡 Primary API Reference

### `GET /api/health`
- **Purpose**: System health monitoring & version metadata.
- **Response**: `{ "status": "ok", "service": "SecureCode Sentinel API", "version": "0.1.0", "timestamp": "..." }`

### `POST /api/analyze`
- **Purpose**: Run static analysis on Python code text.
- **Request Format**: `{ "code": "source string", "filename": "input.py" }`
- **Response Overview**: Contains `status`, `findings`, `summary`, `security`, `scan` metadata.

### `POST /api/reports`
- **Purpose**: Generate structured `SecurityReport` document.
- **Request Format**: `{ "analysis": <AnalysisResult> }`
- **Response Overview**: `{ "report_id": "SCR-2026-000001", "generated_at": "...", "report": <SecurityReport> }`

### `GET /api/reports`
- **Purpose**: Retrieve session scan report history.

### `GET /api/reports/{report_id}`
- **Purpose**: Retrieve specific report by ID (returns `404` if missing).

---

## 🧪 Automated Testing & CI/CD

Run the automated Pytest suite:

```bash
cd backend
python -m pytest -v
```

All 59 backend tests pass 100%, covering:
- Health check monitoring
- Bandit & Semgrep static analysis
- Finding correlation & deduplication
- Scoring engine bounds & weights
- Remediation guidance mapping
- Report generation & severity percentages
- History storage API
- Path traversal & payload size security limits
- Security headers & CORS
- Non-execution regression tests in both Local and Docker runner modes

---

## 🎬 Product Demonstration

For a step-by-step 3-minute product walk-through demonstrating vulnerable vs secure code analysis, findings inspection, report generation, and Docker sandbox isolation, refer to [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

---

## ⚠️ Known Limitations

- **In-Memory History**: Report history is stored in server session memory (`history_service.py`) and resets when the backend server restarts.
- **Python Scope**: Static analysis rules currently target Python source code.
- **Host Docker Runtime**: Docker isolation security relies on the host OS kernel and container runtime.
- **No User Authentication**: SecureCode Sentinel currently operates without user accounts or role-based access control.
