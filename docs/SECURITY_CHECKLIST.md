# Security Checklist — SecureCode Sentinel 🛡️

All items in this checklist have been implemented and verified as part of **Step 7: Security Hardening & Production Readiness**.

---

### Core Execution & Subprocess Security
- [x] **User source code never executed**: Source code is strictly parsed statically; `eval`, `exec`, or dynamic imports are NEVER used on user code.
- [x] **No shell=True for analyzer execution**: Bandit and Semgrep sub-processes are executed with argument arrays (`shell=False`).
- [x] **Analyzer timeout enforced**: Subprocess execution enforces a strict 30-second timeout limit (`ANALYZER_TIMEOUT_SECONDS`).
- [x] **Temporary files cleaned**: Analyzers write to temporary directories (`tempfile.mkdtemp()`) which are guaranteed deleted in `finally:` blocks.

---

### Input Validation & Perimeter Security
- [x] **Filename traversal blocked**: Filenames are sanitized via `os.path.basename` and validated with strict regex (`^[a-zA-Z0-9_\-\.]+\.py$`), blocking `..`, `/`, `\`, and null bytes (`\x00`).
- [x] **Source size limited**: Centralized `MAX_SOURCE_SIZE_BYTES` (500 KB) enforced via Pydantic model validation, returning HTTP 413 Payload Too Large for oversized inputs.
- [x] **Stack traces hidden**: Global FastAPI exception handlers intercept unhandled exceptions and return safe, sanitized JSON responses without exposing internal file paths or stack traces.

---

### Network & Headers Security
- [x] **CORS restricted**: `CORSMiddleware` configured with explicit allowed origins (`ALLOWED_ORIGINS`); wildcard `*` with credentials is disallowed.
- [x] **Security headers configured**: Middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, and `Cache-Control` headers on API responses.
- [x] **Secrets excluded from repository**: Zero API keys or credentials stored in source code; `.env.example` provided for configuration templates.

---

### Frontend & UI Security
- [x] **No eval / new Function in frontend**: React frontend verified free of dynamic code evaluation functions (`eval`, `new Function`).
- [x] **No dangerouslySetInnerHTML**: All user source code, vulnerability findings, evidence snippets, and report JSON strings are rendered strictly as text nodes in React JSX.

---

### Verification Suite
- [x] **Security regression tests passing**: Automated Pytest security suite (`backend/tests/test_security.py`) verifying input validation, path traversal protection, CORS headers, error handling, and source non-execution guarantees.
