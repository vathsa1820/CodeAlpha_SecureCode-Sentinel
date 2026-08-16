# Threat Model — SecureCode Sentinel 🛡️

## Overview
This document outlines the threat model for the **SecureCode Sentinel** Static Application Security Testing (SAST) platform. It evaluates key attack surfaces across the backend FastAPI service, static analysis subprocess engine, report generation pipeline, and React frontend.

---

## Threat Matrix by Attack Surface

### 1. User-Submitted Source Code
- **Threat**: Attackers submitting malicious Python code attempting Remote Code Execution (RCE) during analysis via dynamic imports (`eval`, `exec`, `importlib`).
- **Impact**: Server compromise, process takeover, data exfiltration.
- **Existing Mitigation**: Strict "No-Execution" policy. Code is treated exclusively as plain text and scanned statically by Bandit & Semgrep.
- **Step 7 Mitigation**: Enforced `MAX_SOURCE_SIZE_BYTES` (500 KB limit) in Pydantic schema and non-execution regression test verifying submitted payload cannot create filesystem markers.

### 2. Uploaded Filenames
- **Threat**: Malicious filename strings (e.g., `../../etc/passwd`, `C:\Windows\System32\cmd.exe`, `shell.py\x00.png`).
- **Impact**: Filesystem path traversal, arbitrary file overwrite, null-byte injection.
- **Existing Mitigation**: Filename normalization via `split('/')[-1]`.
- **Step 7 Mitigation**: Strict Pydantic regex validation (`^[a-zA-Z0-9_\-\.]+\.py$`), enforcing `.py` extension, max length 255 chars, blocking directory traversal (`..`), path separators (`/`, `\`), and null bytes (`\x00`). `os.path.basename` enforced in tempfile handlers.

### 3. API Request Bodies
- **Threat**: Excessively large payloads causing Denial of Service (DoS) via server memory exhaustion.
- **Impact**: Server unresponsiveness, crash, resource exhaustion.
- **Existing Mitigation**: Maximum byte checks inside analyzer service.
- **Step 7 Mitigation**: Frontend/backend size validation in FastAPI Pydantic models returning HTTP 413 Payload Too Large.

### 4. Analyzer Execution
- **Threat**: Pathological or computationally expensive Python code causing static analysis tools to loop indefinitely.
- **Impact**: Denial of Service (DoS), thread pool starvation.
- **Existing Mitigation**: None (relied on implicit execution finish).
- **Step 7 Mitigation**: Enforced `ANALYZER_TIMEOUT_SECONDS = 30` in `subprocess.run()`. `TimeoutExpired` exceptions cleanly caught, temporary files cleaned up, and analyzer failure status reported safely.

### 5. Temporary Files
- **Threat**: Local file inclusion, race conditions, or uncleaned temporary scan files cluttering disk space.
- **Impact**: File leakage, storage exhaustion.
- **Existing Mitigation**: Files written to `tempfile.mkdtemp()`.
- **Step 7 Mitigation**: Temporary files created in isolated directories with secure access permissions and guaranteed cleanup inside `finally:` blocks. User filenames never used as raw disk paths.

### 6. Semgrep / Bandit Process Invocation
- **Threat**: OS Command Injection via shell expansion if analyzer arguments are passed through a system shell.
- **Impact**: Remote Code Execution (RCE) on the host operating system.
- **Existing Mitigation**: Command arguments passed as Python lists.
- **Step 7 Mitigation**: Verified `shell=False` across all `subprocess.run` calls. Executable paths resolved using safe `shutil.which` lookups. User input never interpolated into shell strings.

### 7. Report Generation
- **Threat**: Malicious client submitting forged or tampered `AnalysisResult` JSON to corrupt security score metrics or injection payloads in reports.
- **Impact**: Data integrity compromise, misleading security scores, potential stored XSS.
- **Existing Mitigation**: Report generator schema parsing.
- **Step 7 Mitigation**: `AnalysisResult.model_validate()` enforced on `POST /api/reports` payload. Raw code excluded from stored report history.

### 8. In-Memory Report Storage
- **Threat**: Unbounded accumulation of report objects causing server memory leak over extended uptime.
- **Impact**: Memory exhaustion, process restart.
- **Existing Mitigation**: None.
- **Step 7 Mitigation**: Clearly documented session storage disclaimer; raw source code is excluded from stored report history objects.

### 9. Frontend Rendering
- **Threat**: Cross-Site Scripting (XSS) via vulnerability titles, code snippets, or report JSON rendered in the browser.
- **Impact**: Session hijacking, malicious script execution in client browser context.
- **Existing Mitigation**: React JSX auto-escaping.
- **Step 7 Mitigation**: Audit confirmed zero usage of `dangerouslySetInnerHTML`, `eval()`, or `new Function()`. All user code, evidence snippets, and JSON strings are rendered strictly as text nodes.

### 10. Error Handling
- **Threat**: Unhandled backend exceptions leaking internal stack traces, system paths, environment variables, or CLI invocation commands in HTTP responses.
- **Impact**: Information disclosure assisting attacker reconnaissance.
- **Existing Mitigation**: Basic FastAPI exception messages.
- **Step 7 Mitigation**: Centralized global exception handlers in `app/main.py` returning safe, sanitized HTTP 422/413/500 JSON responses without stack traces.

---

## Security Boundary Summary
- **Untrusted Zone**: User source code text, filenames, API JSON payloads.
- **Sanitization Zone**: FastAPI Pydantic validators, `os.path.basename`, regex path controls.
- **Execution Zone**: Static analysis subprocesses (`bandit`, `semgrep`) run with `shell=False`, 30s timeout, isolated tempdir.
- **Trusted Zone**: Correlator, Scoring Engine, Remediation KB, Security Reports.
