# Security Policy 🛡️

## Scope

SecureCode Sentinel is a Static Application Security Testing (SAST) platform designed to analyze Python source code for security vulnerabilities, assign risk scores, provide remediation guidance, and generate audit reports.

---

## Source Code Handling & Non-Execution Guarantee

> **CORE SECURITY GUARANTEE:**
> Submitted Python source code is **NEVER** executed, imported, compiled, or dynamically evaluated (`exec`, `eval`, `importlib`).
> Code submitted to SecureCode Sentinel is written to an isolated temporary file and processed **STRICTLY** as static text by Bandit and Semgrep.

---

## Containerized Analyzer Isolation (Docker Mode)

### Threat Model
Attacker-controlled Python source text processed by static analysis parser engines attempting host system compromise or resource exhaustion.

### Security Mitigations in Docker Mode (`ANALYZER_MODE=docker`)
- **Static-Only Analysis**: Source code is processed strictly as plain text. Code execution, compilation, or dynamic imports are disallowed.
- **Container Sandbox Isolation**: Bandit and Semgrep execute inside an isolated container instance (`securecode-sentinel-analyzer:latest`).
- **Zero Network Access**: Invoked with `--network=none`, completely blocking internet and internal network connectivity.
- **Non-Root Execution**: Container process runs as unprivileged non-root user `sentinel` (`UID:GID 10001:10001`). `whoami` inside container returns `sentinel`.
- **Read-Only Root Filesystem**: Root filesystem is mounted read-only (`--read-only`).
- **Restricted Writable Temporary Storage**: Temporary directory is mounted as `--tmpfs /tmp:rw,noexec,nosuid,size=64m`.
- **Strict Resource Boundaries**: CPU (`--cpus=1.0`), Memory (`--memory=512m`), PID (`--pids-limit=64`), and 30-second execution timeouts.
- **Source File Mount Privacy**: User filename is kept metadata-only. Source code is mounted read-only as `/tmp/source.py:ro`. Host root and user home directories are never mounted.
- **Guaranteed Cleanup**: Containers run with `--rm` flag and host temporary files are deleted inside `finally:` blocks.

---

## Local Analyzer Execution (Local Mode)

- **Isolated Temporary Directories**: In local mode, source code is written into temporary directories created via `tempfile.mkdtemp()` with restricted filesystem permissions.
- **Immediate Cleanup**: Temporary files and directories are guaranteed destroyed immediately after analysis inside `finally:` blocks.
- **Subprocess Safety**: Analyzers are invoked using explicit argument arrays with `shell=False`. User input is never interpolated into system shell strings.
- **Timeout Protection**: A strict 30-second execution timeout is enforced per analyzer run to prevent Denial of Service (DoS).

---

## Input Validation & Request Protection

- **Payload Size Limits**: Source code size is capped at 500 KB (`MAX_SOURCE_SIZE_BYTES = 512,000`). Oversized requests are rejected with HTTP 413 Payload Too Large.
- **Filename Sanitization**: Filenames are validated against a strict regular expression (`^[a-zA-Z0-9_\-\.]+\.py$`), enforcing `.py` extensions, max 255 character length, and disallowing path separators (`/`, `\`), null bytes (`\x00`), and directory traversal sequences (`..`).

---

## Report Security & Trust Boundaries

- **Strict Schema Validation**: `POST /api/reports` enforces full Pydantic schema validation (`AnalysisResult.model_validate()`) on incoming payloads.
- **Source Code Privacy**: Raw source code is excluded from stored report history objects. Only logical findings, evidence snippets, and risk metrics are stored in session memory.

---

## Known Limitations & Deployment Assumptions

1. **Host Docker Security Dependency**: Docker mode container isolation security relies on the host OS kernel and container runtime isolation.
2. **No Authentication**: SecureCode Sentinel currently operates without user authentication or role-based access controls.
3. **In-Memory Storage**: Report history is stored in server memory (`history_service.py`) and resets when the backend server restarts.
4. **Local Deployment Boundary**: Designed for local development and single-host internal security review workflows.
5. **Python Language Scope**: Static analysis rules currently target Python source code.

---

## Responsible Disclosure

If you discover a security vulnerability within SecureCode Sentinel:
1. Please report findings privately to the repository maintainer.
2. Provide full reproduction steps, proof-of-concept payloads, and system configuration details.
3. Allow reasonable time for remediation prior to public disclosure.
