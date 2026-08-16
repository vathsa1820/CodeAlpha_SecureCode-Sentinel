# Changelog — SecureCode Sentinel 🛡️

All notable changes to **SecureCode Sentinel** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-08-16

### Added
- **Python SAST Engine**: Integrated Bandit and Semgrep for parallel static application security testing of Python source code.
- **Finding Correlation & Deduplication**: Smart correlation engine merging duplicate raw findings into unified logical vulnerabilities with combined scanner evidence.
- **Deterministic Risk Scoring**: Formula-based 0–100 security scoring algorithm mapping scores to categorical risk levels (`MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Enriched Security Standards Mapping**: Automated mapping of findings to **CWE** (Common Weakness Enumeration) and **OWASP Top 10:2021** standards.
- **Remediation Knowledge Base**: Actionable remediation guidance providing security explanations, impact assessments, and compliant code fix recommendations.
- **Security Review Reports Engine**: Structured report generator creating audit reports with executive summaries, severity percentages, and deterministic IDs (`SCR-2026-000001`).
- **In-Memory Scan History**: Session history store with REST API endpoints (`GET /api/reports`, `GET /api/reports/{id}`, `DELETE /api/reports/{id}`).
- **Interactive Security Dashboard**: Modern dark-mode React dashboard with code editor, sample loader, score gauge, severity breakdown, finding cards, and report modal inspector.
- **Containerized Analyzer Isolation**: Configurable runner abstraction (`LocalAnalyzerRunner` vs `DockerAnalyzerRunner`) supporting Docker sandbox execution.
- **Automated Verification & CI/CD**: 59 automated Pytest tests, GitHub Actions CI workflow, security check script, secret scan script, and Dockerfile security verifier.

### Security
- **Non-Execution Security Guarantee**: Submitted Python source code is strictly treated as text; code is **NEVER** imported, executed, compiled, or evaluated.
- **Strict Input Validation**: Payload size capping at 500 KB and filename regex validation (`^[a-zA-Z0-9_\-\.]+\.py$`) blocking directory traversal and shell metacharacters.
- **Subprocess Hardening**: Enforced `shell=False` and 30-second execution timeouts for all analyzer subprocesses.
- **Hardened Docker Sandbox**: Docker execution mode runs non-root (`10001:10001`), network-isolated (`--network=none`), read-only root filesystem (`--read-only`), and resource-constrained (1 CPU, 512 MB RAM, 64 PIDs).
- **Security Headers & Restricted CORS**: Security header middleware (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`) and configurable CORS origin policy.
- **Zero Stack Trace Leaks**: Global exception handlers shielding internal stack traces and server file paths from API error responses.

### Limitations
- **Python Scope**: Static analysis rules currently target Python source code text.
- **In-Memory History**: Scan history is stored in server session memory and resets upon backend server restarts.
- **No User Authentication**: Operates without user accounts or role-based access control (RBAC).
- **Docker Host Dependency**: Docker isolation mode requires Docker Engine access on the host system running the backend.
