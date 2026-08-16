# SecureCode Sentinel — 3-Minute Product Demonstration Guide 🎬

This guide provides a structured 3–5 minute walk-through for demonstrating **SecureCode Sentinel** v0.1.0 to stakeholders, interviewers, or security team members.

---

## ⏱️ Quick Summary & Objective

Demonstrate how SecureCode Sentinel statically analyzes Python source code without execution, correlates multi-tool static findings (Bandit + Semgrep), calculates deterministic risk scores, provides actionable remediation guidance, and generates audit reports.

---

## 🚀 Demo Walk-Through (3–5 Minutes)

### Step 1: Launch Application Stack (30 Seconds)

1. **Start Backend Server**:
   ```bash
   cd backend
   uvicorn app.main:app --reload --port 8000
   ```
2. **Start Frontend Client**:
   ```bash
   cd frontend
   npm run dev
   ```
3. Open browser to `http://localhost:5173`.

---

### Step 2: Analyze Vulnerable Code Sample (1 Minute)

1. On the **Code Analyzer** page (`/analyzer`), click **Load Sample** and select **Vulnerable Python Sample**.
2. Click **Run Security Scan**.
3. Point out the **Security Score & Risk Level**:
   - **Score**: `29 / 100`
   - **Risk Level**: `CRITICAL`
4. Highlight the **Analysis Breakdown**:
   - **Raw Detections**: `12` raw scanner outputs from Bandit and Semgrep.
   - **Logical Vulnerabilities**: `6` correlated, deduplicated findings.
   - **Active Analyzers Badge**: Shows `bandit` and `semgrep` completed via `Local` or `Docker Sandbox`.

---

### Step 3: Inspect Findings & Remediation Guidance (1 Minute)

1. Click on the **Code Injection (`eval`)** finding.
2. Review the enriched security metadata:
   - **CWE Mapping**: `CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code`
   - **OWASP Top 10**: `A03:2021 - Injection`
   - **Fingerprint**: Deterministic sha256 fingerprint (`8f4a2...`).
   - **Analyzer Evidence**: Displays correlated evidence snippets from both Bandit (`B307`) and Semgrep (`unsafe-eval-exec`).
3. View **Remediation & Secure Coding Guidance**:
   - Explanation of security impact.
   - Compliant secure code example (`ast.literal_eval()`).

---

### Step 4: Generate Report & Review Scan History (30 Seconds)

1. Click **Generate Security Report** at the top right of the scan results.
2. Inspect the **Report Inspector**:
   - Executive Summary
   - Report Identifier: `SCR-2026-000001`
   - Severity Breakdown & Percentages
   - Categorized Remediation Priorities
3. Click **Copy Report JSON** to demonstrate API compatibility.
4. Navigate to **Scan History** (`/reports`) to show stored report history and score comparison deltas.

---

### Step 5: Analyze Clean Secure Code Sample (30 Seconds)

1. Return to **Code Analyzer**, click **Load Sample**, and select **Secure Python Sample**.
2. Click **Run Security Scan**.
3. View clean results:
   - **Score**: `100 / 100`
   - **Risk Level**: `MINIMAL`
   - **Logical Vulnerabilities**: `0`
4. Compare score delta with the previous vulnerable report (`+71 Points`).

---

### Step 6: Highlight Docker Sandbox Isolation (Optional - 30 Seconds)

Explain that setting `ANALYZER_MODE=docker` in `.env` executes Bandit and Semgrep inside an unprivileged Docker container (`sentinel: 10001:10001`) with `--network=none`, `--read-only` root filesystem, and strict memory/CPU limits to isolate analyzer execution from the host system.
