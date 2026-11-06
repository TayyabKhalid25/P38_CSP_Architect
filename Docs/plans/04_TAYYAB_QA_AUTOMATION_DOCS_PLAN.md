# 04 - Tayyab Khalid: Automation, Security Testing, Packaging & Deliverables Plan
**Owner:** Tayyab Khalid  
**Git Branch:** `feat/tayyab-qa-automation-docs`  
**Git Author:** `Tayyab Khalid <146368050+TayyabKhalid25@users.noreply.github.com>`  
**Assigned Layers:** Layer 5 (Automated Evaluation & Security QA Suite, CLI Metrics Runner, Packaging, and Full Academic Deliverable Suite)

---

## 1. Exclusive File Ownership
You may **only** create/modify the following files:
1. `tests/evaluation_t1_t6.test.js` - Automated test suite verifying Mandatory Evaluation Cases `T1` through `T6` and the normal baseline fixture.
2. `tests/security_t_final.test.js` - Automated test suite verifying `T-final` (malformed/oversized input, unauthorized requests across roles, missing CSRF token rejection, rate limiting on repeated submissions, safe failure behavior without stack traces, and SQLite persistence/recovery across restarts) plus admin rule/threshold traceability.
3. `scripts/run_evaluation.js` - CLI evaluation benchmark script (`npm run eval`) that runs `T1`-`T6` + normal/adverse corpus and outputs formatted tables with **Rule Coverage (%), False Positive Rate, False Negative Rate, and Decision Latency (ms)**.
4. `README.md` - Project overview, setup/run guide, manual login credentials table, architecture summary, and test commands.
5. `Docs/ARCHITECTURE_AND_DFD.md` - Layered architecture specification + Mermaid Data-Flow Diagram (DFD) with explicit trust boundaries (`TB-1` through `TB-4`).
6. `Docs/THREAT_MODEL.md` - Comprehensive STRIDE Threat Model mapping 10 concrete threats (exceeding the minimum 8 required) to specific code controls, audit events, and verification tests.
7. `Docs/TEST_PLAN_AND_RESULTS.md` - Detailed test matrix for `T1`-`T6` and `T-final`, including input, expected result, actual result, evidence, pass/fail status, and quantitative metrics.
8. `Docs/USER_AND_ADMIN_GUIDE.md` - Step-by-step operating manual for Operators, Restricted Viewers, and Administrators.
9. `Docs/LIMITATIONS_AND_ETHICS.md` - Technical limitations (static DOM crawl vs runtime JS mutation, CSP Level 3 compatibility) and ethical guardrails (strict local allowlist enforcement, no external offensive scanning).
10. `Docs/FINAL_REPORT.md` - Complete academic final report linking every requirement (`FR-1` to `FR-6`, `T1`-`T6`, `T-final`) to code modules, test cases, log excerpts, and measured metrics.
11. `Docs/DEMO_SCRIPT_15MIN.md` - Reproducible 10-15 minute classroom live demonstration script covering the exact "Illustrative working example" from Page 3 of the specification PDF.

---

## 2. Mandatory Evaluation Cases (`T1`-`T6` & `T-final`)

| Test ID | Target / Input | Expected Security Decision & Evidence |
| :--- | :--- | :--- |
| **Baseline** | `GET /fixtures/normal-safe` | Status `COMPLETED`; baseline score >= 85 (`PASS`); 0 critical warnings; all 10 header rules pass. |
| **T1** | `GET /fixtures/t1-xss` | Identifies missing CSP (`HDR-CSP-PRESENT`), DOM XSS sink (`document.write`), `eval()`, and inline `onerror` handler; synthesizes strict CSP blocking inline/eval execution; simulates violations for the unsafe script vectors; increases score from `< 25` to `>= 90`. |
| **T2** | `GET /fixtures/t2-inline` | Extracts inline `<script>` and `<style>`, computes exact `sha256-...` hashes for safe blocks while flagging inline `onclick` attribute for violation/refactoring. |
| **T3** | `GET /fixtures/t3-third-party` | Flags wildcard `*` and `'unsafe-inline'` in baseline CSP (`HDR-CSP-NO-WILDCARD`, `HDR-CSP-NO-UNSAFE-INLINE`); strips untrusted third-party origins (`cdn.untrusted-analytics.example`) in synthesized `'self'` CSP and records simulated third-party blocking violations. |
| **T4** | `GET /fixtures/t4-clickjacking` | Flags missing `X-Frame-Options` (`HDR-XFO-SAMEORIGIN`) and missing `frame-ancestors` (`HDR-CSP-FRAME-ANCESTORS`); injects `frame-ancestors 'none'` and `X-Frame-Options: DENY`. |
| **T5** | `GET /fixtures/t5-mime-sniffing` | Flags missing `X-Content-Type-Options: nosniff` (`HDR-XCTO-NOSNIFF`) and missing `object-src 'none'` (`HDR-CSP-OBJECT-SRC`); remedies both in exported header block. |
| **T6** | External URL `https://evil.example.com/attack` & `http://169.254.169.254/latest/meta-data` | Rejected before HTTP fetch with `403 ERR_ALLOWLIST_DENIED`; records `DENIED` event in `audit_logs`. |
| **T-final** | Malformed/oversized JSON, unauthenticated/viewer access to operator/admin routes, missing CSRF header, rapid login/submission burst, DB restart | Returns stable error codes (`400`, `413`, `401`, `403`, `429`) with zero stack traces; persists audit records across SQLite reconnect. |
