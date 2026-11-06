# Final Academic Project Report — Proposal 38: CSP Architect

**Project Title:** CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Team Members & Ownership:**
- **Tayyab Khalid (Team Lead, QA, Automation & Documentation):** `tests/*`, `scripts/run_evaluation.js`, `README.md`, `Docs/*`
- **Abdul Nafay Khan Burki (Backend, SQLite Persistence, Auth, RBAC, CSRF & Audit):** `src/app.js`, `src/db/database.js`, `src/repositories/repo.js`, `src/middleware/security.js`, `src/routes/auth.js`, `src/routes/admin.js`, `src/routes/audit.js`
- **Muhammad Ibrahim Alam (6-Stage Security Engine & Local Target Fixtures):** `src/engine/*`, `src/fixtures/fixturesRouter.js`, `src/routes/engine.js`
- **Fasih Ur Rehman (Dark-Slate Workbench UI, Reporting & Run Comparison):** `public/*`, `src/routes/reports.js`

---

## 1. Executive Summary & Problem Statement

Modern web applications remain heavily exposed to Cross-Site Scripting (XSS), UI Redressing (Clickjacking), untrusted third-party script injection, and MIME-confusion attacks due to missing or overly permissive browser security headers (such as `Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'`). Manual CSP authoring is error-prone: developers either deploy overly lax policies that fail to stop attacks or overly rigid policies that break legitimate inline scripts and styles.

**CSP Architect** solves this problem by providing an authenticated, role-governed, 6-stage security workbench that crawls approved local web applications, analyzes existing headers against 10 weighted rules, synthesizes least-privilege CSP headers with cryptographic SHA-256 hashes, simulates and collects W3C violation reports, computes explainable before/after posture scores, and exports deployment-ready HTTP header blocks and sanitized JSON evidence bundles.

---

## 2. End-to-End Traceability: Requirements (`FR-1`–`FR-6`) to Code, Tests & Logs

| Requirement | Stage Name | Primary Implementation Modules | Automated Verification Tests | Audit & Persistence Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **FR-1** | **Local App Crawler & Resource Extractor** | `src/engine/crawler.js` (`validateTargetUrl`, `crawlTarget`) | `tests/evaluation_t1_t6.test.js` (`Baseline`, `T1`, `T2`, `T6`) | Logs `ALLOWLIST_DENIED` (`DENIED`) on external URLs; persists `crawlResult` in `workflow_runs.stages_json`. |
| **FR-2** | **Header Analysis Engine (10 Rules)** | `src/engine/headerAnalyzer.js` (`parseCsp`, `analyzeHeaders`) | `tests/evaluation_t1_t6.test.js` (`Baseline`, `T1`–`T5`) | Records rule-by-rule `passed`, `severity`, `weight`, `reason`, `evidence`, and `remediation`. |
| **FR-3** | **Least-Privilege CSP Builder** | `src/engine/cspBuilder.js` (`buildCsp`) | `tests/evaluation_t1_t6.test.js` (`T1`–`T5`) | Generates `default-src 'self'`, SHA-256 script/style hashes, `frame-ancestors`, `object-src 'none'`, and companion headers. |
| **FR-4** | **Violation-Report Collector** | `src/engine/violationCollector.js` (`simulateViolations`, `normalizeBrowserReport`) | `tests/evaluation_t1_t6.test.js` (`T1`–`T3`) | Persists simulated and live browser W3C `csp-report` events in SQLite `violation_reports`. |
| **FR-5** | **Before/After Posture Score** | `src/engine/scorer.js` (`calculateBeforeAfterScore`) | `tests/evaluation_t1_t6.test.js` (`Baseline`, `T1`–`T5`) | Computes `before.score`, `after.score`, letter grades (`A`–`F`), `delta`, and itemized deduction/credit breakdown. |
| **FR-6** | **Downloadable Configuration** | `src/engine/exporter.js`, `src/routes/reports.js` | `tests/security_t_final.test.js` (`Test 2`, `Test 6`) | Exports Raw HTTP Header Block (`.txt`) and Sanitized JSON Report (`.json`) scrubbed via `redactSensitiveData()`. |

---

## 3. Security Architecture & Governance Controls

1. **Manual Authentication & RBAC (`src/routes/auth.js`, `src/middleware/security.js`):**
   - Accounts (`admin`, `operator`, `viewer`) authenticate with `bcryptjs` password verification and receive `HttpOnly`, `SameSite=Strict` session cookies backed by SHA-256 token hashes in SQLite.
   - Least privilege is strictly enforced: `viewer` can view run history (`200 OK`) but is blocked with `403 ERR_AUTH_FORBIDDEN` from running crawls, exporting reports, or accessing admin/audit routes.
2. **Synchronizer Token CSRF Defense (`verifyCsrf`):**
   - Every state-changing `POST`/`PUT` request requires a per-session `X-CSRF-Token` header (`403 ERR_CSRF_INVALID` on omission or mismatch).
3. **SSRF & Allowlist Enforcement (`validateTargetUrl`):**
   - Outbound crawling is restricted strictly to `systemConfig.allowlist` (`localhost`, `127.0.0.1`). Unapproved hosts (`https://evil.example.com/attack`, `http://169.254.169.254/latest/meta-data`) are rejected pre-fetch with `403 ERR_ALLOWLIST_DENIED`.
4. **Input Validation, Payload Limits & Rate Limiting:**
   - Malformed JSON and invalid schemas return `400 ERR_VALIDATION_FAILED`; payloads `> 100 KB` return `413 ERR_PAYLOAD_TOO_LARGE`; rapid request bursts return `429 ERR_RATE_LIMITED`—all with zero stack trace leakage.
5. **Append-Only Audit Trail & Persistence (`src/repositories/repo.js`):**
   - All security events (`SUCCESS`, `DENIED`, `FAILURE`) are written to `audit_logs` via `appendAuditLog` with `redactSensitiveData()` scrubbing and survive SQLite restarts intact.

---

## 4. Quantitative Evaluation Summary

Executed via `npm test` and `npm run eval` across the built-in fixture corpus:

- **Automated Test Suites:** `100%` passing (`tests/evaluation_t1_t6.test.js` and `tests/security_t_final.test.js`).
- **Rule Coverage:** **`100.0%`** (`10 / 10` security header rules exercised).
- **False Positive Rate (Normal Corpus):** **`0.0%`** (`0` false alerts on `/fixtures/normal-safe`; baseline score `100/100`).
- **False Negative Rate (Adverse Corpus `T1`–`T6`):** **`0.0%`** (`6 / 6` adverse fixtures accurately detected, remediated, or blocked).
- **Mean Pipeline Decision Latency:** **`~5.4 ms`** per complete 6-stage local workflow execution (`~1.1 ms` for `T6` allowlist rejection).
