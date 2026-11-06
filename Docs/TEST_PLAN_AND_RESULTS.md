# Test Plan, Evaluation Matrix & Quantitative Results

**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**QA & Automation Lead:** Tayyab Khalid

---

## 1. Testing Strategy & Scope

Our verification framework validates both functional accuracy across the 6-stage security engine (`FR-1` through `FR-6`) and adversarial resilience across authentication, RBAC, CSRF, SSRF/allowlist enforcement, input validation, rate limiting, and SQLite persistence (`T1`-`T6` and `T-final`).

### Test Execution Commands
```bash
# Run complete automated test suite (node:test + supertest)
npm test

# Run standalone CLI evaluation benchmark & metrics table
npm run eval
```

---

## 2. Mandatory Evaluation Matrix (`Baseline` + `T1`-`T6`)

Verified by `tests/evaluation_t1_t6.test.js` and `scripts/run_evaluation.js`:

| Test ID | Target / Input | Expected Result | Actual Result | Concrete Evidence (Stage Findings & Headers) | Latency | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **Baseline** | `GET /fixtures/normal-safe` | Status `COMPLETED`; before score `>= 85` (`PASS`); `0` critical warnings; all 10 rules pass. | Before: `100/100` (`A`, `PASS`) -> After: `100/100` (`A`, `PASS`); `0` critical warnings. | All 10/10 header rules (`HDR-CSP-PRESENT` through `HDR-REFERRER-POLICY`) passed; 0 false positives. | `~6.4 ms` | **PASS** |
| **T1** | `GET /fixtures/t1-xss` | Detect missing CSP, DOM XSS sink (`document.write`), `eval()`, and inline `onerror`; synthesize strict CSP; improve score `< 30` -> `>= 90`. | Before: `7/100` (`F`, `FAIL`) -> After: `95/100` (`A`, `PASS`); `3` simulated XSS violations blocked. | `HDR-CSP-PRESENT` failed (`CRITICAL`); extracted `usesEvalOrFunction: true` and `onerror`; synthesized `default-src 'self'; script-src 'self'`. | `~7.8 ms` | **PASS** |
| **T2** | `GET /fixtures/t2-inline` | Extract inline `<script>` and `<style>`, compute `sha256-...` hashes for safe blocks, and flag inline `onclick` attribute for violation/refactoring. | Hashed `1` safe inline script & `1` inline style; flagged `onclick` attribute as `script-src-attr` violation. | Generated `'sha256-...'` tokens in `script-src` and `style-src`; flagged unhashable `onclick` handler with remediation guidance. | `~5.9 ms` | **PASS** |
| **T3** | `GET /fixtures/t3-third-party` | Flag wildcard `*` and `'unsafe-inline'` in baseline CSP; strip untrusted external domains (`cdn.untrusted-analytics.example`) in `'self'` CSP; record violations. | Before: `35/100` (`F`) -> After: `95/100` (`A`); stripped untrusted domains; recorded `2` third-party blocking violations. | `HDR-CSP-NO-WILDCARD` & `HDR-CSP-NO-UNSAFE-INLINE` flagged; untrusted script/image origins blocked in Stage 4 simulation. | `~6.2 ms` | **PASS** |
| **T4** | `GET /fixtures/t4-clickjacking` | Flag missing `X-Frame-Options` and missing `frame-ancestors`; inject `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | Before: `62/100` (`D`, `FAIL`) -> After: `98/100` (`A`, `PASS`); clickjacking framing blocked. | `HDR-CSP-FRAME-ANCESTORS` and `HDR-XFO-SAMEORIGIN` failed on baseline and passed post-remediation in `rawHttpHeaderBlock`. | `~5.4 ms` | **PASS** |
| **T5** | `GET /fixtures/t5-mime-sniffing` | Flag missing `X-Content-Type-Options: nosniff` and `object-src 'none'`; remediate both in exported header bundle. | Before: `68/100` (`D`, `FAIL`) -> After: `98/100` (`A`, `PASS`); MIME sniffing & plugin execution blocked. | `HDR-XCTO-NOSNIFF` and `HDR-CSP-OBJECT-SRC` failed on baseline; exported header block contains `X-Content-Type-Options: nosniff` and `object-src 'none'`. | `~5.1 ms` | **PASS** |
| **T6** | `https://evil.example.com/attack` & `http://169.254.169.254/latest/meta-data` | Reject unapproved external/metadata hosts prior to HTTP fetch with `403 ERR_ALLOWLIST_DENIED` and log `DENIED` in `audit_logs`. | Rejected with HTTP `403` (`ERR_ALLOWLIST_DENIED`) in `< 1.5 ms`; `DENIED` audit event persisted. | Pre-fetch allowlist guard blocked socket connection; `audit_logs` recorded `outcome: 'DENIED'` with sanitized target details. | `~1.1 ms` | **PASS** |

---

## 3. Security Controls & Resilience Matrix (`T-final`)

Verified by `tests/security_t_final.test.js`:

| Test Case ID | Security Control / Scenario | Input / Action | Expected HTTP Status & Error Code | Actual Result & Audit Evidence | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **T-final-1** | **Unauthenticated Access Control** | `GET /api/reports/runs`, `POST /api/engine/run-pipeline`, `GET /api/admin/config`, `GET /api/audit/logs` without session cookie | `401 Unauthorized` (`ERR_AUTH_REQUIRED`) | Returned `401 ERR_AUTH_REQUIRED` with zero stack traces; logged `DENIED` in `audit_logs`. | **PASS** |
| **T-final-2** | **RBAC Least-Privilege (`viewer`)** | Authenticated `viewer` calls `GET /api/reports/runs` (allowed) vs `POST /api/engine/run-pipeline`, `GET /api/reports/runs/:id/export-json`, `GET /api/admin/config`, `GET /api/audit/logs` (forbidden) | `200 OK` on read list; `403 Forbidden` (`ERR_AUTH_FORBIDDEN`) on operator/admin endpoints | Viewer allowed to list runs (`200`), denied on pipeline, exports, admin config, and audit logs (`403 ERR_AUTH_FORBIDDEN`); all denials logged in `audit_logs`. | **PASS** |
| **T-final-3** | **CSRF Token Verification** | Authenticated `operator`/`admin` sends `POST /api/engine/run-pipeline` or `PUT /api/admin/config` without or with forged `X-CSRF-Token` | `403 Forbidden` (`ERR_CSRF_INVALID`) | Returned `403 ERR_CSRF_INVALID`; state mutation prevented and logged as `DENIED`. | **PASS** |
| **T-final-4** | **Malformed JSON & Schema Validation** | Broken JSON payload `{"targetUrl": "http://localhost:3000", BROKEN_JSON` and empty `{ "targetUrl": "" }` | `400 Bad Request` (`ERR_VALIDATION_FAILED`) | Returned `400 ERR_VALIDATION_FAILED`; error handler suppressed internal `SyntaxError` stack traces. | **PASS** |
| **T-final-5** | **Oversized Payload Protection** | `POST /api/engine/run-pipeline` with `150 KB` payload (exceeding `100 KB` limit) | `413 Payload Too Large` (`ERR_PAYLOAD_TOO_LARGE`) | Returned `413 ERR_PAYLOAD_TOO_LARGE` safely without memory exhaustion or stack trace leakage. | **PASS** |
| **T-final-6** | **Admin Rule/Threshold Change Traceability** | Admin updates `passScoreThreshold: 99` and disables `HDR-REFERRER-POLICY`; Operator repeats run, compares `runA` vs `runB`, and exports `.txt` and `.json` | `200 OK` across config update, re-run, `/api/reports/compare`, and export endpoints | Comparison delta and rule status changes verified; exports scrubbed via `redactSensitiveData()`; config change and runs recorded in `audit_logs`. | **PASS** |
| **T-final-7** | **SQLite Persistence Across Restart** | Re-initialize SQLite database (`initDb()`) and query `workflow_runs` and `audit_logs` | `100%` of workflow runs and append-only audit records preserved | All prior runs and audit entries recovered intact after database re-initialization. | **PASS** |
| **T-final-8** | **Rate Limiting on Rapid Burst** | Rapid burst of `25` failed login requests from same client IP (`203.0.113.99`) | `429 Too Many Requests` (`ERR_RATE_LIMITED`) | Triggered `429 ERR_RATE_LIMITED` once threshold exceeded and recorded `DENIED` event in `audit_logs`. | **PASS** |

---

## 4. Quantitative Security & Performance Metrics Summary

Measured across the evaluation corpus (`Baseline` + `T1`-`T6`) via `npm run eval` and `POST /api/engine/evaluate-suite`:

| Metric | Target Benchmark | Measured Value | How Computed |
| :--- | :---: | :---: | :--- |
| **Rule Coverage (%)** | `100%` | **`100.0%` (`10 / 10` rules)** | `Unique rules evaluated across corpus / Total rules in DEFAULT_RULES (10) * 100` |
| **False Positive Rate (FPR)** | `0%` | **`0.0%` (`0 / 1` normal fixtures)** | `Unjustified critical/high alerts on hardened normal-safe baseline / Total normal fixtures * 100` |
| **False Negative Rate (FNR)** | `0%` | **`0.0%` (`0 / 6` adverse fixtures)** | `Missed vulnerabilities or unblocked SSRF targets across T1-T6 / Total adverse cases * 100` |
| **Mean Decision Latency** | `< 50 ms` | **`~5.4 ms` per full 6-stage run** | High-resolution `process.hrtime.bigint()` elapsed time across `FR-1` through `FR-6` |
| **Allowlist Rejection Latency** | `< 5 ms` | **`~1.1 ms` pre-fetch rejection** | Time to parse URL, verify allowlist failure, and return `403 ERR_ALLOWLIST_DENIED` |
