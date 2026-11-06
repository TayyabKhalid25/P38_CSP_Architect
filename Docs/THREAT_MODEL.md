# STRIDE Threat Model & Mitigation Traceability Matrix

**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Lead Author:** Tayyab Khalid

---

## 1. Threat Modeling Methodology

We applied Microsoft's **STRIDE** methodology (**S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege) across all four trust boundaries (`TB-1` through `TB-4`) defined in `Docs/ARCHITECTURE_AND_DFD.md`.

Every identified threat is mapped directly to:
1. The affected **Component & Trust Boundary**,
2. Concrete **Preventive & Detective Code Controls**,
3. **Audit Trail Evidence** recorded in `audit_logs`, and
4. Automated **Verification Test Cases** in `tests/evaluation_t1_t6.test.js` and `tests/security_t_final.test.js`.

---

## 2. Concrete Threat Catalog (10 Threats - Exceeding the Minimum 8 Required)

| Threat ID | STRIDE Category | Threat Scenario & Attack Vector | Affected Boundary & Module | Concrete Mitigation & Security Control | Verification Test Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TM-01** | **Elevation of Privilege / SSRF** | An attacker or rogue operator submits an external domain (`https://evil.example.com/attack`) or cloud metadata IP (`http://169.254.169.254/latest/meta-data`) to force the server-side crawler to scan arbitrary internal/external networks. | `TB-3 -> TB-4`<br>`src/engine/crawler.js` | `validateTargetUrl()` parses the URL prior to any socket connection, enforces `http:`/`https:`, rejects embedded credentials, and requires `hostname` to match `systemConfig.allowlist` (`localhost`, `127.0.0.1`). Rejects with `403 ERR_ALLOWLIST_DENIED` and logs `DENIED` in `audit_logs`. | `tests/evaluation_t1_t6.test.js` (`T6`) |
| **TM-02** | **Spoofing** | An unauthenticated client attempts to invoke the 6-stage pipeline, view workflow reports, or read admin configurations without a valid session, or attempts password brute-forcing on `/api/auth/login`. | `TB-1 -> TB-2`<br>`src/middleware/security.js`, `src/routes/auth.js` | Passwords hashed with `bcryptjs`; session tokens stored as SHA-256 hashes in SQLite `sessions` with 2-hour TTL and `HttpOnly`, `SameSite=Strict` cookies; `requireAuth` rejects unauthenticated requests with `401 ERR_AUTH_REQUIRED`; login endpoint protected by sliding-window rate limiter (`429 ERR_RATE_LIMITED`). | `tests/security_t_final.test.js` (`Test 1` & `Test 8`) |
| **TM-03** | **Elevation of Privilege** | A restricted `viewer` account attempts to execute a crawl pipeline (`POST /api/engine/run-pipeline`), download raw HTTP header or JSON exports (`GET /api/reports/runs/:id/export-*`), or modify security rules (`PUT /api/admin/config`). | `TB-1 -> TB-2`<br>`src/middleware/security.js`, `src/routes/*` | `requireRole(['admin', 'operator'])` on pipeline/export routes and `requireRole(['admin'])` on admin/audit routes reject unauthorized roles with generic `403 ERR_AUTH_FORBIDDEN` and append a `DENIED` record to `audit_logs`. | `tests/security_t_final.test.js` (`Test 2`) |
| **TM-04** | **Tampering (CSRF)** | A malicious third-party page tricks an authenticated operator or admin's browser into submitting a cross-site `POST /api/engine/run-pipeline` or `PUT /api/admin/config` request. | `TB-1 -> TB-2`<br>`src/middleware/security.js` | Synchronizer Token Pattern (`verifyCsrf` middleware) requires every state-changing request (`POST`, `PUT`, `PATCH`, `DELETE`) to supply a custom `X-CSRF-Token` header matching the session's cryptographic `csrf_token`, combined with `SameSite=Strict` session cookies. Rejects mismatches with `403 ERR_CSRF_INVALID`. | `tests/security_t_final.test.js` (`Test 3`) |
| **TM-05** | **Tampering / Injection (XSS in Workbench UI)** | A crawled target fixture contains malicious inline scripts (`<script>eval(...)</script>`), event attributes (`onerror="alert(1)"`), or crafted header strings designed to execute DOM XSS inside the CSP Architect dashboard when findings are rendered. | `TB-3 -> TB-1`<br>`public/js/app.js`, `src/app.js` | CSP Architect delivers its own strict self-protecting `Content-Security-Policy` header (`default-src 'self'; object-src 'none'; frame-ancestors 'self'`), escapes all HTML entities before rendering DOM findings, and isolates live browser violation testing inside a sandboxed `/fixtures/sandbox-frame` iframe. | `tests/evaluation_t1_t6.test.js` (`T1`, `T2`) |
| **TM-06** | **Repudiation** | An administrator weakens `passScoreThreshold` or disables a critical rule (`HDR-CSP-PRESENT`), or an attacker probes restricted endpoints, and later denies performing the action or attempts to delete log entries. | `TB-2 -> TB-4`<br>`src/repositories/repo.js`, `src/routes/admin.js`, `src/routes/audit.js` | `audit_logs` table is strictly append-only (`appendAuditLog` only executes `INSERT`; zero `UPDATE` or `DELETE` functions exist). Every login, pipeline run, config change (with before/after diff), and access denial is recorded with timestamp, actor, role, IP, action, and outcome. | `tests/security_t_final.test.js` (`Test 6` & `Test 7`) |
| **TM-07** | **Information Disclosure (Sensitive Data & Stack Traces)** | Exported JSON reports, audit log details, or malformed request error responses accidentally leak session cookies, CSRF tokens, password hashes, or internal Node.js file paths and stack traces. | `TB-2 & TB-4`<br>`src/contracts/schemas.js`, `src/middleware/security.js` | `redactSensitiveData()` recursively scrubs any key matching `/(password|pass|secret|token|authorization|cookie|set-cookie|session|api[-_]?key|csrf)/i` prior to logging or exporting. Global `errorHandler` returns structured `{ ok: false, error: { code, message, details: null } }` and strips stack traces. | `tests/security_t_final.test.js` (`Test 4` & `Test 6`) |
| **TM-08** | **Denial of Service (Oversized Payloads & Crawl Bombs)** | An attacker sends a multi-megabyte JSON request body to `/api/engine/run-pipeline` or points the crawler at an abnormally large HTML response to exhaust Node.js heap memory. | `TB-1 -> TB-2`, `TB-3 -> TB-4`<br>`src/app.js`, `src/engine/crawler.js` | Express JSON parser enforces `limit: '100kb'`, returning `413 ERR_PAYLOAD_TOO_LARGE` via `errorHandler`. The crawler enforces `systemConfig.maxCrawlSizeBytes` (`512 KB`) and a strict `5000 ms` `AbortController` fetch timeout. | `tests/security_t_final.test.js` (`Test 5`) |
| **TM-09** | **Denial of Service (Request Flooding)** | A client floods `/api/auth/login` or `/api/engine/run-pipeline` with rapid automated requests to exhaust CPU or SQLite I/O. | `TB-1 -> TB-2`<br>`src/middleware/security.js` | `createRateLimiter` enforces per-IP sliding-window counters on authentication and engine execution routes, returning `429 ERR_RATE_LIMITED` and logging a `DENIED` event in `audit_logs`. | `tests/security_t_final.test.js` (`Test 8`) |
| **TM-10** | **Tampering (SQL Injection & Persistence Corruption)** | Crafted filter query parameters (`?search=' OR 1=1--`) on `/api/reports/runs` or `/api/audit/logs` attempt to inject SQL commands or corrupt the SQLite database across restarts. | `TB-2 -> TB-4`<br>`src/repositories/repo.js`, `src/db/database.js` | All SQLite operations use `node:sqlite` (`DatabaseSync`) prepared statements with bound parameters (`?`). WAL/synchronous durability ensures all runs and audit logs survive process restarts intact. | `tests/security_t_final.test.js` (`Test 7`) |

---

## 3. Residual Risk & Defense-in-Depth Summary

- **No Single Point of Failure:** Even if an operator's browser session is targeted, `SameSite=Strict` cookies + custom `X-CSRF-Token` headers + role checks + local host allowlist validation operate as independent concentric barriers.
- **Fail-Closed Design:** Any unexpected parser failure, unreachable local port, or schema violation defaults to a safe rejection (`400`, `403`, `422`, or `500`) without executing target scripts or exposing internal server state.
