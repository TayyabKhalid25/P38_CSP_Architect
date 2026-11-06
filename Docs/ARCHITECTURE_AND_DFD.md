# System Architecture & Data-Flow Diagram (DFD)

**Project:** Proposal 38 — CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Authors:** Tayyab Khalid (Lead/QA), Abdul Nafay Khan Burki (Backend/Auth), Muhammad Ibrahim Alam (Security Engine), Fasih Ur Rehman (Frontend/Reporting)

---

## 1. Architectural Overview (5-Layer Defense-in-Depth Model)

CSP Architect is engineered as a modular, five-layer local security workbench that crawls approved local web applications, evaluates HTTP browser security headers against a 10-rule policy matrix, synthesizes least-privilege Content Security Policy (CSP) headers with cryptographic SHA-256 hashes, simulates and captures real browser W3C CSP violation reports, computes explainable before/after posture scores, and exports deployment-ready HTTP header blocks and sanitized JSON evidence reports.

### Layer Breakdown

| Layer | Name | Primary Modules | Core Responsibilities & Security Controls |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **User / Browser Interface** | `public/index.html`, `public/css/styles.css`, `public/js/app.js` | Manual authentication login view (zero hardcoded/prefilled credentials in UI), 6-stage interactive & 1-click pipeline controls, live browser CSP violation sandbox (`<iframe>`), side-by-side run comparison, and role-aware Admin/Audit console. |
| **Layer 2** | **Application / API & Security Gateway** | `src/app.js`, `src/middleware/security.js`, `src/routes/auth.js`, `src/routes/admin.js`, `src/routes/audit.js`, `src/routes/reports.js`, `src/routes/engine.js` | Session cookie validation (`HttpOnly`, `SameSite=Strict`), Role-Based Access Control (`admin`, `operator`, `viewer`), synchronizer-token CSRF verification (`X-CSRF-Token`), sliding-window rate limiting (`429 ERR_RATE_LIMITED`), strict JSON schema & payload size validation (`100kb` limit), and stack-trace-free error normalization. |
| **Layer 3** | **Dedicated Security Engine (`FR-1`–`FR-6`)** | `src/engine/crawler.js`, `src/engine/headerAnalyzer.js`, `src/engine/cspBuilder.js`, `src/engine/violationCollector.js`, `src/engine/scorer.js`, `src/engine/exporter.js`, `src/engine/index.js` | Pre-fetch SSRF/allowlist validation (`localhost` / `127.0.0.1`), Cheerio DOM resource & SHA-256 hash extraction (`FR-1`), 10-rule weighted header analysis (`FR-2`), least-privilege CSP synthesis (`FR-3`), deterministic + browser W3C violation collection (`FR-4`), before/after posture scoring (`FR-5`), and sanitized artifact generation (`FR-6`). |
| **Layer 4** | **Data Store & Append-Only Audit Log** | `src/db/database.js`, `src/repositories/repo.js`, `src/contracts/schemas.js` | Built-in `node:sqlite` (`DatabaseSync`) relational persistence for `users`, `sessions`, `system_config`, `workflow_runs`, `violation_reports`, and immutable `audit_logs` with recursive sensitive-key redaction (`redactSensitiveData`). |
| **Layer 5** | **Local Target Fixtures & Evaluation Harness** | `src/fixtures/fixturesRouter.js`, `tests/evaluation_t1_t6.test.js`, `tests/security_t_final.test.js`, `scripts/run_evaluation.js` | Self-contained local vulnerable and hardened target endpoints (`/fixtures/normal-safe`, `t1-xss` through `t6-allowlist`, `sandbox-frame`) and automated verification suites measuring Rule Coverage, False Positive Rate, False Negative Rate, and Decision Latency. |

---

## 2. Data-Flow Diagram (DFD) with Explicit Trust Boundaries

The following Mermaid Data-Flow Diagram illustrates how requests, credentials, CSRF tokens, target HTML/headers, and sanitized audit records traverse the four explicit trust boundaries (`TB-1` through `TB-4`).

```mermaid
flowchart TB
    subgraph TB1["TB-1: Untrusted Client / Browser Zone"]
        U["Human Actor (Admin / Operator / Viewer)"]
        SPA["CSP Architect Browser UI (public/js/app.js)"]
        SBX["Sandboxed Browser Iframe (/fixtures/sandbox-frame)"]
    end

    subgraph TB2["TB-2: Authenticated API & Security Middleware Boundary"]
        MW_RATE["Sliding-Window Rate Limiter (429 ERR_RATE_LIMITED)"]
        MW_AUTH["Session & RBAC Guard (requireAuth / requireRole)"]
        MW_CSRF["CSRF Synchronizer Guard (verifyCsrf: X-CSRF-Token)"]
        MW_VAL["Input Schema & 100KB Payload Validator"]
        API_AUTH["/api/auth/*"]
        API_ENG["/api/engine/*"]
        API_REP["/api/reports/*"]
        API_ADM["/api/admin/* & /api/audit/*"]
    end

    subgraph TB3["TB-3: Dedicated 6-Stage Security Engine Boundary"]
        FR1["FR-1: Allowlist & SSRF Guard + DOM Crawler (crawler.js)"]
        FR2["FR-2: 10-Rule Header Analyzer (headerAnalyzer.js)"]
        FR3["FR-3: Least-Privilege CSP Synthesizer (cspBuilder.js)"]
        FR4["FR-4: Violation Simulator & Collector (violationCollector.js)"]
        FR5["FR-5: Before/After Posture Scorer (scorer.js)"]
        FR6["FR-6: Sanitized Header & JSON Exporter (exporter.js)"]
    end

    subgraph TB4["TB-4: Persistence & Target Fixture Boundary"]
        DB[("SQLite Data Store (node:sqlite)\nusers | sessions | system_config\nworkflow_runs | violation_reports")]
        AUDIT[("Append-Only Audit Log\n(audit_logs + redactSensitiveData)")]
        FIX["Approved Local Target Fixtures\n(http://localhost / 127.0.0.1 /fixtures/*)"]
        EXT["Unapproved External / Metadata Hosts\n(evil.example.com / 169.254.169.254)"]
    end

    U -->|"1. Manual Credentials & Workflow Actions"| SPA
    SPA -->|"2. HTTPS/HTTP JSON + Cookie + X-CSRF-Token"| MW_RATE
    SBX -->|"3. W3C CSP Violation POST (/api/engine/csp-report)"| MW_RATE

    MW_RATE --> MW_AUTH
    MW_AUTH --> MW_CSRF
    MW_CSRF --> MW_VAL

    MW_VAL --> API_AUTH
    MW_VAL --> API_ENG
    MW_VAL --> API_REP
    MW_VAL --> API_ADM

    API_ENG -->|"Stage 1"| FR1
    FR1 -->|"Verified Local HTTP GET"| FIX
    FR1 -.->|"BLOCKED Pre-Fetch (403 ERR_ALLOWLIST_DENIED)"| EXT
    FR1 -->|"Stage 2 (crawlResult)"| FR2
    FR2 -->|"Stage 3 (headerAnalysis)"| FR3
    FR3 -->|"Stage 4 (cspBuild)"| FR4
    FR4 -->|"Stage 5 (violationAnalysis)"| FR5
    FR5 -->|"Stage 6 (scoreComparison)"| FR6

    API_AUTH --> DB
    API_ADM --> DB
    API_REP --> DB
    FR6 -->|"Persist Run & Artifacts"| DB

    MW_AUTH -.->|"Log SUCCESS / DENIED"| AUDIT
    MW_CSRF -.->|"Log DENIED"| AUDIT
    FR1 -.->|"Log SSRF / Allowlist DENIED"| AUDIT
    API_ADM -.->|"Log Config Change & Actor"| AUDIT
    API_ENG -.->|"Log Pipeline Decision"| AUDIT
```

---

## 3. Trust Boundaries & Enforcement Mechanisms

1. **`TB-1 -> TB-2` (Browser Client to Express API Gateway):**
   - All incoming HTTP traffic is untrusted.
   - `express.json({ limit: '100kb' })` enforces strict payload bounds (`413 ERR_PAYLOAD_TOO_LARGE` on violation).
   - `createRateLimiter` throttles credential brute-forcing and pipeline flooding (`429 ERR_RATE_LIMITED`).
   - `attachSession` + `requireAuth` verify the SHA-256 hashed session token in SQLite (`401 ERR_AUTH_REQUIRED`).
   - `requireRole` enforces strict separation of duties between `admin`, `operator`, and `viewer` (`403 ERR_AUTH_FORBIDDEN`).
   - `verifyCsrf` validates the per-session `X-CSRF-Token` header on all state-mutating requests (`403 ERR_CSRF_INVALID`).

2. **`TB-2 -> TB-3` (API Gateway to Dedicated Security Engine):**
   - Only authenticated `operator` or `admin` requests reach the active crawling and synthesis pipeline.
   - Current `system_config` (allowlist, pass score threshold, enabled rules, and weights) is loaded from SQLite and injected deterministically into each engine invocation.

3. **`TB-3 -> TB-4` (Security Engine Crawler to Target Network / Fixtures):**
   - `validateTargetUrl(targetUrl, systemConfig)` parses the candidate URL via the WHATWG `URL` parser prior to opening any network socket.
   - Non-HTTP(S) schemes (`file:`, `javascript:`, `data:`, `gopher:`), embedded URL credentials, and any hostname outside `systemConfig.allowlist` (`localhost`, `127.0.0.1`) are immediately rejected with `403 ERR_ALLOWLIST_DENIED` and recorded in `audit_logs`.

4. **`TB-2 / TB-3 -> TB-4` (Application & Engine to SQLite Persistence & Audit Trail):**
   - Every SQL query uses parameterized prepared statements (`db.prepare(...)`) to prevent SQL injection.
   - `redactSensitiveData()` scrubs passwords, session tokens, CSRF tokens, cookies, and authorization headers before writing `details_json` to `audit_logs` or exporting JSON reports.
   - `audit_logs` is strictly append-only (`INSERT` only; no `UPDATE` or `DELETE` paths exist in `repo.js`).

---

## 4. End-to-End 6-Stage Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator (Browser UI)
    participant API as Express API + RBAC/CSRF
    participant Eng as Security Engine (FR-1..FR-6)
    participant Fix as Local Target (/fixtures/t1-xss)
    participant DB as SQLite (Runs + Audit Log)

    Op->>API: POST /api/engine/run-pipeline { targetUrl } + X-CSRF-Token
    API->>API: Verify Session, Role (operator/admin), CSRF, Rate Limit
    API->>DB: Load active system_config (allowlist, rules, threshold)
    API->>Eng: runFullPipeline(targetUrl, options, systemConfig)
    Eng->>Eng: FR-1 validateTargetUrl() against allowlist
    Eng->>Fix: HTTP GET /fixtures/t1-xss
    Fix-->>Eng: HTML DOM + Raw Response Headers
    Eng->>Eng: FR-1 Extract scripts, SHA-256 hashes, event handlers, eval()
    Eng->>Eng: FR-2 Evaluate 10 header security rules & weights
    Eng->>Eng: FR-3 Synthesize least-privilege CSP + companion headers
    Eng->>Eng: FR-4 Simulate policy violations against discovered DOM resources
    Eng->>Eng: FR-5 Compute Before/After posture scores, grades, and delta
    Eng->>Eng: FR-6 Generate Raw HTTP Header Block + Sanitized JSON Bundle
    Eng-->>API: Normalized 6-Stage Pipeline Result
    API->>DB: INSERT workflow_runs, violation_reports, audit_logs (SUCCESS)
    API-->>Op: 200 OK { ok: true, data: { id, stages, beforeScore, afterScore } }
```
