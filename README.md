# CSP Architect: Browser Security Header Workbench (Proposal 38)

**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Runtime:** Node.js `>= 22.5.0` + Express + Built-in `node:sqlite` + Vanilla Dark-Slate SPA

---

## 1. Overview

**CSP Architect** is a local browser security header engineering workbench that automates the end-to-end lifecycle of auditing, synthesizing, simulating, scoring, and exporting least-privilege **Content Security Policy (CSP)** and companion browser security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).

### Core 6-Stage Security Pipeline (`FR-1` to `FR-6`)
1. **`FR-1` Local App Crawler (`src/engine/crawler.js`):** Enforces pre-fetch SSRF/allowlist validation (`localhost` / `127.0.0.1`), fetches approved local pages, and extracts scripts, styles, cryptographic SHA-256 inline hashes, inline event handlers (`onclick`, `onerror`), `eval()` sinks, frames, images, and forms.
2. **`FR-2` Header Analysis (`src/engine/headerAnalyzer.js`):** Evaluates HTTP response headers against 10 weighted security rules (`HDR-CSP-PRESENT` through `HDR-REFERRER-POLICY`) with explainable findings and remediation guidance.
3. **`FR-3` Least-Privilege CSP Builder (`src/engine/cspBuilder.js`):** Synthesizes strict CSP directives (`default-src 'self'`, SHA-256 script/style hashes, `frame-ancestors 'none'`, `object-src 'none'`) and companion headers.
4. **`FR-4` Violation-Report Collector (`src/engine/violationCollector.js`):** Deterministically simulates policy violations against discovered DOM resources and collects real browser W3C `csp-report` payloads from an interactive sandboxed iframe (`/fixtures/sandbox-frame`).
5. **`FR-5` Before/After Posture Score (`src/engine/scorer.js`):** Computes quantitative before/after scores (`0–100`), letter grades (`A`–`F`), pass/fail status against configurable thresholds, and itemized score breakdowns.
6. **`FR-6` Downloadable Configuration (`src/engine/exporter.js`):** Exports deployment-ready **Raw HTTP Response Header Blocks (`.txt`)** and **Sanitized JSON Evidence Reports (`.json`)** scrubbed of any sensitive tokens.

---

## 2. Team Members & Module Ownership (Class 3, Group 6)

| Team Member | Role | Git Branch | Owned Modules |
| :--- | :--- | :--- | :--- |
| **Tayyab Khalid** | Team Lead, QA, Automation & Docs | `feat/tayyab-qa-automation-docs` | `tests/*`, `scripts/run_evaluation.js`, `README.md`, `Docs/*`, `server.js`, `src/contracts/schemas.js` |
| **Abdul Nafay Khan Burki** | Backend, Auth, RBAC, CSRF & SQLite | `feat/nafay-backend-auth` | `src/app.js`, `src/db/database.js`, `src/repositories/repo.js`, `src/middleware/security.js`, `src/routes/auth.js`, `src/routes/admin.js`, `src/routes/audit.js` |
| **Muhammad Ibrahim Alam** | 6-Stage Security Engine & Fixtures | `feat/ibrahim-security-engine` | `src/engine/*`, `src/fixtures/fixturesRouter.js`, `src/routes/engine.js` |
| **Fasih Ur Rehman** | Workbench UI, Reports & Comparison | `feat/fasih-frontend-ui` | `public/index.html`, `public/css/styles.css`, `public/js/app.js`, `src/routes/reports.js` |

---

## 3. Setup, Execution & Verification Commands

```bash
# 1. Install project dependencies
npm install

# 2. Start the local workbench server (http://localhost:3000)
npm start

# 3. Run automated test suites (T1-T6 evaluation + T-final security/persistence)
npm test

# 4. Run standalone CLI evaluation benchmark & metrics table
npm run eval
```

---

## 4. Manual Login Credentials (RBAC)

> [!NOTE]
> By design, **no credentials or quick-fill buttons are displayed on the login UI**. Enter the credentials below manually at `http://localhost:3000`:

| Account Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@CSP2026!` | Full pipeline, exports, Admin rule/threshold/allowlist config, and Append-Only Audit Log viewer. |
| **Operator** | `operator` | `Operator@CSP2026!` | Execute 6-stage pipeline, interactive stage controls, evaluation suite, run comparison, and `.txt`/`.json` exports. |
| **Restricted Viewer** | `viewer` | `Viewer@CSP2026!` | Read-only access to workflow run history and run comparison (`403 ERR_AUTH_FORBIDDEN` on crawl/export/admin routes). |

---

## 5. Complete Documentation Index (`Docs/`)

- [`Docs/ARCHITECTURE_AND_DFD.md`](Docs/ARCHITECTURE_AND_DFD.md) — 5-Layer Architecture & Mermaid Data-Flow Diagram with Trust Boundaries (`TB-1`–`TB-4`).
- [`Docs/THREAT_MODEL.md`](Docs/THREAT_MODEL.md) — 10-Threat STRIDE Threat Model mapped to code controls, audit events, and tests.
- [`Docs/TEST_PLAN_AND_RESULTS.md`](Docs/TEST_PLAN_AND_RESULTS.md) — Complete `T1`–`T6` and `T-final` test matrix and quantitative metrics (`100%` coverage, `0%` FP/FN).
- [`Docs/USER_AND_ADMIN_GUIDE.md`](Docs/USER_AND_ADMIN_GUIDE.md) — Step-by-step operating manual for Operators, Viewers, and Administrators.
- [`Docs/LIMITATIONS_AND_ETHICS.md`](Docs/LIMITATIONS_AND_ETHICS.md) — Technical limitations and ethical allowlist/defensive guardrails.
- [`Docs/FINAL_REPORT.md`](Docs/FINAL_REPORT.md) — Comprehensive academic report linking claims to code, tests, logs, and measured metrics.
- [`Docs/DEMO_SCRIPT_15MIN.md`](Docs/DEMO_SCRIPT_15MIN.md) — Reproducible 15-minute live classroom demonstration walkthrough.
