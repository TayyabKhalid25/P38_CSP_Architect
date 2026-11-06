# 03 — Fasih Ur Rehman: Dark-Slate Workbench UI, Reporting & Comparison Plan
**Owner:** Fasih Ur Rehman  
**Git Branch:** `feat/fasih-frontend-ui`  
**Git Author:** `Fasih Ur Rehman <215206356+fasih-ur-rehman1@users.noreply.github.com>`  
**Assigned Layers:** Layer 1 (Browser Interface: Validated Input & Explainable Output) & Reporting/History Routes (`src/routes/reports.js`)

---

## 1. Exclusive File Ownership
You may **only** create/modify the following files:
1. `src/routes/reports.js` — Express router mounted at `/api/reports` for listing workflow run history, retrieving single run records, comparing two runs side-by-side (`GET /compare`), and downloading raw HTTP headers or sanitized JSON reports.
2. `public/index.html` — Single-Page Application HTML structure for CSP Architect.
3. `public/css/styles.css` — Clean dark/slate cybersecurity workbench aesthetic (responsive grid, severity badges, score gauges, code blocks, diff views, accessible focus states).
4. `public/js/app.js` — Frontend controller managing authentication state, CSRF header injection (`X-CSRF-Token`), 6-stage interactive & 1-click pipeline execution, live browser violation iframe sandbox, evaluation suite runner (`T1`–`T6`), history comparison, and Admin configuration/audit views.

---

## 2. Reporting & History Router Specification (`src/routes/reports.js`)
Mounted at `/api/reports`:
- `GET /api/reports/runs` — Requires `requireAuth` (any authenticated role: `admin`, `operator`, `viewer`). Supports query filters `?status=COMPLETED&search=t1&limit=50`. Returns sanitized list of workflow runs.
- `GET /api/reports/runs/:id` — Requires `requireAuth`. Returns full workflow run details.
- `GET /api/reports/compare?runA=<id>&runB=<id>` — Requires `requireAuth`. Compares two workflow runs (`runA` and `runB`) and returns score delta, rule changes, CSP directive diffs, and configuration traceability.
- `GET /api/reports/runs/:id/export-headers` — Requires `requireRole(['admin', 'operator'])` (restricted `viewer` receives `403 ERR_AUTH_FORBIDDEN`, which is logged in `audit_logs`!). Returns `Content-Type: text/plain` attachment with the Raw HTTP Response Header block (`FR-6`).
- `GET /api/reports/runs/:id/export-json` — Requires `requireRole(['admin', 'operator'])` (restricted `viewer` is denied with `403`). Returns `Content-Type: application/json` attachment with the sanitized JSON report (`FR-6`).

---

## 3. Browser UI Requirements (`public/*`)

### A. Strict Manual Login Screen
- Must display a clean username and password login form.
- **CRITICAL USER REQUIREMENT:** Do **NOT** display demo credentials, hint text with passwords, or quick-fill buttons on the login screen. Users must manually type their username and password (kept only in `README.md` and `Docs/USER_AND_ADMIN_GUIDE.md`).

### B. Main Navigation Tabs
1. **6-Stage Workbench (`FR-1` to `FR-6`):**
   - **Target Selector Bar:** Preset dropdown for local fixtures (`/fixtures/normal-safe`, `/fixtures/t1-xss`, `/fixtures/t2-inline`, `/fixtures/t3-third-party`, `/fixtures/t4-clickjacking`, `/fixtures/t5-mime-sniffing`, plus an unapproved external URL test option `https://evil.example.com/ssrf-test` to demonstrate allowlist rejection) OR custom URL text input.
   - **Dual Execution Controls:**
     - **"Run Full 6-Stage Pipeline" (1-Click):** Calls `POST /api/engine/run-pipeline` and populates all 6 stage panels and saves the run to history.
     - **Interactive Step-by-Step Controls:** Each stage panel (`1. Crawler`, `2. Header Analysis`, `3. CSP Builder`, `4. Violation Collector`, `5. Before/After Score`, `6. Downloadable Config`) has its own **"Run / Re-run Stage"** button and interactive policy controls (e.g., toggling SHA-256 inline hashes, framing policy `'none'` vs `'self'`, adding trusted origins) so the operator can tune the CSP and watch Stages 4, 5, and 6 update live!
   - **Live Browser CSP Violation Sandbox (in Stage 4):** Button to load `/fixtures/sandbox-frame` in a sandboxed iframe that triggers a real browser `SecurityPolicyViolationEvent` and POSTs a W3C CSP report to `/api/engine/csp-report`, then refreshes the collected violation table.
   - **Stage 6 Export Controls:** Buttons to copy or download **Raw HTTP Response Header Block (`.txt`)** and **Sanitized JSON Evidence Report (`.json`)** (only these two formats, matching user preferences).
2. **Evaluation & Metrics Suite (`T1`–`T6`):**
   - One-click button (`POST /api/engine/evaluate-suite`) that runs mandatory test fixtures `T1` through `T6` plus the normal baseline, displaying a comprehensive table of **Test ID, Name, Input, Expected Result, Actual Result, Evidence, Decision Latency (ms), and Pass/Fail Badge**, plus aggregate **Rule Coverage %, False Positive Rate, False Negative Rate, and Mean Decision Latency**.
3. **Run History & Side-by-Side Comparison:**
   - Filterable table of past workflow runs (filter by status or target URL substring).
   - Ability to select any two runs (`Run A` and `Run B`) and click **"Compare Selected Runs"** to inspect how a target change or admin threshold/rule change affected the score, rule verdicts, and generated CSP.
4. **Admin & Audit Console (Admin Role):**
   - View/edit allowlisted hosts (`allowlist`), `passScoreThreshold`, and toggle individual security rules or weights (`PUT /api/admin/config`) with confirmation prompt.
   - Filterable **Append-Only Audit Log** viewer (`GET /api/audit/logs`) filtering by outcome (`SUCCESS`, `DENIED`, `FAILURE`) or action.
