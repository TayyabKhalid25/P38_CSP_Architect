# User, Operator & Administrator Guide

**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Lead Author:** Tayyab Khalid

---

## 1. Prerequisites & Local Installation

- **Runtime:** Node.js `>= 22.5.0` (uses Node's built-in `node:sqlite` and `node:test` modules - zero native C++ build toolchains required).
- **OS Support:** Windows, macOS, and Linux.

### Quick Start Commands
```bash
# 1. Install dependencies
npm install

# 2. Start the CSP Architect workbench server (default: http://localhost:3000)
npm start

# 3. Run automated verification suites (T1-T6 + T-final)
npm test

# 4. Run CLI evaluation benchmark and metrics report
npm run eval
```

---

## 2. Manual Login Credentials & Role Matrix

> [!IMPORTANT]
> For operational security, **no credentials, password hints, or auto-fill buttons are rendered on the browser login screen**. Users must manually type the credentials below into the login form at `http://localhost:3000`.

| Role | Username | Password | Permitted Actions | Forbidden Actions (`403 ERR_AUTH_FORBIDDEN`) |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@CSP2026!` | Full access: 6-stage pipeline, evaluation suite, run history, side-by-side comparison, raw HTTP header & JSON exports, Admin rule/threshold/allowlist configuration, and Append-Only Audit Log viewer. | None (all actions logged in `audit_logs`). |
| **Security Operator** | `operator` | `Operator@CSP2026!` | Execute 1-click & step-by-step 6-stage pipeline (`FR-1`-`FR-6`), run `T1`-`T6` evaluation suite, view & compare runs, and export Raw HTTP Header (`.txt`) & Sanitized JSON (`.json`) artifacts. | Modifying `system_config` (`/api/admin/*`) and viewing `/api/audit/logs`. |
| **Restricted Viewer** | `viewer` | `Viewer@CSP2026!` | Read-only access to inspect past workflow runs (`GET /api/reports/runs`) and compare two existing runs (`GET /api/reports/compare`). | Executing crawls/pipelines, exporting `.txt`/`.json` bundles, modifying admin config, or reading raw audit logs. |

---

## 3. Operator Guide: Using the 6-Stage Workbench (`FR-1` to `FR-6`)

1. **Log in as `operator`** (`operator` / `Operator@CSP2026!`).
2. **Select a Target Application:**
   - Choose one of the built-in local evaluation fixtures from the preset selector:
     - `/fixtures/normal-safe` - Hardened baseline web application
     - `/fixtures/t1-xss` - Missing CSP + DOM XSS sink + `eval()` + inline `onerror`
     - `/fixtures/t2-inline` - Safe inline `<script>`/`<style>` blocks + unsafe `onclick` attribute
     - `/fixtures/t3-third-party` - Overly permissive `default-src * 'unsafe-inline'` + external trackers
     - `/fixtures/t4-clickjacking` - Sensitive form missing `X-Frame-Options` & `frame-ancestors`
     - `/fixtures/t5-mime-sniffing` - Missing `X-Content-Type-Options: nosniff` & `object-src 'none'`
     - `https://evil.example.com/attack` - Unapproved external host (demonstrates `T6` allowlist rejection)
   - Or type any custom URL on an approved local host (`http://localhost:3000/...` or `http://127.0.0.1:3000/...`).
3. **Choose Execution Mode:**
   - **One-Click Full Pipeline:** Click **"Run Full 6-Stage Pipeline"** to execute `FR-1` through `FR-6` in sequence, persist the workflow run in SQLite, and populate all 6 stage cards.
   - **Interactive Step-by-Step Mode:** Use the per-stage controls to run or re-run individual stages (`1. Crawler`, `2. Header Analysis`, `3. CSP Builder`, `4. Violation Collector`, `5. Before/After Score`, `6. Downloadable Config`). Toggle policy options (such as SHA-256 inline hashing or `frame-ancestors 'self'` vs `'none'`) and observe real-time changes in simulated violations and posture scores.
4. **Trigger Live Browser W3C Violation Reports (`FR-4`):**
   - In Stage 4, click **"Trigger Live Browser Sandbox Violation"** to load `/fixtures/sandbox-frame` in a sandboxed iframe. Your browser will enforce `Content-Security-Policy-Report-Only` and dispatch a real W3C `csp-report` payload to `POST /api/engine/csp-report`.
5. **Download Hardened Configurations (`FR-6`):**
   - In Stage 6 (or from the Run History table), click:
     - **Download Raw HTTP Headers (`.txt`)** - Ready-to-deploy `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` headers.
     - **Download Sanitized JSON Report (`.json`)** - Complete reproducible decision, score breakdown, and evidence bundle with all sensitive tokens redacted.

---

## 4. Administrator Guide: Policy Tuning, Comparison & Audit Inspection

1. **Log in as `admin`** (`admin` / `Admin@CSP2026!`).
2. **Navigate to the Admin & Audit Console Tab:**
   - **Allowlist Management:** Add or remove approved local hostnames (`allowlist`, default `localhost`, `127.0.0.1`) and ports (`allowedPorts`).
   - **Posture Thresholds:** Adjust `passScoreThreshold` (default `75`) and `criticalWarningThreshold` (default `50`).
   - **Rule Toggles & Weights:** Enable/disable any of the 10 security rules (`HDR-CSP-PRESENT` through `HDR-REFERRER-POLICY`) or adjust their point weights.
   - Click **"Save Configuration"** (or **"Reset to Defaults"**) to persist changes in SQLite and record an immutable configuration change entry in `audit_logs`.
3. **Compare Runs Before and After Policy Changes:**
   - Open the **Run History & Comparison** tab, select two runs (`Run A` before the rule/threshold change and `Run B` after), and click **"Compare Selected Runs"** to inspect the score delta, rule verdict diffs, and CSP directive changes.
4. **Inspect the Append-Only Audit Trail:**
   - Filter audit events by outcome (`SUCCESS`, `DENIED`, `FAILURE`), action (`AUTH_LOGIN`, `PIPELINE_RUN`, `ALLOWLIST_DENIED`, `ADMIN_CONFIG_UPDATE`), or actor username (`admin`, `operator`, `viewer`, `anonymous`).
