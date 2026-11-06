# 15-Minute Classroom Live Demonstration Script

**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Total Duration:** 12-15 Minutes  
**Presenters:** Tayyab Khalid, Abdul Nafay Khan Burki, Muhammad Ibrahim Alam, Fasih Ur Rehman

---

## Pre-Demo Checklist (Before Stepping to the Podium)

1. Open a terminal in the project root and start the server:
   ```bash
   npm start
   ```
2. Open a browser to `http://localhost:3000`.
3. Keep a second terminal tab ready to run `npm test` and `npm run eval`.

---

## Part 1: Architecture, Manual Authentication & Normal Baseline (0:00 - 3:00)

1. **Show the Login Screen (`0:00 - 1:00`):**
   - Point out that the login screen contains **no hardcoded demo credentials or auto-fill buttons** to enforce realistic authentication hygiene.
   - Manually sign in as **Security Operator**:
     - **Username:** `operator`
     - **Password:** `Operator@CSP2026!`
2. **Run Normal Baseline (`/fixtures/normal-safe`) (`1:00 - 3:00`):**
   - Select **`/fixtures/normal-safe`** from the Target Preset dropdown and click **"Run Full 6-Stage Pipeline"**.
   - Highlight the **Before Score (`100/100`, Grade `A`, `PASS`)**, **0 Critical Warnings**, and **10/10 Passed Rules** in Stage 2 (`FR-2`), proving **0% False Positives** on a properly hardened application.

---

## Part 2: Core 6-Stage Workflow & Adverse Cases `T1`-`T6` (3:00 - 8:00)

1. **Demonstrate `T1` (`/fixtures/t1-xss` - Missing CSP, DOM XSS & `eval()`) (`3:00 - 5:00`):**
   - Select **`/fixtures/t1-xss`** and click **"Run Full 6-Stage Pipeline"**.
   - Walk through each stage panel:
     - **Stage 1 (`FR-1` Crawler):** Shows extracted `eval()`, `document.write`, and inline `onerror="alert(1)"`.
     - **Stage 2 (`FR-2` Header Analysis):** Flags `HDR-CSP-PRESENT` (`CRITICAL`) and missing companion headers.
     - **Stage 3 (`FR-3` CSP Builder):** Synthesizes `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'` plus companion headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).
     - **Stage 4 (`FR-4` Violation Collector):** Lists simulated violations blocking the inline `onerror` and `eval()` payloads, then click **"Trigger Live Browser Sandbox Violation"** to fire a real W3C `csp-report` POST from the browser iframe!
     - **Stage 5 (`FR-5` Before/After Score):** Shows posture jumping from **`7/100` (`F`, `FAIL`)** to **`95/100` (`A`, `PASS`)**.
     - **Stage 6 (`FR-6` Export):** Click **"Download Raw HTTP Headers (`.txt`)"** and **"Download Sanitized JSON Report (`.json`)"**.
2. **Demonstrate `T2` Inline SHA-256 Hashing & Interactive Re-Run (`5:00 - 6:30`):**
   - Select **`/fixtures/t2-inline`** and run the pipeline.
   - Show the computed `'sha256-...'` hashes for legitimate inline `<script>` and `<style>` blocks while `onclick` is flagged as a `script-src-attr` violation.
   - Toggle policy options in Stage 3 (`allowFramingSelf` or hash mode) and click **"Re-run Stage"** to show interactive policy tuning.
3. **Demonstrate `T6` Allowlist & SSRF Rejection (`6:30 - 8:00`):**
   - Select or enter `https://evil.example.com/attack` (or `http://169.254.169.254/latest/meta-data`) and click **"Run Full 6-Stage Pipeline"**.
   - Show the immediate **`403 ERR_ALLOWLIST_DENIED`** banner - blocked prior to any network request.

---

## Part 3: RBAC Denial (`viewer`), Admin Policy Change & Run Comparison (8:00 - 12:00)

*(Matches the exact "Illustrative Working Example" from the project specification)*

1. **Restricted `viewer` Role Verification (`8:00 - 9:30`):**
   - Log out and sign in as **Restricted Viewer**:
     - **Username:** `viewer`
     - **Password:** `Viewer@CSP2026!`
   - Open **Run History** - confirm `viewer` can read past runs (`200 OK`).
   - Attempt to run a pipeline or download a JSON/Header export - point out the **`403 ERR_AUTH_FORBIDDEN`** denial message and explain that the attempt was just recorded in the append-only audit trail.
2. **Admin Rule/Threshold Update & Side-by-Side Comparison (`9:30 - 12:00`):**
   - Log out and sign in as **Administrator**:
     - **Username:** `admin`
     - **Password:** `Admin@CSP2026!`
   - Open the **Admin & Audit Console** tab.
   - Change `passScoreThreshold` from `75` to `98` (or toggle a rule) and click **"Save Configuration"**.
   - Return to the **6-Stage Workbench**, re-run `/fixtures/t4-clickjacking` (or `/fixtures/t1-xss`), then open **Run History & Comparison**, select the pre-change run (`Run A`) and post-change run (`Run B`), and click **"Compare Selected Runs"** to display the side-by-side policy and threshold diff.
   - Switch to the **Audit Log Viewer** in the Admin Console and filter by `DENIED` and `SUCCESS` to show the `ALLOWLIST_DENIED`, viewer `ERR_AUTH_FORBIDDEN`, `ADMIN_CONFIG_UPDATE`, and `PIPELINE_RUN` audit entries.

---

## Part 4: Automated One-Click Evaluation & CLI Verification (12:00 - 15:00)

1. **In-Browser Evaluation Suite (`12:00 - 13:00`):**
   - Click the **Evaluation & Metrics (`T1`-`T6`)** tab and click **"Run Full Evaluation Suite"**.
   - Show the live badge metrics: **100% Rule Coverage, 0% False Positive Rate, 0% False Negative Rate**, and per-case latency.
2. **Terminal Automated Test & CLI Benchmark (`13:00 - 15:00`):**
   - Switch to the terminal and run:
     ```bash
     npm run eval
     npm test
     ```
   - Conclude by showing all automated `node:test` suites (`evaluation_t1_t6.test.js` and `security_t_final.test.js`, including SQLite restart persistence and rate limiting) passing with zero errors.
