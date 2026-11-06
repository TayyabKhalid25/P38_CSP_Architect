# 02 - Muhammad Ibrahim Alam: Dedicated Security Engine & Test Fixtures Plan
**Owner:** Muhammad Ibrahim Alam  
**Git Branch:** `feat/ibrahim-security-engine`  
**Git Author:** `Muhammad Ibrahim Alam <148635265+Ibrahim-Alam-3075@users.noreply.github.com>`  
**Assigned Layers:** Layer 3 (Dedicated Security Engine: `FR-1` to `FR-6`) & Layer 5 (Local Target Fixtures `T1`-`T6`)

---

## 1. Exclusive File Ownership
You may **only** create/modify the following files:
1. `src/engine/crawler.js` - `FR-1`: Allowlist verification, SSRF defense, local HTTP crawler, and Cheerio DOM resource/hash extractor.
2. `src/engine/headerAnalyzer.js` - `FR-2`: CSP directive parser and 10-rule browser security header evaluator.
3. `src/engine/cspBuilder.js` - `FR-3`: Least-privilege CSP synthesizer (SHA-256 hashes, nonces, strict presets, companion headers).
4. `src/engine/violationCollector.js` - `FR-4`: Deterministic policy violation simulator + real browser `csp-report` normalizer.
5. `src/engine/scorer.js` - `FR-5`: Weighted before/after security posture scoring engine with explainable deduction/credit breakdown.
6. `src/engine/exporter.js` - `FR-6`: Raw HTTP response header block generator and sanitized JSON evidence bundle exporter.
7. `src/engine/index.js` - Orchestrator exporting all 6 stage functions plus `runFullPipeline(targetUrl, options, systemConfig)`.
8. `src/fixtures/fixturesRouter.js` - Local target web application routes mounted at `/fixtures` representing `T1` through `T6` plus a safe baseline (`/fixtures/normal-safe`).
9. `src/routes/engine.js` - Express router mounted at `/api/engine` exposing individual stage endpoints (`POST /crawl`, `POST /analyze-headers`, `POST /build-csp`, `POST /collect-violations`, `POST /score`, `POST /export`, `POST /run-pipeline`, `POST /csp-report`, `POST /evaluate-suite`).

---

## 2. Detailed Stage Specifications (`src/engine/*`)

### `FR-1`: `crawler.js`
- **Exports:** `validateTargetUrl(targetUrl, systemConfig)`, `crawlTarget({ targetUrl, rawHtml, rawHeaders }, systemConfig)`
- **Allowlist & SSRF Protection:**
  - Parse `targetUrl` with `new URL(targetUrl)`.
  - Reject if protocol is not `http:` or `https:`.
  - Reject if `hostname` is not in `systemConfig.allowlist` (default `['localhost', '127.0.0.1']`).
  - Reject if credentials (`url.username` or `url.password`) are present in URL.
  - On rejection, throw `new AppError(ERROR_CODES.ERR_ALLOWLIST_DENIED, 'Target host is not on the approved local allowlist.', 403, { targetUrl, hostname })`.
- **DOM & Resource Extraction (Cheerio):**
  - Extract external `<script src>`, inline `<script>` contents (computing `sha256-<base64>` hash for each non-empty inline script), inline event attributes (`onclick`, `onload`, `onerror`, `onmouseover`, `onsubmit`, `onfocus`), detection of `eval(` or `new Function(` or `setTimeout("..."` in inline scripts, `<link rel="stylesheet" href>`, inline `<style>` hashes, `<img src>`, `<iframe src>`, `<form action>`, and `<object data>` / `<embed src>`.
  - Detect potential reflected/DOM XSS sinks (`innerHTML`, `document.write`, unescaped query reflection markers).

### `FR-2`: `headerAnalyzer.js`
- **Exports:** `parseCsp(cspString)`, `analyzeHeaders(crawlResult, systemConfig)`
- Evaluates all enabled rules in `systemConfig.rules` (`HDR-CSP-PRESENT`, `HDR-CSP-NO-UNSAFE-INLINE`, `HDR-CSP-NO-UNSAFE-EVAL`, `HDR-CSP-NO-WILDCARD`, `HDR-CSP-FRAME-ANCESTORS`, `HDR-CSP-OBJECT-SRC`, `HDR-CSP-BASE-URI`, `HDR-XFO-SAMEORIGIN`, `HDR-XCTO-NOSNIFF`, `HDR-REFERRER-POLICY`).
- Every finding records `{ ruleId, ruleName, category, severity, passed, weight, reason, evidence, remediation }`.

### `FR-3`: `cspBuilder.js`
- **Exports:** `buildCsp(crawlResult, headerAnalysis, options = {}, systemConfig)`
- `options`: `{ mode: 'strict-hash' | 'nonce' | 'strict-origin', allowInlineHashes: true, allowFramingSelf: false, allowedThirdPartyOrigins: [], includeReportUri: true }`
- Constructs least-privilege directives:
  - `default-src 'self'`
  - `script-src`: `'self'` + SHA-256 hashes of safe inline scripts (specifically excluding scripts containing dangerous XSS sinks like `eval(`, `document.write(`, `innerHTML =` when flagging suspicious inline scripts) + any explicitly approved origins.
  - `style-src`: `'self'` + SHA-256 hashes of inline styles.
  - `img-src`: `'self'` + approved local image origins.
  - `connect-src`: `'self'`
  - `object-src`: `'none'`
  - `base-uri`: `'self'`
  - `form-action`: `'self'`
  - `frame-ancestors`: `'self'` if `allowFramingSelf` else `'none'`
  - `report-uri`: `/api/engine/csp-report` (when `includeReportUri !== false`)
- Returns `directives`, `cspHeaderString`, `recommendedCompanionHeaders` (`X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`), and explainable `decisions`.

### `FR-4`: `violationCollector.js`
- **Exports:** `simulateViolations(crawlResult, cspBuild)`, `normalizeBrowserReport(payload, runId)`
- Deterministically tests every resource discovered in `crawlResult` against `cspBuild.directives`:
  - Flags inline event handlers (`onclick=...`) as `script-src-attr` violations (`blockedUri: 'inline'`).
  - Flags unhashed or dangerous inline scripts (e.g., XSS payloads or `eval()`) as `script-src` / `unsafe-eval` violations.
  - Flags untrusted third-party script/img/frame origins not in `cspBuild.directives` as `script-src` / `img-src` / `frame-src` violations.
  - Flags clickjacking embed attempts if `frame-ancestors 'none'` blocks external framing.
  - Flags MIME-sniffing risk when `X-Content-Type-Options: nosniff` blocks ambiguous script execution.

### `FR-5`: `scorer.js`
- **Exports:** `calculateBeforeAfterScore(crawlResult, headerAnalysis, cspBuild, violationAnalysis, systemConfig)`
- Uses `analyzeHeaders` on the baseline `crawlResult.rawHeaders` for `before`, and runs `analyzeHeaders` on a synthesized post-hardening header map (`Content-Security-Policy: cspBuild.cspHeaderString` + `recommendedCompanionHeaders`) for `after`.
- Applies additional risk penalties if active unmitigated XSS/clickjacking/MIME vectors remain, normalizes score to `0-100`, assigns letter grade (`A`, `B`, `C`, `D`, `F`), compares against `systemConfig.passScoreThreshold`, and produces an itemized `breakdown`.

### `FR-6`: `exporter.js`
- **Exports:** `generateExportBundle({ runId, crawlResult, headerAnalysis, cspBuild, violationAnalysis, scoreComparison })`
- Produces **only** the two user-approved formats:
  1. `rawHttpHeaderBlock`: Multi-line raw HTTP response header text (`Content-Security-Policy: ...`, `X-Frame-Options: ...`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: ...`).
  2. `sanitizedJsonReport`: Complete reproducible decision and evidence record scrubbed via `redactSensitiveData()`.

---

## 3. Built-in Target Fixtures (`src/fixtures/fixturesRouter.js`)
Mounted at `/fixtures`:
- `GET /fixtures` - returns JSON catalog of available fixtures.
- `GET /fixtures/normal-safe` - Baseline properly-configured local application (delivers full CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, external same-origin script only).
- `GET /fixtures/t1-xss` - **T1 (XSS Test Fixture)**: Missing CSP, contains reflected/DOM XSS sink (`document.write(location.hash)`), `eval()`, and inline `onerror` payload.
- `GET /fixtures/t2-inline` - **T2 (Inline Scripts Fixture)**: Contains legitimate inline configuration `<script>`, inline `<style>`, and an inline `onclick` handler requiring hash/refactoring analysis.
- `GET /fixtures/t3-third-party` - **T3 (Third-Party Resource Simulation)**: Loads scripts and images from untrusted external origins (`https://cdn.untrusted-analytics.example/tracker.js`, `https://ads.external-network.example/pixel.png`) with an overly permissive `Content-Security-Policy: default-src * 'unsafe-inline'`.
- `GET /fixtures/t4-clickjacking` - **T4 (Clickjacking Fixture)**: Sensitive account action form delivered without `X-Frame-Options` and without `frame-ancestors` in CSP.
- `GET /fixtures/t5-mime-sniffing` - **T5 (MIME Sniffing Fixture)**: Page + user-upload script endpoint missing `X-Content-Type-Options: nosniff` and missing `object-src 'none'`.
- `GET /fixtures/t6-allowlist` - **T6 (Allowlist Enforcement Info & Local Endpoint)**: Valid local fixture paired with external SSRF rejection test cases (`https://evil.example.com/attack`).
- `GET /fixtures/sandbox-frame` - Live interactive HTML page used by the UI iframe sandbox that sets `Content-Security-Policy-Report-Only` with `report-uri /api/engine/csp-report` so the user's real browser fires live W3C CSP violation POST requests.
