# Technical Limitations & Ethical Scope Statement

**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | **Domain:** Web Security  
**Lead Author:** Tayyab Khalid

---

## 1. Known Technical Limitations

While CSP Architect provides a complete, deterministic 6-stage pipeline (`FR-1` through `FR-6`) for browser security header analysis and least-privilege Content Security Policy synthesis, operators and auditors should account for the following architectural boundaries:

1. **Static HTML DOM Parsing vs. Dynamic Runtime JS Execution (`FR-1`):**
   - The local crawler (`src/engine/crawler.js`) fetches the HTTP response and parses the HTML DOM statically using `cheerio`.
   - Scripts, stylesheets, or iframes injected dynamically at runtime via complex client-side JavaScript frameworks (e.g., lazy-loaded webpack chunks fetched after user interaction) will not be visible during the initial static HTML parse unless they are represented in the HTML document or captured via Stage 4's live browser `csp-report` endpoint (`POST /api/engine/csp-report`).
2. **Inline Event Handler Refactoring Requirement (`FR-3` & `FR-4`):**
   - Per the W3C CSP Level 2/3 specification, cryptographic SHA-256 hashes (`'sha256-...'`) in `script-src` apply to `<script>` blocks (and in CSP3 with `'unsafe-hashes'` to specific attributes, which is discouraged for high-assurance policies).
   - Therefore, CSP Architect intentionally refuses to weaken policies with `'unsafe-inline'` when inline event attributes (`onclick`, `onerror`, `onload`) are discovered; instead, it flags them as `script-src-attr` violations and guides developers to refactor them into `addEventListener()` bindings.
3. **Single-Page Depth Crawl per Pipeline Execution:**
   - Each pipeline run evaluates a single specified target URL (`targetUrl`) rather than spidering multi-depth hyperlinks automatically. This guarantees predictable, bounded latency (`< 15 ms` per local run) and prevents accidental recursive crawling loops.
4. **In-Memory Rate Limiting Window:**
   - The sliding-window rate limiter (`createRateLimiter` in `src/middleware/security.js`) stores request counters in process memory, which is appropriate for a single-node local workbench deployment. Multi-node horizontal deployments would require a shared Redis store.

---

## 2. Ethical Scope & Defensive Guardrails

CSP Architect is designed **exclusively as a defensive security engineering workbench** for authorized local web applications and classroom test fixtures.

### Mandatory Ethical Controls Implemented in Code

1. **Strict Local Allowlist Enforcement (`T6` / SSRF Prevention):**
   - By default, `systemConfig.allowlist` restricts all outbound crawler connections strictly to `localhost` and `127.0.0.1` (`src/contracts/schemas.js` & `src/engine/crawler.js`).
   - Any attempt to target external internet domains (e.g., `https://evil.example.com`) or cloud instance metadata endpoints (`http://169.254.169.254`) is blocked **before** any DNS resolution or TCP socket connection occurs, returning `403 ERR_ALLOWLIST_DENIED` and recording a permanent `DENIED` entry in the append-only audit trail.
2. **Zero Offensive Exploitation Payloads:**
   - The workbench evaluates HTTP headers and extracts DOM resource declarations passively. It never submits destructive payloads, SQL injection strings, or active exploit vectors to target servers.
3. **Self-Contained Vulnerable Fixtures (`/fixtures/*`):**
   - All adversarial test scenarios (`T1` XSS, `T2` Inline Scripts, `T3` Third-Party Wildcard, `T4` Clickjacking, `T5` MIME Sniffing) are hosted locally inside `src/fixtures/fixturesRouter.js` so students and instructors can safely reproduce every vulnerability class offline without interacting with third-party websites.
4. **Privacy & Credential Redaction (`redactSensitiveData`):**
   - All exported JSON reports and stored audit logs automatically redact passwords, session cookies, bearer tokens, and CSRF secrets (`[REDACTED]`) to prevent accidental credential disclosure during security audits.
