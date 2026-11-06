# 00 - Master System Architecture & Interface Contracts
**Project:** Proposal 38 - CSP Architect: Browser Security Header Workbench  
**Course / Group:** Class 3, Group 6 | Domain: Web Security  
**Lead Architect:** Tayyab Khalid

---

## 1. Purpose of This Master Contract
Every member of Group 6 works on an isolated Git branch (`feat/nafay-backend-auth`, `feat/ibrahim-security-engine`, `feat/fasih-frontend-ui`, `feat/tayyab-qa-automation-docs`). To guarantee **zero merge conflicts** and **100% plug-and-play compatibility** when branches merge into `main`, every module MUST adhere strictly to the file ownership boundaries, database schemas, normalized stage payloads, and HTTP API contracts defined here and in `src/contracts/schemas.js`.

---

## 2. Strict File Ownership Matrix (Zero Overlap Rule)

**No agent may create or modify any file outside their assigned paths.**

| Team Member | Git Branch | Git Author Identity | Exclusive File Paths Owned |
| :--- | :--- | :--- | :--- |
| **Shared Foundation** | `main` (Pre-committed) | `Tayyab Khalid <146368050+TayyabKhalid25@users.noreply.github.com>` | `package.json`, `package-lock.json`, `server.js`, `src/contracts/schemas.js`, `Docs/plans/*` |
| **Abdul Nafay Khan Burki** | `feat/nafay-backend-auth` | `Abdul Nafay Khan Burki <165305926+abdulnafaykhan@users.noreply.github.com>` | `src/app.js`, `src/db/database.js`, `src/repositories/repo.js`, `src/middleware/security.js`, `src/routes/auth.js`, `src/routes/admin.js`, `src/routes/audit.js` |
| **Muhammad Ibrahim Alam** | `feat/ibrahim-security-engine` | `Muhammad Ibrahim Alam <148635265+Ibrahim-Alam-3075@users.noreply.github.com>` | `src/engine/crawler.js`, `src/engine/headerAnalyzer.js`, `src/engine/cspBuilder.js`, `src/engine/violationCollector.js`, `src/engine/scorer.js`, `src/engine/exporter.js`, `src/engine/index.js`, `src/fixtures/fixturesRouter.js`, `src/routes/engine.js` |
| **Fasih Ur Rehman** | `feat/fasih-frontend-ui` | `Fasih Ur Rehman <215206356+fasih-ur-rehman1@users.noreply.github.com>` | `public/index.html`, `public/css/styles.css`, `public/js/app.js`, `src/routes/reports.js` |
| **Tayyab Khalid** | `feat/tayyab-qa-automation-docs` | `Tayyab Khalid <146368050+TayyabKhalid25@users.noreply.github.com>` | `tests/*.test.js`, `scripts/run_evaluation.js`, `README.md`, `Docs/ARCHITECTURE_AND_DFD.md`, `Docs/THREAT_MODEL.md`, `Docs/TEST_PLAN_AND_RESULTS.md`, `Docs/USER_AND_ADMIN_GUIDE.md`, `Docs/LIMITATIONS_AND_ETHICS.md`, `Docs/FINAL_REPORT.md`, `Docs/DEMO_SCRIPT_15MIN.md` |

---

## 3. Normalized 6-Stage Data Flow Schemas

Each stage (`FR-1` through `FR-6`) outputs a validated, normalized object containing `stage`, `status` (`COMPLETED` | `REJECTED` | `WARNING`), `evidence` (array of explainable findings), and stage-specific normalized fields:

### Stage 1 (`FR-1`: Local Crawler Output - `crawlResult`)
```json
{
  "stage": "FR-1_CRAWLER",
  "status": "COMPLETED",
  "targetUrl": "http://localhost:3000/fixtures/t1-xss",
  "normalizedOrigin": "http://localhost:3000",
  "httpStatus": 200,
  "rawHeaders": { "content-type": "text/html; charset=utf-8" },
  "resources": {
    "externalScripts": ["http://localhost:3000/static/app.js"],
    "inlineScripts": [{ "index": 0, "preview": "const x = 1;", "sha256": "sha256-..." }],
    "inlineEventHandlers": [{ "tag": "button", "attr": "onclick", "code": "alert(1)" }],
    "usesEvalOrFunction": false,
    "externalStyles": [],
    "inlineStyles": [{ "index": 0, "sha256": "sha256-..." }],
    "images": ["http://localhost:3000/logo.png"],
    "frames": [],
    "forms": [{ "action": "/submit", "method": "POST" }],
    "connectOrigins": []
  },
  "evidence": [
    { "code": "CRAWL-ALLOWLIST-OK", "severity": "INFO", "message": "Target host localhost:3000 verified against allowlist." }
  ]
}
```

### Stage 2 (`FR-2`: Header Analysis Output - `headerAnalysis`)
```json
{
  "stage": "FR-2_HEADER_ANALYSIS",
  "status": "COMPLETED",
  "engineVersion": "1.0.0",
  "existingCspRaw": null,
  "parsedDirectives": {},
  "findings": [
    {
      "ruleId": "HDR-CSP-PRESENT",
      "ruleName": "Content-Security-Policy Header Present",
      "category": "CSP Core",
      "severity": "CRITICAL",
      "passed": false,
      "weight": 25,
      "reason": "No Content-Security-Policy header was found in the response.",
      "evidence": "Header 'content-security-policy' is absent.",
      "remediation": "Add a restrictive Content-Security-Policy response header."
    }
  ],
  "summary": { "totalRules": 10, "passedRules": 2, "failedRules": 8, "criticalCount": 1, "highCount": 4 }
}
```

### Stage 3 (`FR-3`: CSP Builder Output - `cspBuild`)
```json
{
  "stage": "FR-3_CSP_BUILDER",
  "status": "COMPLETED",
  "mode": "strict-hash",
  "directives": {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'sha256-...'"],
    "style-src": ["'self'", "'sha256-...'"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"]
  },
  "cspHeaderString": "default-src 'self'; script-src 'self' 'sha256-...'; ...",
  "recommendedCompanionHeaders": {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  },
  "decisions": [
    { "directive": "script-src", "decision": "Added 1 SHA-256 hash for legitimate inline script; blocked 1 unsafe inline event handler.", "evidence": "Inline handler onclick=alert(1) cannot be hashed safely without refactoring." }
  ]
}
```

### Stage 4 (`FR-4`: Violation-Report Collector Output - `violationAnalysis`)
```json
{
  "stage": "FR-4_VIOLATION_COLLECTOR",
  "status": "COMPLETED",
  "totalViolations": 2,
  "violations": [
    {
      "source": "simulation",
      "violatedDirective": "script-src-attr",
      "effectiveDirective": "script-src",
      "blockedUri": "inline",
      "disposition": "enforce",
      "sample": "onclick=\"alert(1)\"",
      "explanation": "Inline event handler blocked because 'unsafe-inline' is disallowed by least-privilege CSP."
    }
  ]
}
```

### Stage 5 (`FR-5`: Before/After Score Output - `scoreComparison`)
```json
{
  "stage": "FR-5_BEFORE_AFTER_SCORE",
  "status": "COMPLETED",
  "passThreshold": 75,
  "before": {
    "score": 15,
    "grade": "F",
    "status": "FAIL",
    "breakdown": []
  },
  "after": {
    "score": 95,
    "grade": "A",
    "status": "PASS",
    "breakdown": []
  },
  "delta": 80,
  "explanation": "Applying the synthesized least-privilege CSP and companion headers increases posture from 15/100 (F) to 95/100 (A), mitigating XSS, Clickjacking, and MIME sniffing."
}
```

### Stage 6 (`FR-6`: Downloadable Configuration Output - `exportBundle`)
```json
{
  "stage": "FR-6_DOWNLOADABLE_CONFIG",
  "status": "COMPLETED",
  "rawHttpHeaderBlock": "Content-Security-Policy: default-src 'self'; ...\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin",
  "sanitizedJsonReport": {
    "reportVersion": "1.0.0",
    "generatedAt": "2026-11-06T00:00:00.000Z",
    "targetUrl": "http://localhost:3000/fixtures/t1-xss",
    "decision": "HARDENED_POLICY_GENERATED",
    "beforeScore": 15,
    "afterScore": 95,
    "headers": {},
    "evidenceSummary": []
  }
}
```

---

## 4. Standard API Response & Error Envelope

- **Success:** `{ "ok": true, "data": { ... } }`
- **Failure:** `{ "ok": false, "error": { "code": "ERR_...", "message": "Safe human-readable explanation", "details": null } }`
- Stack traces and internal file paths must **never** be returned in HTTP responses.
