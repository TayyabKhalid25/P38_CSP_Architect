'use strict';

/**
 * Automated Evaluation Suite: Mandatory Test Cases T1 through T6 + Baseline
 * Proposal 38 — CSP Architect: Browser Security Header Workbench
 * Owner: Tayyab Khalid (QA, Automation & Documentation Lead)
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const request = require('supertest');

// Use an isolated test SQLite database so evaluation tests are 100% deterministic
const TEST_DB_DIR = path.join(__dirname, '../data');
if (!fs.existsSync(TEST_DB_DIR)) {
  fs.mkdirSync(TEST_DB_DIR, { recursive: true });
}
process.env.DB_PATH = path.join(TEST_DB_DIR, 'test_eval_t1_t6.sqlite');
process.env.NODE_ENV = 'test';

const { startServer } = require('../server');
const { resetDbForTests } = require('../src/db/database');
const repo = require('../src/repositories/repo');
const { ERROR_CODES } = require('../src/contracts/schemas');

/**
 * Normalizes pipeline response payload so assertions work consistently across stage keys
 */
function extractStages(payload) {
  const data = payload?.data || payload || {};
  const stages = data.stages || data;
  return {
    runId: data.id || data.runId || stages.runId,
    status: data.status || stages.status || 'COMPLETED',
    beforeScore:
      typeof data.beforeScore === 'number'
        ? data.beforeScore
        : stages.scoreComparison?.before?.score,
    afterScore:
      typeof data.afterScore === 'number'
        ? data.afterScore
        : stages.scoreComparison?.after?.score,
    crawlResult: stages.crawlResult || stages.stage1 || stages['FR-1_CRAWLER'],
    headerAnalysis: stages.headerAnalysis || stages.stage2 || stages['FR-2_HEADER_ANALYSIS'],
    cspBuild: stages.cspBuild || stages.stage3 || stages['FR-3_CSP_BUILDER'],
    violationAnalysis:
      stages.violationAnalysis || stages.stage4 || stages['FR-4_VIOLATION_COLLECTOR'],
    scoreComparison:
      stages.scoreComparison || stages.stage5 || stages['FR-5_BEFORE_AFTER_SCORE'],
    exportBundle: stages.exportBundle || stages.stage6 || stages['FR-6_DOWNLOADABLE_CONFIG'],
  };
}

/**
 * Helper to authenticate a user and extract session cookie + CSRF token
 */
async function authenticate(baseUrl, username, password) {
  const res = await request(baseUrl)
    .post('/api/auth/login')
    .send({ username, password })
    .set('Content-Type', 'application/json');

  assert.equal(
    res.status,
    200,
    `Expected 200 on login for ${username}, got ${res.status}: ${JSON.stringify(res.body)}`
  );
  assert.equal(res.body.ok, true);

  const rawCookies = res.headers['set-cookie'] || [];
  const cookieHeader = (Array.isArray(rawCookies) ? rawCookies : [rawCookies])
    .filter(Boolean)
    .map((c) => c.split(';')[0])
    .join('; ');

  const csrfToken =
    res.body.data?.csrfToken ||
    res.body.data?.user?.csrfToken ||
    res.headers['x-csrf-token'];

  assert.ok(cookieHeader, 'Session cookie must be issued upon login');
  assert.ok(csrfToken, 'CSRF token must be returned upon login');

  return { cookieHeader, csrfToken, user: res.body.data?.user || res.body.data };
}

describe('CSP Architect — Mandatory Evaluation Suite (Baseline & T1–T6)', () => {
  let server;
  let port;
  let baseUrl;
  let operatorAuth;

  before(async () => {
    server = await startServer(0);
    port = server.address().port;
    baseUrl = `http://localhost:${port}`;

    if (typeof resetDbForTests === 'function') {
      resetDbForTests();
    }

    // Ensure the dynamic ephemeral test port is included in allowedPorts if port checking is enabled
    const currentConfig = repo.getSystemConfig();
    const updatedPorts = Array.from(new Set([...(currentConfig.allowedPorts || []), port]));
    repo.updateSystemConfig(
      {
        ...currentConfig,
        allowlist: ['localhost', '127.0.0.1'],
        allowedPorts: updatedPorts,
      },
      'test-harness'
    );

    operatorAuth = await authenticate(baseUrl, 'operator', 'Operator@CSP2026!');
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('Fixture Catalog: GET /fixtures lists all built-in local evaluation targets', async () => {
    const res = await request(baseUrl).get('/fixtures');
    assert.equal(res.status, 200);
    const text = JSON.stringify(res.body);
    assert.ok(text.includes('normal-safe'), 'Catalog must include normal-safe baseline');
    assert.ok(text.includes('t1-xss'), 'Catalog must include t1-xss');
    assert.ok(text.includes('t2-inline'), 'Catalog must include t2-inline');
    assert.ok(text.includes('t3-third-party'), 'Catalog must include t3-third-party');
    assert.ok(text.includes('t4-clickjacking'), 'Catalog must include t4-clickjacking');
    assert.ok(text.includes('t5-mime-sniffing'), 'Catalog must include t5-mime-sniffing');
  });

  it('Baseline (/fixtures/normal-safe): verifies COMPLETED status, high baseline score (>= 85), and 0 critical warnings', async () => {
    const targetUrl = `${baseUrl}/fixtures/normal-safe`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl, options: { mode: 'strict-hash' } });

    assert.equal(res.status, 200, `Pipeline failed: ${JSON.stringify(res.body)}`);
    assert.equal(res.body.ok, true);

    const stages = extractStages(res.body);
    assert.equal(stages.status, 'COMPLETED');
    assert.equal(stages.crawlResult.status, 'COMPLETED');
    assert.equal(stages.headerAnalysis.status, 'COMPLETED');

    // Verify all 10 security header rules pass on normal-safe fixture
    assert.equal(
      stages.headerAnalysis.summary.criticalCount,
      0,
      'Normal-safe baseline must have 0 critical warnings'
    );
    assert.equal(
      stages.headerAnalysis.summary.failedRules,
      0,
      'All 10 default rules should pass on normal-safe fixture'
    );

    // Verify high baseline score
    assert.ok(
      stages.scoreComparison.before.score >= 85,
      `Expected baseline before score >= 85, got ${stages.scoreComparison.before.score}`
    );
    assert.equal(stages.scoreComparison.before.status, 'PASS');
    assert.ok(stages.scoreComparison.after.score >= 90);
  });

  it('T1 (/fixtures/t1-xss): detects missing CSP, DOM XSS sink, eval(), and inline onerror; synthesizes strict CSP and improves score from < 30 to >= 90', async () => {
    const targetUrl = `${baseUrl}/fixtures/t1-xss`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl, options: { mode: 'strict-hash' } });

    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);

    const stages = extractStages(res.body);
    assert.equal(stages.status, 'COMPLETED');

    // FR-1: Verify DOM extraction of eval(), inline event handler (onerror), and XSS sinks
    const resources = stages.crawlResult.resources;
    assert.equal(resources.usesEvalOrFunction, true, 'Must detect eval() usage in T1 fixture');
    assert.ok(
      resources.inlineEventHandlers.some((h) => h.attr === 'onerror' || h.code.includes('alert')),
      'Must detect inline onerror handler in T1 fixture'
    );

    // FR-2: Verify missing CSP header finding (HDR-CSP-PRESENT failed)
    const cspPresentFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-CSP-PRESENT'
    );
    assert.ok(cspPresentFinding, 'HDR-CSP-PRESENT rule must be evaluated');
    assert.equal(cspPresentFinding.passed, false, 'HDR-CSP-PRESENT must fail on T1 fixture');
    assert.equal(cspPresentFinding.severity, 'CRITICAL');

    // FR-3: Verify synthesized CSP is least-privilege without unsafe-inline or unsafe-eval
    const cspString = stages.cspBuild.cspHeaderString;
    assert.ok(cspString.includes("default-src 'self'"), 'Synthesized CSP must set default-src self');
    assert.ok(cspString.includes("script-src 'self'"), 'Synthesized CSP must set script-src self');
    assert.ok(!cspString.includes("'unsafe-inline'"), 'Synthesized CSP must NOT allow unsafe-inline');
    assert.ok(!cspString.includes("'unsafe-eval'"), 'Synthesized CSP must NOT allow unsafe-eval');

    // FR-4: Verify simulated violations captured the blocked inline/eval XSS vectors
    assert.ok(
      stages.violationAnalysis.totalViolations >= 1,
      'Must record simulated CSP violations for T1 XSS vectors'
    );
    assert.ok(stages.violationAnalysis.violations.length >= 1);

    // FR-5: Verify quantitative before/after posture improvement
    assert.ok(
      stages.scoreComparison.before.score < 30,
      `Expected T1 before score < 30, got ${stages.scoreComparison.before.score}`
    );
    assert.equal(stages.scoreComparison.before.status, 'FAIL');
    assert.ok(
      stages.scoreComparison.after.score >= 90,
      `Expected T1 after score >= 90, got ${stages.scoreComparison.after.score}`
    );
    assert.equal(stages.scoreComparison.after.status, 'PASS');
  });

  it('T2 (/fixtures/t2-inline): computes SHA-256 hashes for safe inline script/style blocks and flags inline onclick attribute', async () => {
    const targetUrl = `${baseUrl}/fixtures/t2-inline`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl, options: { mode: 'strict-hash', allowInlineHashes: true } });

    assert.equal(res.status, 200);
    const stages = extractStages(res.body);

    // FR-1: Verify SHA-256 hash generation for inline <script> and <style>
    const { inlineScripts, inlineStyles, inlineEventHandlers } = stages.crawlResult.resources;
    assert.ok(inlineScripts.length >= 1, 'T2 must extract at least 1 inline script block');
    assert.match(
      inlineScripts[0].sha256,
      /^sha256-[A-Za-z0-9+/=]+$/,
      'Inline script must have valid sha256-<base64> hash'
    );

    assert.ok(inlineStyles.length >= 1, 'T2 must extract at least 1 inline style block');
    assert.match(
      inlineStyles[0].sha256,
      /^sha256-[A-Za-z0-9+/=]+$/,
      'Inline style must have valid sha256-<base64> hash'
    );

    assert.ok(
      inlineEventHandlers.some((h) => h.attr === 'onclick'),
      'T2 must extract inline onclick event attribute'
    );

    // FR-3: Verify safe inline script SHA-256 hash is included in synthesized CSP
    assert.ok(
      stages.cspBuild.cspHeaderString.includes("'sha256-"),
      'Synthesized CSP in strict-hash mode must include sha256 hash token'
    );

    // FR-4: Verify inline onclick handler is flagged as a violation requiring refactoring
    assert.ok(
      stages.violationAnalysis.violations.some(
        (v) =>
          v.violatedDirective.includes('script-src') ||
          v.blockedUri === 'inline' ||
          String(v.sample || v.explanation).includes('onclick')
      ),
      'Violation collector must flag unhashable onclick attribute'
    );
  });

  it('T3 (/fixtures/t3-third-party): detects wildcard (*) and unsafe-inline, strips untrusted external origins in synthesized CSP, and records blocking violations', async () => {
    const targetUrl = `http://127.0.0.1:${port}/fixtures/t3-third-party`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl, options: { mode: 'strict-hash', allowedThirdPartyOrigins: [] } });

    assert.equal(res.status, 200);
    const stages = extractStages(res.body);

    // FR-2: Verify detection of wildcard (*) and 'unsafe-inline' in existing header
    const wildcardFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-CSP-NO-WILDCARD'
    );
    const unsafeInlineFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-CSP-NO-UNSAFE-INLINE'
    );
    assert.ok(wildcardFinding && !wildcardFinding.passed, 'Must flag wildcard (*) in T3 CSP');
    assert.ok(
      unsafeInlineFinding && !unsafeInlineFinding.passed,
      'Must flag unsafe-inline in T3 CSP'
    );

    // FR-3: Verify untrusted third-party domains are excluded from synthesized CSP
    const synthesizedCsp = stages.cspBuild.cspHeaderString;
    assert.ok(
      !synthesizedCsp.includes('cdn.untrusted-analytics.example'),
      'Untrusted third-party script origin must be stripped from synthesized CSP'
    );
    assert.ok(
      !synthesizedCsp.includes('ads.external-network.example'),
      'Untrusted third-party image/ad origin must be stripped from synthesized CSP'
    );

    // FR-4: Verify simulated third-party blocking violations are recorded
    assert.ok(
      stages.violationAnalysis.violations.some(
        (v) =>
          v.blockedUri.includes('untrusted-analytics.example') ||
          v.blockedUri.includes('external-network.example') ||
          v.explanation.toLowerCase().includes('third-party') ||
          v.explanation.toLowerCase().includes('external')
      ),
      'Must record violation for blocked untrusted third-party resource'
    );
  });

  it('T4 (/fixtures/t4-clickjacking): detects missing X-Frame-Options and frame-ancestors, and remediates with frame-ancestors none and X-Frame-Options: DENY', async () => {
    const targetUrl = `${baseUrl}/fixtures/t4-clickjacking`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl, options: { allowFramingSelf: false } });

    assert.equal(res.status, 200);
    const stages = extractStages(res.body);

    // FR-2: Verify both clickjacking rules fail on T4 baseline
    const faFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-CSP-FRAME-ANCESTORS'
    );
    const xfoFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-XFO-SAMEORIGIN'
    );
    assert.ok(faFinding && !faFinding.passed, 'Must detect missing frame-ancestors on T4');
    assert.ok(xfoFinding && !xfoFinding.passed, 'Must detect missing X-Frame-Options on T4');

    // FR-3 & FR-6: Verify remediation injects frame-ancestors 'none' and X-Frame-Options: DENY
    assert.ok(
      stages.cspBuild.cspHeaderString.includes("frame-ancestors 'none'"),
      'Synthesized CSP must enforce frame-ancestors none'
    );
    assert.equal(stages.cspBuild.recommendedCompanionHeaders['X-Frame-Options'], 'DENY');
    assert.ok(
      stages.exportBundle.rawHttpHeaderBlock.includes('X-Frame-Options: DENY'),
      'Exported header block must contain X-Frame-Options: DENY'
    );
  });

  it('T5 (/fixtures/t5-mime-sniffing): detects missing X-Content-Type-Options: nosniff and object-src, and remediates both in exported headers', async () => {
    const targetUrl = `${baseUrl}/fixtures/t5-mime-sniffing`;
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl });

    assert.equal(res.status, 200);
    const stages = extractStages(res.body);

    // FR-2: Verify detection of missing X-Content-Type-Options and object-src
    const xctoFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-XCTO-NOSNIFF'
    );
    const objFinding = stages.headerAnalysis.findings.find(
      (f) => f.ruleId === 'HDR-CSP-OBJECT-SRC'
    );
    assert.ok(
      xctoFinding && !xctoFinding.passed,
      'Must detect missing X-Content-Type-Options: nosniff on T5'
    );
    assert.ok(objFinding && !objFinding.passed, 'Must detect missing object-src none on T5');

    // FR-3 & FR-6: Verify remediation in CSP and exported raw HTTP header block
    assert.ok(
      stages.cspBuild.cspHeaderString.includes("object-src 'none'"),
      'Synthesized CSP must enforce object-src none'
    );
    assert.equal(
      stages.cspBuild.recommendedCompanionHeaders['X-Content-Type-Options'],
      'nosniff'
    );
    assert.ok(
      stages.exportBundle.rawHttpHeaderBlock.includes('X-Content-Type-Options: nosniff'),
      'Exported header block must include X-Content-Type-Options: nosniff'
    );
  });

  it('T6 (Allowlist & SSRF Enforcement): rejects unapproved external targets with 403 ERR_ALLOWLIST_DENIED and logs DENIED in audit_logs', async () => {
    const forbiddenTargets = [
      'https://evil.example.com/attack',
      'http://169.254.169.254/latest/meta-data',
    ];

    for (const badUrl of forbiddenTargets) {
      const res = await request(baseUrl)
        .post('/api/engine/run-pipeline')
        .set('Cookie', operatorAuth.cookieHeader)
        .set('X-CSRF-Token', operatorAuth.csrfToken)
        .send({ targetUrl: badUrl });

      assert.equal(
        res.status,
        403,
        `Expected 403 for unapproved target ${badUrl}, got ${res.status}`
      );
      assert.equal(res.body.ok, false);
      assert.equal(res.body.error.code, ERROR_CODES.ERR_ALLOWLIST_DENIED);
    }

    // Verify audit trail recorded the allowlist denial events
    const deniedLogs = repo.listAuditLogs({ outcome: 'DENIED', limit: 20 });
    assert.ok(
      deniedLogs.some(
        (log) =>
          String(log.details_json || log.resource).includes('evil.example.com') ||
          String(log.details_json || log.resource).includes('169.254.169.254') ||
          String(log.action).includes('ALLOWLIST') ||
          String(log.action).includes('PIPELINE') ||
          String(log.action).includes('CRAWL')
      ),
      'Audit log must record DENIED event for unapproved external target URL'
    );
  });

  it('Evaluation Suite Runner (POST /api/engine/evaluate-suite): achieves 100% Rule Coverage, 0% FP Rate, and 0% FN Rate', async () => {
    const res = await request(baseUrl)
      .post('/api/engine/evaluate-suite')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ baseUrl });

    assert.equal(res.status, 200, `evaluate-suite failed: ${JSON.stringify(res.body)}`);
    assert.equal(res.body.ok, true);

    const evalData = res.body.data;
    const metrics = evalData.metrics || evalData.summary || evalData;
    const results = evalData.results || evalData.cases || evalData.tests || [];

    assert.ok(results.length >= 6, `Expected at least 6 evaluation cases, got ${results.length}`);
    assert.ok(
      results.every((r) => r.passed === true || r.status === 'PASS'),
      'Every mandatory test case in evaluate-suite must pass'
    );

    assert.equal(
      Number(metrics.ruleCoveragePercent),
      100,
      'Rule coverage across evaluation corpus must be 100%'
    );
    assert.equal(
      Number(metrics.falsePositiveRate),
      0,
      'False positive rate on normal corpus must be 0%'
    );
    assert.equal(
      Number(metrics.falseNegativeRate),
      0,
      'False negative rate on adverse corpus must be 0%'
    );
  });
});
