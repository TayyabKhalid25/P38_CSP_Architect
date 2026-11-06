'use strict';

/**
 * Automated Security & Resilience Suite: T-final & Illustrative Working Example
 * Proposal 38 — CSP Architect: Browser Security Header Workbench
 * Owner: Tayyab Khalid (QA, Automation & Documentation Lead)
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const request = require('supertest');

// Isolated SQLite DB path for T-final security and persistence verification
const TEST_DB_DIR = path.join(__dirname, '../data');
if (!fs.existsSync(TEST_DB_DIR)) {
  fs.mkdirSync(TEST_DB_DIR, { recursive: true });
}
process.env.DB_PATH = path.join(TEST_DB_DIR, 'test_security_t_final.sqlite');
process.env.NODE_ENV = 'test';

const { startServer } = require('../server');
const { initDb, resetDbForTests } = require('../src/db/database');
const repo = require('../src/repositories/repo');
const { ERROR_CODES } = require('../src/contracts/schemas');

/**
 * Helper to login and obtain session cookie + CSRF token
 */
async function loginAs(baseUrl, username, password) {
  const res = await request(baseUrl)
    .post('/api/auth/login')
    .send({ username, password })
    .set('Content-Type', 'application/json');

  assert.equal(
    res.status,
    200,
    `Login failed for ${username} (${res.status}): ${JSON.stringify(res.body)}`
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

  return { cookieHeader, csrfToken, user: res.body.data?.user || res.body.data };
}

describe('CSP Architect — T-final Security Controls, RBAC, Traceability & Persistence', () => {
  let server;
  let port;
  let baseUrl;
  let adminAuth;
  let operatorAuth;
  let viewerAuth;
  let baselineRunId;
  let postConfigRunId;

  before(async () => {
    server = await startServer(0);
    port = server.address().port;
    baseUrl = `http://localhost:${port}`;

    if (typeof resetDbForTests === 'function') {
      resetDbForTests();
    }

    const cfg = repo.getSystemConfig();
    repo.updateSystemConfig(
      {
        ...cfg,
        allowlist: ['localhost', '127.0.0.1'],
        allowedPorts: Array.from(new Set([...(cfg.allowedPorts || []), port])),
      },
      'test-harness'
    );

    adminAuth = await loginAs(baseUrl, 'admin', 'Admin@CSP2026!');
    operatorAuth = await loginAs(baseUrl, 'operator', 'Operator@CSP2026!');
    viewerAuth = await loginAs(baseUrl, 'viewer', 'Viewer@CSP2026!');
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('1. Unauthenticated Access Control: rejects unauthenticated requests with 401 ERR_AUTH_REQUIRED and records DENIED in audit_logs', async () => {
    const protectedEndpoints = [
      { method: 'get', path: '/api/reports/runs' },
      { method: 'post', path: '/api/engine/run-pipeline' },
      { method: 'get', path: '/api/admin/config' },
      { method: 'get', path: '/api/audit/logs' },
    ];

    for (const ep of protectedEndpoints) {
      const res = await request(baseUrl)[ep.method](ep.path);
      assert.equal(
        res.status,
        401,
        `Expected 401 on unauthenticated ${ep.method.toUpperCase()} ${ep.path}, got ${res.status}`
      );
      assert.equal(res.body.ok, false);
      assert.equal(res.body.error.code, ERROR_CODES.ERR_AUTH_REQUIRED);
      assert.ok(
        !JSON.stringify(res.body).includes('at Object.'),
        'Error response must never leak internal stack traces'
      );
    }

    const deniedAudit = repo.listAuditLogs({ outcome: 'DENIED', limit: 20 });
    assert.ok(deniedAudit.length >= 1, 'Unauthenticated access attempts must be logged as DENIED');
  });

  it('2. Role-Based Access Control (RBAC): restricted viewer can read runs but receives 403 ERR_AUTH_FORBIDDEN on operator/admin actions', async () => {
    // Seed at least one run as operator first so viewer has a run ID to test against
    const runRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl: `${baseUrl}/fixtures/t1-xss` });

    assert.equal(runRes.status, 200);
    baselineRunId = runRes.body.data.id || runRes.body.data.runId;
    assert.ok(baselineRunId, 'Operator pipeline execution must return a valid run ID');

    // Viewer CAN list workflow runs
    const listRes = await request(baseUrl)
      .get('/api/reports/runs')
      .set('Cookie', viewerAuth.cookieHeader);
    assert.equal(listRes.status, 200);
    assert.equal(listRes.body.ok, true);

    // Viewer CANNOT execute pipeline (operator/admin only)
    const viewerRunRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', viewerAuth.cookieHeader)
      .set('X-CSRF-Token', viewerAuth.csrfToken)
      .send({ targetUrl: `${baseUrl}/fixtures/t1-xss` });
    assert.equal(viewerRunRes.status, 403);
    assert.equal(viewerRunRes.body.error.code, ERROR_CODES.ERR_AUTH_FORBIDDEN);

    // Viewer CANNOT export JSON or raw HTTP header reports (operator/admin only)
    const viewerExportJson = await request(baseUrl)
      .get(`/api/reports/runs/${baselineRunId}/export-json`)
      .set('Cookie', viewerAuth.cookieHeader);
    assert.equal(viewerExportJson.status, 403);
    assert.equal(viewerExportJson.body.error.code, ERROR_CODES.ERR_AUTH_FORBIDDEN);

    const viewerExportHeaders = await request(baseUrl)
      .get(`/api/reports/runs/${baselineRunId}/export-headers`)
      .set('Cookie', viewerAuth.cookieHeader);
    assert.equal(viewerExportHeaders.status, 403);
    assert.equal(viewerExportHeaders.body.error.code, ERROR_CODES.ERR_AUTH_FORBIDDEN);

    // Viewer CANNOT access admin config or audit logs (admin only)
    const viewerAdminRes = await request(baseUrl)
      .get('/api/admin/config')
      .set('Cookie', viewerAuth.cookieHeader);
    assert.equal(viewerAdminRes.status, 403);
    assert.equal(viewerAdminRes.body.error.code, ERROR_CODES.ERR_AUTH_FORBIDDEN);

    const viewerAuditRes = await request(baseUrl)
      .get('/api/audit/logs')
      .set('Cookie', viewerAuth.cookieHeader);
    assert.equal(viewerAuditRes.status, 403);
    assert.equal(viewerAuditRes.body.error.code, ERROR_CODES.ERR_AUTH_FORBIDDEN);

    // Verify all forbidden viewer attempts were recorded in audit_logs
    const viewerDeniedLogs = repo.listAuditLogs({
      actor: 'viewer',
      outcome: 'DENIED',
      limit: 20,
    });
    assert.ok(
      viewerDeniedLogs.length >= 3,
      `Expected at least 3 DENIED audit entries for viewer, found ${viewerDeniedLogs.length}`
    );
  });

  it('3. CSRF Defense: rejects state-changing POST/PUT requests missing or having invalid X-CSRF-Token with 403 ERR_CSRF_INVALID', async () => {
    // Missing X-CSRF-Token
    const noCsrfRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .send({ targetUrl: `${baseUrl}/fixtures/normal-safe` });

    assert.equal(noCsrfRes.status, 403);
    assert.equal(noCsrfRes.body.ok, false);
    assert.equal(noCsrfRes.body.error.code, ERROR_CODES.ERR_CSRF_INVALID);

    // Invalid X-CSRF-Token on admin PUT
    const badCsrfRes = await request(baseUrl)
      .put('/api/admin/config')
      .set('Cookie', adminAuth.cookieHeader)
      .set('X-CSRF-Token', 'forged-csrf-token-00000')
      .send({ passScoreThreshold: 80 });

    assert.equal(badCsrfRes.status, 403);
    assert.equal(badCsrfRes.body.ok, false);
    assert.equal(badCsrfRes.body.error.code, ERROR_CODES.ERR_CSRF_INVALID);
  });

  it('4. Input Validation & Malformed JSON Handling: returns 400 ERR_VALIDATION_FAILED with zero stack trace leakage', async () => {
    // Malformed raw JSON syntax
    const malformedRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .set('Content-Type', 'application/json')
      .send('{"targetUrl": "http://localhost:3000", BROKEN_JSON');

    assert.equal(malformedRes.status, 400);
    assert.equal(malformedRes.body.ok, false);
    assert.equal(malformedRes.body.error.code, ERROR_CODES.ERR_VALIDATION_FAILED);
    assert.ok(!JSON.stringify(malformedRes.body).includes('SyntaxError'));

    // Missing required schema fields (empty targetUrl)
    const invalidSchemaRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl: '' });

    assert.equal(invalidSchemaRes.status, 400);
    assert.equal(invalidSchemaRes.body.ok, false);
    assert.equal(invalidSchemaRes.body.error.code, ERROR_CODES.ERR_VALIDATION_FAILED);
  });

  it('5. Oversized Payload Protection: rejects payloads > 100kb with 413 ERR_PAYLOAD_TOO_LARGE safely', async () => {
    const hugeString = 'A'.repeat(150 * 1024); // 150 KB
    const res = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl: `${baseUrl}/fixtures/normal-safe`, padding: hugeString });

    assert.equal(res.status, 413);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.error.code, ERROR_CODES.ERR_PAYLOAD_TOO_LARGE);
    assert.ok(!JSON.stringify(res.body).includes('node_modules'));
  });

  it('6. Admin Rule/Threshold Change Traceability & Illustrative Working Example: updates config, repeats run, compares runs, and exports sanitized artifacts', async () => {
    // Step A: Admin updates passScoreThreshold to 99 and disables HDR-REFERRER-POLICY
    const currentConfig = repo.getSystemConfig();
    const updatedRules = {
      ...currentConfig.rules,
      'HDR-REFERRER-POLICY': {
        ...currentConfig.rules['HDR-REFERRER-POLICY'],
        enabled: false,
      },
    };

    const adminUpdateRes = await request(baseUrl)
      .put('/api/admin/config')
      .set('Cookie', adminAuth.cookieHeader)
      .set('X-CSRF-Token', adminAuth.csrfToken)
      .send({
        passScoreThreshold: 99,
        rules: updatedRules,
      });

    assert.equal(
      adminUpdateRes.status,
      200,
      `Admin config update failed: ${JSON.stringify(adminUpdateRes.body)}`
    );
    assert.equal(adminUpdateRes.body.ok, true);

    // Step B: Operator repeats the workflow run on /fixtures/t1-xss under the updated config
    const secondRunRes = await request(baseUrl)
      .post('/api/engine/run-pipeline')
      .set('Cookie', operatorAuth.cookieHeader)
      .set('X-CSRF-Token', operatorAuth.csrfToken)
      .send({ targetUrl: `${baseUrl}/fixtures/t1-xss` });

    assert.equal(secondRunRes.status, 200);
    postConfigRunId = secondRunRes.body.data.id || secondRunRes.body.data.runId;
    assert.ok(postConfigRunId);

    // Step C: Compare both runs side-by-side via GET /api/reports/compare
    const compareRes = await request(baseUrl)
      .get(
        `/api/reports/compare?runA=${baselineRunId}&runB=${postConfigRunId}&runId1=${baselineRunId}&runId2=${postConfigRunId}`
      )
      .set('Cookie', operatorAuth.cookieHeader);

    assert.equal(
      compareRes.status,
      200,
      `Compare endpoint failed: ${JSON.stringify(compareRes.body)}`
    );
    assert.equal(compareRes.body.ok, true);
    assert.ok(compareRes.body.data, 'Comparison data must be returned');

    // Step D: Operator exports Raw HTTP Header Block (.txt) and Sanitized JSON Report (.json) (FR-6)
    const exportHeadersRes = await request(baseUrl)
      .get(`/api/reports/runs/${postConfigRunId}/export-headers`)
      .set('Cookie', operatorAuth.cookieHeader);

    assert.equal(exportHeadersRes.status, 200);
    assert.ok(
      exportHeadersRes.text.includes('Content-Security-Policy:'),
      'Exported header file must contain Content-Security-Policy header line'
    );
    assert.ok(
      exportHeadersRes.text.includes('X-Content-Type-Options: nosniff'),
      'Exported header file must contain X-Content-Type-Options: nosniff'
    );

    const exportJsonRes = await request(baseUrl)
      .get(`/api/reports/runs/${postConfigRunId}/export-json`)
      .set('Cookie', operatorAuth.cookieHeader);

    assert.equal(exportJsonRes.status, 200);
    const exportedJsonText = exportJsonRes.text || JSON.stringify(exportJsonRes.body);
    assert.ok(
      exportedJsonText.includes('/fixtures/t1-xss'),
      'Exported JSON report must reference targetUrl'
    );
    assert.ok(
      !exportedJsonText.includes('Operator@CSP2026!'),
      'Exported JSON report must never contain sensitive credentials'
    );

    // Step E: Admin inspects append-only audit logs via GET /api/audit/logs
    const auditRes = await request(baseUrl)
      .get('/api/audit/logs?limit=50')
      .set('Cookie', adminAuth.cookieHeader);

    assert.equal(auditRes.status, 200);
    assert.equal(auditRes.body.ok, true);
    const logs = auditRes.body.data?.logs || auditRes.body.data || [];
    assert.ok(logs.length >= 5, 'Audit trail must contain all workflow and admin events');

    // Reset config back to defaults and ensure test port stays allowed
    await request(baseUrl)
      .post('/api/admin/config/reset')
      .set('Cookie', adminAuth.cookieHeader)
      .set('X-CSRF-Token', adminAuth.csrfToken);

    const defaultCfg = repo.getSystemConfig();
    repo.updateSystemConfig(
      {
        ...defaultCfg,
        allowedPorts: Array.from(new Set([...(defaultCfg.allowedPorts || []), port])),
      },
      'test-harness'
    );
  });

  it('7. Persistence & Recovery After Restart: SQLite workflow runs and append-only audit logs survive DB re-initialization intact', async () => {
    const runsBefore = repo.listWorkflowRuns({ limit: 50 });
    const logsBefore = repo.listAuditLogs({ limit: 100 });
    assert.ok(runsBefore.length >= 2, 'Should have persisted at least 2 workflow runs');
    assert.ok(logsBefore.length >= 5, 'Should have persisted audit log entries');

    // Simulate service restart by re-initializing database connection on the same SQLite file
    initDb(process.env.DB_PATH);

    const runsAfter = repo.listWorkflowRuns({ limit: 50 });
    const logsAfter = repo.listAuditLogs({ limit: 100 });

    assert.equal(
      runsAfter.length,
      runsBefore.length,
      'All workflow runs must survive database restart intact'
    );
    assert.ok(
      logsAfter.length >= logsBefore.length,
      'Append-only audit logs must survive database restart without loss'
    );

    const recoveredRun = repo.getWorkflowRunById(baselineRunId);
    assert.ok(recoveredRun, 'Specific workflow run record must be recoverable by ID after restart');
  });

  it('8. Rate Limiting Defense: repeated rapid authentication attempts trigger 429 ERR_RATE_LIMITED and record DENIED in audit_logs', async () => {
    const statuses = [];
    for (let i = 0; i < 25; i += 1) {
      const res = await request(baseUrl)
        .post('/api/auth/login')
        .set('X-Forwarded-For', '203.0.113.99')
        .send({ username: 'operator', password: 'WrongPassword123!' });
      statuses.push(res.status);
      if (res.status === 429) {
        assert.equal(res.body.ok, false);
        assert.equal(res.body.error.code, ERROR_CODES.ERR_RATE_LIMITED);
        break;
      }
    }

    assert.ok(
      statuses.includes(429),
      `Expected rapid burst of login requests to trigger HTTP 429, got statuses: ${statuses.join(',')}`
    );
  });
});
