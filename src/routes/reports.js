'use strict';

/**
 * Reporting, Workflow Run History, Side-by-Side Comparison & Export Router
 * Mounted at: /api/reports
 * Owner: Fasih Ur Rehman (Layer 1 & Reporting Routes)
 */

const express = require('express');
const repo = require('../repositories/repo');
const { requireAuth, requireRole } = require('../middleware/security');
const {
  ROLES,
  ERROR_CODES,
  ENGINE_VERSION,
  redactSensitiveData,
  AppError,
} = require('../contracts/schemas');

const router = express.Router();

/**
 * Normalizes stage keys so both canonical stage names and shorthand keys resolve cleanly.
 * @param {object} rawStages
 * @returns {object}
 */
function normalizeStages(rawStages) {
  if (!rawStages || typeof rawStages !== 'object') {
    return {
      crawlResult: null,
      headerAnalysis: null,
      cspBuild: null,
      violationAnalysis: null,
      scoreComparison: null,
      exportBundle: null,
    };
  }

  return {
    ...rawStages,
    crawlResult: rawStages.crawlResult || rawStages.fr1 || rawStages.crawler || null,
    headerAnalysis: rawStages.headerAnalysis || rawStages.fr2 || rawStages.headers || null,
    cspBuild: rawStages.cspBuild || rawStages.fr3 || rawStages.csp || null,
    violationAnalysis: rawStages.violationAnalysis || rawStages.fr4 || rawStages.violations || null,
    scoreComparison: rawStages.scoreComparison || rawStages.fr5 || rawStages.score || null,
    exportBundle: rawStages.exportBundle || rawStages.fr6 || rawStages.export || null,
  };
}

/**
 * Normalizes a workflow run record from SQLite repository into a consistent object
 * supporting both camelCase and snake_case field lookups.
 * @param {object} rawRun
 * @returns {object|null}
 */
function normalizeRun(rawRun) {
  if (!rawRun) return null;

  let parsedStages = {};
  if (rawRun.stages && typeof rawRun.stages === 'object') {
    parsedStages = rawRun.stages;
  } else if (typeof rawRun.stages_json === 'string' && rawRun.stages_json.trim()) {
    try {
      parsedStages = JSON.parse(rawRun.stages_json);
    } catch (_err) {
      parsedStages = {};
    }
  } else if (rawRun.stages_json && typeof rawRun.stages_json === 'object') {
    parsedStages = rawRun.stages_json;
  }

  const stages = normalizeStages(parsedStages);
  const beforeScore = Number(
    rawRun.beforeScore ??
      rawRun.before_score ??
      stages.scoreComparison?.before?.score ??
      0
  );
  const afterScore = Number(
    rawRun.afterScore ??
      rawRun.after_score ??
      stages.scoreComparison?.after?.score ??
      0
  );
  const targetUrl = rawRun.targetUrl || rawRun.target_url || '';
  const engineVersion = rawRun.engineVersion || rawRun.engine_version || ENGINE_VERSION;
  const latencyMs = Number(rawRun.latencyMs ?? rawRun.latency_ms ?? 0);
  const createdAt = rawRun.createdAt || rawRun.created_at || new Date().toISOString();
  const userId = rawRun.userId ?? rawRun.user_id ?? null;

  return {
    id: rawRun.id,
    userId,
    user_id: userId,
    username: rawRun.username || 'unknown',
    targetUrl,
    target_url: targetUrl,
    status: rawRun.status || 'COMPLETED',
    beforeScore,
    before_score: beforeScore,
    afterScore,
    after_score: afterScore,
    delta: afterScore - beforeScore,
    engineVersion,
    engine_version: engineVersion,
    latencyMs,
    latency_ms: latencyMs,
    createdAt,
    created_at: createdAt,
    stages,
  };
}

/**
 * Safely writes an audit log entry without breaking the request if optional fields are missing.
 */
function safeAudit(req, action, resource, outcome, details = {}) {
  if (typeof repo.appendAuditLog !== 'function') return;
  try {
    repo.appendAuditLog({
      actorUsername: req.user?.username || 'anonymous',
      actorRole: req.user?.role || 'unauthenticated',
      action,
      resource,
      outcome,
      ipAddress: req.ip || req.socket?.remoteAddress || '127.0.0.1',
      details: redactSensitiveData(details),
    });
  } catch (_err) {
    // Non-fatal in case audit helper throws
  }
}

/**
 * Builds a side-by-side comparison payload between two normalized workflow runs.
 * @param {object} runA
 * @param {object} runB
 * @returns {object}
 */
function buildRunComparison(runA, runB) {
  const stagesA = runA.stages || {};
  const stagesB = runB.stages || {};

  const beforeGradeA = stagesA.scoreComparison?.before?.grade || scoreToFallbackGrade(runA.beforeScore);
  const afterGradeA = stagesA.scoreComparison?.after?.grade || scoreToFallbackGrade(runA.afterScore);
  const beforeGradeB = stagesB.scoreComparison?.before?.grade || scoreToFallbackGrade(runB.beforeScore);
  const afterGradeB = stagesB.scoreComparison?.after?.grade || scoreToFallbackGrade(runB.afterScore);

  const directivesA = stagesA.cspBuild?.directives || {};
  const directivesB = stagesB.cspBuild?.directives || {};
  const allDirectiveKeys = Array.from(
    new Set([...Object.keys(directivesA), ...Object.keys(directivesB)])
  );

  const directiveChanges = allDirectiveKeys.map((directive) => {
    const valA = Array.isArray(directivesA[directive])
      ? directivesA[directive]
      : directivesA[directive]
        ? [String(directivesA[directive])]
        : [];
    const valB = Array.isArray(directivesB[directive])
      ? directivesB[directive]
      : directivesB[directive]
        ? [String(directivesB[directive])]
        : [];
    const strA = valA.join(' ');
    const strB = valB.join(' ');
    let status = 'UNCHANGED';
    if (!valA.length && valB.length) status = 'ADDED';
    else if (valA.length && !valB.length) status = 'REMOVED';
    else if (strA !== strB) status = 'MODIFIED';

    return {
      directive,
      runAValues: valA,
      runBValues: valB,
      runAString: strA || '(absent)',
      runBString: strB || '(absent)',
      changed: status !== 'UNCHANGED',
      status,
    };
  });

  const findingsA = Array.isArray(stagesA.headerAnalysis?.findings)
    ? stagesA.headerAnalysis.findings
    : [];
  const findingsB = Array.isArray(stagesB.headerAnalysis?.findings)
    ? stagesB.headerAnalysis.findings
    : [];

  const mapA = new Map(findingsA.map((f) => [f.ruleId, f]));
  const mapB = new Map(findingsB.map((f) => [f.ruleId, f]));
  const allRuleIds = Array.from(new Set([...mapA.keys(), ...mapB.keys()]));

  const ruleFindingsDiff = allRuleIds.map((ruleId) => {
    const rA = mapA.get(ruleId) || null;
    const rB = mapB.get(ruleId) || null;
    const runAPassed = rA ? Boolean(rA.passed) : null;
    const runBPassed = rB ? Boolean(rB.passed) : null;
    const runAWeight = rA ? Number(rA.weight ?? 0) : null;
    const runBWeight = rB ? Number(rB.weight ?? 0) : null;
    const changed = runAPassed !== runBPassed || runAWeight !== runBWeight;

    return {
      ruleId,
      ruleName: rB?.ruleName || rA?.ruleName || ruleId,
      category: rB?.category || rA?.category || 'General',
      severity: rB?.severity || rA?.severity || 'MEDIUM',
      runAPassed,
      runBPassed,
      runAWeight,
      runBWeight,
      runAReason: rA?.reason || 'Not evaluated in Run A',
      runBReason: rB?.reason || 'Not evaluated in Run B',
      changed,
    };
  });

  const runACsp = stagesA.cspBuild?.cspHeaderString || '';
  const runBCsp = stagesB.cspBuild?.cspHeaderString || '';

  return {
    runA: {
      id: runA.id,
      targetUrl: runA.targetUrl,
      status: runA.status,
      beforeScore: runA.beforeScore,
      afterScore: runA.afterScore,
      delta: runA.delta,
      beforeGrade: beforeGradeA,
      afterGrade: afterGradeA,
      passThreshold: stagesA.scoreComparison?.passThreshold ?? 75,
      engineVersion: runA.engineVersion,
      latencyMs: runA.latencyMs,
      username: runA.username,
      createdAt: runA.createdAt,
    },
    runB: {
      id: runB.id,
      targetUrl: runB.targetUrl,
      status: runB.status,
      beforeScore: runB.beforeScore,
      afterScore: runB.afterScore,
      delta: runB.delta,
      beforeGrade: beforeGradeB,
      afterGrade: afterGradeB,
      passThreshold: stagesB.scoreComparison?.passThreshold ?? 75,
      engineVersion: runB.engineVersion,
      latencyMs: runB.latencyMs,
      username: runB.username,
      createdAt: runB.createdAt,
    },
    scoreDelta: {
      beforeScoreDiff: runB.beforeScore - runA.beforeScore,
      afterScoreDiff: runB.afterScore - runA.afterScore,
      netImprovementDiff: runB.delta - runA.delta,
    },
    beforeAfterComparison: {
      runA: {
        before: runA.beforeScore,
        after: runA.afterScore,
        delta: runA.delta,
        beforeGrade: beforeGradeA,
        afterGrade: afterGradeA,
      },
      runB: {
        before: runB.beforeScore,
        after: runB.afterScore,
        delta: runB.delta,
        beforeGrade: beforeGradeB,
        afterGrade: afterGradeB,
      },
    },
    cspDiff: {
      runACsp,
      runBCsp,
      identical: runACsp === runBCsp,
      modeA: stagesA.cspBuild?.mode || 'strict-hash',
      modeB: stagesB.cspBuild?.mode || 'strict-hash',
      directiveChanges,
    },
    ruleFindingsDiff,
    violationsDiff: {
      runATotal: Number(stagesA.violationAnalysis?.totalViolations ?? 0),
      runBTotal: Number(stagesB.violationAnalysis?.totalViolations ?? 0),
      delta:
        Number(stagesB.violationAnalysis?.totalViolations ?? 0) -
        Number(stagesA.violationAnalysis?.totalViolations ?? 0),
    },
    metadata: {
      sameTarget: runA.targetUrl === runB.targetUrl,
      engineVersionA: runA.engineVersion,
      engineVersionB: runB.engineVersion,
      passThresholdA: stagesA.scoreComparison?.passThreshold ?? 75,
      passThresholdB: stagesB.scoreComparison?.passThreshold ?? 75,
      comparedAt: new Date().toISOString(),
    },
  };
}

function scoreToFallbackGrade(score) {
  const n = Number(score || 0);
  if (n >= 90) return 'A';
  if (n >= 80) return 'B';
  if (n >= 70) return 'C';
  if (n >= 60) return 'D';
  return 'F';
}

/**
 * GET /api/reports/runs
 * Lists saved workflow runs with optional filtering by status, target search, and limit.
 */
router.get('/runs', requireAuth, (req, res, next) => {
  try {
    const rawLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 200) : 50;
    const status = typeof req.query.status === 'string' && req.query.status.trim()
      ? req.query.status.trim().toUpperCase()
      : undefined;
    const search = typeof req.query.search === 'string' && req.query.search.trim()
      ? req.query.search.trim()
      : undefined;

    const rawRuns = repo.listWorkflowRuns({ limit, status, search }) || [];
    const runs = rawRuns.map((r) => normalizeRun(r));

    return res.status(200).json({
      ok: true,
      data: {
        runs,
        total: runs.length,
        filters: { limit, status: status || null, search: search || null },
      },
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * GET /api/reports/compare?runA=<id>&runB=<id>
 * Compares two workflow runs side-by-side (scores, CSP directives, rule findings, and config metadata).
 */
router.get('/compare', requireAuth, (req, res, next) => {
  try {
    const runAId = String(req.query.runA || req.query.idA || '').trim();
    const runBId = String(req.query.runB || req.query.idB || '').trim();

    if (!runAId || !runBId) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'Both runA and runB query parameters are required to compare workflow runs.',
        400,
        { runA: runAId || null, runB: runBId || null }
      );
    }

    const rawRunA = repo.getWorkflowRunById(runAId);
    if (!rawRunA) {
      throw new AppError(
        ERROR_CODES.ERR_NOT_FOUND,
        `Workflow run A (${runAId}) was not found.`,
        404,
        { runId: runAId }
      );
    }

    const rawRunB = repo.getWorkflowRunById(runBId);
    if (!rawRunB) {
      throw new AppError(
        ERROR_CODES.ERR_NOT_FOUND,
        `Workflow run B (${runBId}) was not found.`,
        404,
        { runId: runBId }
      );
    }

    const runA = normalizeRun(rawRunA);
    const runB = normalizeRun(rawRunB);
    const comparison = buildRunComparison(runA, runB);

    safeAudit(req, 'REPORT_COMPARE_RUNS', '/api/reports/compare', 'SUCCESS', {
      runA: runA.id,
      runB: runB.id,
      afterScoreDiff: comparison.scoreDelta.afterScoreDiff,
    });

    return res.status(200).json({
      ok: true,
      data: {
        ...comparison,
        comparison,
      },
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * GET /api/reports/runs/:id
 * Retrieves a single workflow run with full 6-stage evidence and any linked violation reports.
 */
router.get('/runs/:id', requireAuth, (req, res, next) => {
  try {
    const runId = String(req.params.id || '').trim();
    const rawRun = repo.getWorkflowRunById(runId);

    if (!rawRun) {
      throw new AppError(
        ERROR_CODES.ERR_NOT_FOUND,
        `Workflow run '${runId}' was not found.`,
        404,
        { runId }
      );
    }

    const run = normalizeRun(rawRun);
    const violationReports =
      typeof repo.listViolationReports === 'function'
        ? repo.listViolationReports({ runId: run.id, limit: 100 })
        : [];

    return res.status(200).json({
      ok: true,
      data: {
        run,
        violationReports,
      },
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * GET /api/reports/runs/:id/export-headers
 * Restricted to ['admin', 'operator'] so 'viewer' receives 403 ERR_AUTH_FORBIDDEN (and audit log).
 * Logs REPORT_EXPORT_HEADERS and downloads rawHttpHeaderBlock as text/plain.
 */
router.get(
  '/runs/:id/export-headers',
  requireAuth,
  requireRole([ROLES.ADMIN, ROLES.OPERATOR]),
  (req, res, next) => {
    try {
      const runId = String(req.params.id || '').trim();
      const rawRun = repo.getWorkflowRunById(runId);

      if (!rawRun) {
        throw new AppError(
          ERROR_CODES.ERR_NOT_FOUND,
          `Workflow run '${runId}' was not found.`,
          404,
          { runId }
        );
      }

      const run = normalizeRun(rawRun);
      const exportBundle = run.stages?.exportBundle || {};
      const cspBuild = run.stages?.cspBuild || {};

      let rawHeaderBlock = exportBundle.rawHttpHeaderBlock;
      if (!rawHeaderBlock || typeof rawHeaderBlock !== 'string') {
        const lines = [];
        if (cspBuild.cspHeaderString) {
          lines.push(`Content-Security-Policy: ${cspBuild.cspHeaderString}`);
        } else {
          lines.push("Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
        }
        const companions = cspBuild.recommendedCompanionHeaders || {
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'strict-origin-when-cross-origin',
        };
        for (const [hdrName, hdrVal] of Object.entries(companions)) {
          lines.push(`${hdrName}: ${hdrVal}`);
        }
        rawHeaderBlock = lines.join('\r\n');
      }

      safeAudit(
        req,
        'REPORT_EXPORT_HEADERS',
        `/api/reports/runs/${run.id}/export-headers`,
        'SUCCESS',
        {
          runId: run.id,
          targetUrl: run.targetUrl,
          format: 'text/plain',
        }
      );

      const safeFileSuffix = run.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || 'export';
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="csp-headers-${safeFileSuffix}.txt"`
      );
      return res.status(200).send(rawHeaderBlock);
    } catch (err) {
      return next(err);
    }
  }
);

/**
 * GET /api/reports/runs/:id/export-json
 * Restricted to ['admin', 'operator'] so 'viewer' receives 403 ERR_AUTH_FORBIDDEN (and audit log).
 * Logs REPORT_EXPORT_JSON and downloads sanitizedJsonReport as application/json.
 */
router.get(
  '/runs/:id/export-json',
  requireAuth,
  requireRole([ROLES.ADMIN, ROLES.OPERATOR]),
  (req, res, next) => {
    try {
      const runId = String(req.params.id || '').trim();
      const rawRun = repo.getWorkflowRunById(runId);

      if (!rawRun) {
        throw new AppError(
          ERROR_CODES.ERR_NOT_FOUND,
          `Workflow run '${runId}' was not found.`,
          404,
          { runId }
        );
      }

      const run = normalizeRun(rawRun);
      const exportBundle = run.stages?.exportBundle || {};

      const baseReport = exportBundle.sanitizedJsonReport || {
        reportVersion: '1.0.0',
        engineVersion: run.engineVersion || ENGINE_VERSION,
        generatedAt: run.createdAt,
        runId: run.id,
        targetUrl: run.targetUrl,
        status: run.status,
        beforeScore: run.beforeScore,
        afterScore: run.afterScore,
        delta: run.delta,
        stages: run.stages,
      };

      const sanitizedReport = redactSensitiveData({
        ...baseReport,
        runId: baseReport.runId || run.id,
        targetUrl: baseReport.targetUrl || run.targetUrl,
        engineVersion: baseReport.engineVersion || run.engineVersion || ENGINE_VERSION,
      });

      safeAudit(
        req,
        'REPORT_EXPORT_JSON',
        `/api/reports/runs/${run.id}/export-json`,
        'SUCCESS',
        {
          runId: run.id,
          targetUrl: run.targetUrl,
          format: 'application/json',
        }
      );

      const safeFileSuffix = run.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || 'export';
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="csp-report-${safeFileSuffix}.json"`
      );
      return res.status(200).send(JSON.stringify(sanitizedReport, null, 2));
    } catch (err) {
      return next(err);
    }
  }
);

module.exports = router;
