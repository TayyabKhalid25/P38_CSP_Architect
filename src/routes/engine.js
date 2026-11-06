'use strict';

/**
 * Layer 2/3 Bridge: Dedicated Security Engine Express Router (`/api/engine`)
 * Exposes individual stage execution routes (`FR-1` through `FR-6`), the full
 * 6-stage pipeline orchestrator, the mandatory `T1`–`T6` evaluation suite runner,
 * and the W3C browser `csp-report` telemetry collector.
 */

const crypto = require('node:crypto');
const express = require('express');
const repo = require('../repositories/repo');
const {
  requireAuth,
  requireRole,
  verifyCsrf,
  createRateLimiter,
} = require('../middleware/security');
const {
  ENGINE_VERSION,
  ROLES,
  ERROR_CODES,
  DEFAULT_SYSTEM_CONFIG,
  AppError,
} = require('../contracts/schemas');
const engine = require('../engine');

const router = express.Router();

const engineRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  keyPrefix: 'engine-exec',
});

const cspReportRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 120,
  keyPrefix: 'csp-report',
});

/**
 * Resolves the local server baseUrl from the incoming Express request.
 * @param {import('express').Request} req
 * @returns {string}
 */
function getRequestBaseUrl(req) {
  const protocol = req.protocol || 'http';
  const host = req.get('host') || 'localhost:3000';
  return `${protocol}://${host}`;
}

/**
 * Loads the active system configuration from SQLite repository or falls back to default config.
 * @returns {object}
 */
function loadActiveSystemConfig() {
  try {
    const cfg = repo.getSystemConfig();
    return cfg ? { ...DEFAULT_SYSTEM_CONFIG, ...cfg } : DEFAULT_SYSTEM_CONFIG;
  } catch (_err) {
    return DEFAULT_SYSTEM_CONFIG;
  }
}

/**
 * Safely appends an audit log entry via `repo.appendAuditLog`.
 */
function logAudit(req, action, resource, outcome, details = {}) {
  try {
    const actorUsername = (req.user && req.user.username) || 'anonymous';
    const actorRole = (req.user && req.user.role) || 'anonymous';
    const ipAddress = req.ip || (req.socket && req.socket.remoteAddress) || '127.0.0.1';
    repo.appendAuditLog({
      actorUsername,
      actorRole,
      action,
      resource,
      outcome,
      ipAddress,
      details,
    });
  } catch (_err) {
    // Prevent audit failure from crashing request flow
  }
}

const operatorGuards = [
  requireAuth,
  requireRole([ROLES.ADMIN, ROLES.OPERATOR]),
  verifyCsrf,
  engineRateLimiter,
];

/**
 * POST /api/engine/crawl — Stage 1 (FR-1: Local Target Crawler)
 */
router.post('/crawl', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const { targetUrl, rawHtml, rawHeaders } = req.body || {};

  try {
    const crawlResult = await engine.crawlTarget(
      { targetUrl, rawHtml, rawHeaders, baseUrl },
      systemConfig
    );
    logAudit(req, 'ENGINE_STAGE_CRAWL', crawlResult.targetUrl, 'SUCCESS', {
      stage: 'FR-1_CRAWLER',
      httpStatus: crawlResult.httpStatus,
      evidenceCount: crawlResult.evidence.length,
    });
    return res.json({ ok: true, data: crawlResult });
  } catch (err) {
    const outcome =
      err && err.code === ERROR_CODES.ERR_ALLOWLIST_DENIED ? 'DENIED' : 'FAILURE';
    logAudit(req, 'ENGINE_STAGE_CRAWL', String(targetUrl || 'unknown'), outcome, {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/analyze-headers — Stage 2 (FR-2: Security Header Analyzer)
 */
router.post('/analyze-headers', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const { crawlResult, rawHeaders, targetUrl } = req.body || {};

  try {
    let sourceInput = crawlResult;
    if (!sourceInput && rawHeaders && typeof rawHeaders === 'object') {
      sourceInput = { rawHeaders };
    } else if (!sourceInput && targetUrl) {
      sourceInput = await engine.crawlTarget({ targetUrl, baseUrl }, systemConfig);
    }

    if (!sourceInput) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'Provide crawlResult, rawHeaders, or targetUrl for FR-2 header analysis.',
        400
      );
    }

    const headerAnalysis = engine.analyzeHeaders(sourceInput, systemConfig);
    logAudit(
      req,
      'ENGINE_STAGE_ANALYZE_HEADERS',
      String(targetUrl || (crawlResult && crawlResult.targetUrl) || 'raw-headers'),
      'SUCCESS',
      {
        stage: 'FR-2_HEADER_ANALYSIS',
        passedRules: headerAnalysis.summary.passedRules,
        failedRules: headerAnalysis.summary.failedRules,
      }
    );
    return res.json({ ok: true, data: headerAnalysis });
  } catch (err) {
    const outcome =
      err && err.code === ERROR_CODES.ERR_ALLOWLIST_DENIED ? 'DENIED' : 'FAILURE';
    logAudit(req, 'ENGINE_STAGE_ANALYZE_HEADERS', String(targetUrl || 'headers'), outcome, {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/build-csp — Stage 3 (FR-3: Least-Privilege CSP Synthesizer)
 */
router.post('/build-csp', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const { crawlResult, headerAnalysis, options, builderOptions, targetUrl } = req.body || {};

  try {
    let resolvedCrawl = crawlResult;
    if (!resolvedCrawl && targetUrl) {
      resolvedCrawl = await engine.crawlTarget({ targetUrl, baseUrl }, systemConfig);
    }
    if (!resolvedCrawl || typeof resolvedCrawl !== 'object') {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'A valid crawlResult or targetUrl is required to synthesize a CSP.',
        400
      );
    }

    const resolvedHeaderAnalysis =
      headerAnalysis || engine.analyzeHeaders(resolvedCrawl, systemConfig);
    const cspBuild = engine.buildCsp(
      resolvedCrawl,
      resolvedHeaderAnalysis,
      options || builderOptions || {},
      systemConfig
    );

    logAudit(
      req,
      'ENGINE_STAGE_BUILD_CSP',
      String(resolvedCrawl.targetUrl || targetUrl || 'custom'),
      'SUCCESS',
      {
        stage: 'FR-3_CSP_BUILDER',
        mode: cspBuild.mode,
        decisionsCount: cspBuild.decisions.length,
      }
    );
    return res.json({ ok: true, data: cspBuild });
  } catch (err) {
    logAudit(req, 'ENGINE_STAGE_BUILD_CSP', String(targetUrl || 'custom'), 'FAILURE', {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/collect-violations — Stage 4 (FR-4: Policy Violation Simulator)
 */
router.post('/collect-violations', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const { crawlResult, cspBuild, targetUrl, builderOptions, runId } = req.body || {};

  try {
    let resolvedCrawl = crawlResult;
    if (!resolvedCrawl && targetUrl) {
      resolvedCrawl = await engine.crawlTarget({ targetUrl, baseUrl }, systemConfig);
    }
    if (!resolvedCrawl || typeof resolvedCrawl !== 'object') {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'A valid crawlResult or targetUrl is required for FR-4 violation simulation.',
        400
      );
    }

    const resolvedCspBuild =
      cspBuild ||
      engine.buildCsp(
        resolvedCrawl,
        engine.analyzeHeaders(resolvedCrawl, systemConfig),
        builderOptions || {},
        systemConfig
      );

    const violationAnalysis = engine.simulateViolations(resolvedCrawl, resolvedCspBuild);

    // Persist simulated violations if runId is provided
    if (runId && Array.isArray(violationAnalysis.violations)) {
      for (const v of violationAnalysis.violations) {
        try {
          repo.saveViolationReport({
            id: v.id || crypto.randomUUID(),
            runId,
            source: 'simulation',
            documentUri: v.documentUri || resolvedCrawl.targetUrl || 'http://localhost:3000',
            violatedDirective: v.violatedDirective,
            blockedUri: v.blockedUri,
            disposition: v.disposition || 'enforce',
            rawReport: v,
          });
        } catch (_saveErr) {
          // Ignore duplicate or transient DB save error on ad-hoc simulation
        }
      }
    }

    logAudit(
      req,
      'ENGINE_STAGE_COLLECT_VIOLATIONS',
      String(resolvedCrawl.targetUrl || targetUrl || 'custom'),
      'SUCCESS',
      {
        stage: 'FR-4_VIOLATION_COLLECTOR',
        totalViolations: violationAnalysis.totalViolations,
      }
    );
    return res.json({ ok: true, data: violationAnalysis });
  } catch (err) {
    logAudit(req, 'ENGINE_STAGE_COLLECT_VIOLATIONS', String(targetUrl || 'custom'), 'FAILURE', {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/score — Stage 5 (FR-5: Before/After Posture Scorer)
 */
router.post('/score', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const {
    crawlResult,
    headerAnalysis,
    cspBuild,
    violationAnalysis,
    targetUrl,
    builderOptions,
  } = req.body || {};

  try {
    let resolvedCrawl = crawlResult;
    if (!resolvedCrawl && targetUrl) {
      resolvedCrawl = await engine.crawlTarget({ targetUrl, baseUrl }, systemConfig);
    }
    if (!resolvedCrawl || typeof resolvedCrawl !== 'object') {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'A valid crawlResult or targetUrl is required to calculate security posture scores.',
        400
      );
    }

    const resolvedHeaderAnalysis =
      headerAnalysis || engine.analyzeHeaders(resolvedCrawl, systemConfig);
    const resolvedCspBuild =
      cspBuild ||
      engine.buildCsp(
        resolvedCrawl,
        resolvedHeaderAnalysis,
        builderOptions || {},
        systemConfig
      );
    const resolvedViolations =
      violationAnalysis || engine.simulateViolations(resolvedCrawl, resolvedCspBuild);

    const scoreComparison = engine.calculateBeforeAfterScore(
      resolvedCrawl,
      resolvedHeaderAnalysis,
      resolvedCspBuild,
      resolvedViolations,
      systemConfig
    );

    logAudit(
      req,
      'ENGINE_STAGE_SCORE',
      String(resolvedCrawl.targetUrl || targetUrl || 'custom'),
      'SUCCESS',
      {
        stage: 'FR-5_BEFORE_AFTER_SCORE',
        beforeScore: scoreComparison.before.score,
        afterScore: scoreComparison.after.score,
        delta: scoreComparison.delta,
      }
    );
    return res.json({ ok: true, data: scoreComparison });
  } catch (err) {
    logAudit(req, 'ENGINE_STAGE_SCORE', String(targetUrl || 'custom'), 'FAILURE', {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/export — Stage 6 (FR-6: Downloadable Config & Sanitized JSON Bundle)
 */
router.post('/export', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const {
    runId,
    crawlResult,
    headerAnalysis,
    cspBuild,
    violationAnalysis,
    scoreComparison,
    targetUrl,
    builderOptions,
  } = req.body || {};

  try {
    let resolvedCrawl = crawlResult;
    if (!resolvedCrawl && targetUrl) {
      resolvedCrawl = await engine.crawlTarget({ targetUrl, baseUrl }, systemConfig);
    }
    if (!resolvedCrawl && !cspBuild) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'Provide pipeline stage outputs or targetUrl to generate an export bundle.',
        400
      );
    }

    const resolvedHeader =
      headerAnalysis || (resolvedCrawl ? engine.analyzeHeaders(resolvedCrawl, systemConfig) : {});
    const resolvedCsp =
      cspBuild ||
      (resolvedCrawl
        ? engine.buildCsp(resolvedCrawl, resolvedHeader, builderOptions || {}, systemConfig)
        : {});
    const resolvedViolations =
      violationAnalysis ||
      (resolvedCrawl ? engine.simulateViolations(resolvedCrawl, resolvedCsp) : {});
    const resolvedScore =
      scoreComparison ||
      (resolvedCrawl
        ? engine.calculateBeforeAfterScore(
            resolvedCrawl,
            resolvedHeader,
            resolvedCsp,
            resolvedViolations,
            systemConfig
          )
        : {});

    const exportBundle = engine.generateExportBundle({
      runId: runId || crypto.randomUUID(),
      crawlResult: resolvedCrawl || {},
      headerAnalysis: resolvedHeader,
      cspBuild: resolvedCsp,
      violationAnalysis: resolvedViolations,
      scoreComparison: resolvedScore,
    });

    logAudit(
      req,
      'ENGINE_STAGE_EXPORT',
      String((resolvedCrawl && resolvedCrawl.targetUrl) || targetUrl || 'export-bundle'),
      'SUCCESS',
      {
        stage: 'FR-6_DOWNLOADABLE_CONFIG',
        runId: exportBundle.sanitizedJsonReport.runId,
      }
    );
    return res.json({ ok: true, data: exportBundle });
  } catch (err) {
    logAudit(req, 'ENGINE_STAGE_EXPORT', String(targetUrl || 'export'), 'FAILURE', {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/run-pipeline — Full 6-Stage Pipeline Execution (`FR-1` to `FR-6`)
 * Persists the completed (or rejected) workflow run and simulated violations to SQLite.
 */
router.post('/run-pipeline', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);
  const { targetUrl, rawHtml, rawHeaders, builderOptions } = req.body || {};
  const runId = crypto.randomUUID();
  const startTime = performance.now();

  try {
    const pipelineResult = await engine.runFullPipeline(
      {
        runId,
        targetUrl,
        rawHtml,
        rawHeaders,
        builderOptions,
        baseUrl,
      },
      systemConfig
    );

    // Save workflow run to SQLite
    try {
      repo.saveWorkflowRun({
        id: pipelineResult.runId,
        userId: req.user.id,
        username: req.user.username,
        targetUrl: pipelineResult.targetUrl,
        status: 'COMPLETED',
        beforeScore: pipelineResult.beforeScore,
        afterScore: pipelineResult.afterScore,
        engineVersion: pipelineResult.engineVersion,
        latencyMs: pipelineResult.latencyMs,
        stages: pipelineResult.stages,
      });

      const simViolations =
        (pipelineResult.stages.violationAnalysis &&
          pipelineResult.stages.violationAnalysis.violations) ||
        [];
      for (const v of simViolations) {
        repo.saveViolationReport({
          id: v.id || crypto.randomUUID(),
          runId: pipelineResult.runId,
          source: 'simulation',
          documentUri: v.documentUri || pipelineResult.targetUrl,
          violatedDirective: v.violatedDirective,
          blockedUri: v.blockedUri,
          disposition: v.disposition || 'enforce',
          rawReport: v,
        });
      }
    } catch (_dbErr) {
      // Continue returning pipeline result even if DB logging fails
    }

    logAudit(req, 'ENGINE_RUN_PIPELINE', pipelineResult.targetUrl, 'SUCCESS', {
      runId: pipelineResult.runId,
      beforeScore: pipelineResult.beforeScore,
      afterScore: pipelineResult.afterScore,
      latencyMs: pipelineResult.latencyMs,
    });

    return res.json({ ok: true, data: pipelineResult });
  } catch (err) {
    const latencyMs = Math.max(1, Math.round(performance.now() - startTime));
    const isAllowlistDenied = err && err.code === ERROR_CODES.ERR_ALLOWLIST_DENIED;
    const statusLabel = isAllowlistDenied ? 'REJECTED' : 'FAILED';
    const auditOutcome = isAllowlistDenied ? 'DENIED' : 'FAILURE';

    try {
      repo.saveWorkflowRun({
        id: runId,
        userId: req.user.id,
        username: req.user.username,
        targetUrl: String(targetUrl || 'invalid-target'),
        status: statusLabel,
        beforeScore: 0,
        afterScore: 0,
        engineVersion: systemConfig.engineVersion || ENGINE_VERSION,
        latencyMs,
        stages: {
          error: {
            code: err.code || ERROR_CODES.ERR_INTERNAL,
            message: err.message,
          },
        },
      });
    } catch (_dbErr) {
      // Ignore secondary persistence error
    }

    logAudit(req, 'ENGINE_RUN_PIPELINE', String(targetUrl || 'invalid-target'), auditOutcome, {
      runId,
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });

    return next(err);
  }
});

/**
 * POST /api/engine/evaluate-suite — Automated Evaluation Benchmark (`Baseline` + `T1`–`T6`)
 */
router.post('/evaluate-suite', ...operatorGuards, async (req, res, next) => {
  const systemConfig = loadActiveSystemConfig();
  const baseUrl = getRequestBaseUrl(req);

  try {
    const evaluationReport = await engine.runEvaluationSuite(baseUrl, systemConfig);

    logAudit(req, 'ENGINE_EVALUATE_SUITE', 'T1-T6_BENCHMARK_SUITE', 'SUCCESS', {
      totalCases: evaluationReport.totalCases,
      passedCases: evaluationReport.passedCases,
      ruleCoveragePercent: evaluationReport.metrics.ruleCoveragePercent,
      falsePositiveRate: evaluationReport.metrics.falsePositiveRate,
      falseNegativeRate: evaluationReport.metrics.falseNegativeRate,
      meanLatencyMs: evaluationReport.metrics.meanLatencyMs,
    });

    return res.json({ ok: true, data: evaluationReport });
  } catch (err) {
    logAudit(req, 'ENGINE_EVALUATE_SUITE', 'T1-T6_BENCHMARK_SUITE', 'FAILURE', {
      errorCode: err.code || ERROR_CODES.ERR_INTERNAL,
      message: err.message,
    });
    return next(err);
  }
});

/**
 * POST /api/engine/csp-report — Public W3C Browser CSP Violation Collector Endpoint
 * Accepts `application/csp-report` or `application/json` sent by browsers when
 * a `Content-Security-Policy` or `Content-Security-Policy-Report-Only` policy with
 * `report-uri /api/engine/csp-report` is violated.
 */
router.post(
  '/csp-report',
  cspReportRateLimiter,
  express.json({
    type: ['application/csp-report', 'application/reports+json', 'application/json'],
    limit: '64kb',
  }),
  (req, res, next) => {
    try {
      const payload = req.body || {};
      const runId = (req.query && req.query.runId) || payload.runId || null;
      const normalized = engine.normalizeBrowserReport(payload, runId);

      try {
        repo.saveViolationReport({
          id: normalized.id,
          runId: normalized.runId,
          source: 'browser',
          documentUri: normalized.documentUri,
          violatedDirective: normalized.violatedDirective,
          blockedUri: normalized.blockedUri,
          disposition: normalized.disposition,
          rawReport: normalized,
        });
      } catch (_dbErr) {
        // Ensure report collector responds gracefully even if DB write encounters transient lock
      }

      logAudit(req, 'CSP_BROWSER_VIOLATION_REPORT', normalized.documentUri, 'SUCCESS', {
        reportId: normalized.id,
        violatedDirective: normalized.violatedDirective,
        blockedUri: normalized.blockedUri,
        disposition: normalized.disposition,
      });

      return res.status(201).json({
        ok: true,
        data: normalized,
      });
    } catch (err) {
      return next(err);
    }
  }
);

/**
 * GET /api/engine/violations — Lists stored browser and simulated violation reports
 */
router.get('/violations', requireAuth, (req, res, next) => {
  try {
    const runId = req.query.runId ? String(req.query.runId) : undefined;
    const limit = req.query.limit ? Math.min(200, Math.max(1, Number(req.query.limit))) : 50;
    const reports = repo.listViolationReports({ runId, limit });
    return res.json({
      ok: true,
      data: {
        violations: reports,
      },
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
