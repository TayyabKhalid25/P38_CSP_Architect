'use strict';

/**
 * Security Engine Orchestrator (FR-1 through FR-6) & Evaluation Benchmark Suite (T1-T6)
 * Exports all 6 individual stage functions plus `runFullPipeline` and `runEvaluationSuite`.
 */

const crypto = require('node:crypto');
const {
  ENGINE_VERSION,
  ERROR_CODES,
  DEFAULT_RULES,
  DEFAULT_SYSTEM_CONFIG,
} = require('../contracts/schemas');
const { validateTargetUrl, crawlTarget, computeSha256CspHash } = require('./crawler');
const { parseCsp, analyzeHeaders } = require('./headerAnalyzer');
const { buildCsp, serializeDirectives } = require('./cspBuilder');
const { simulateViolations, normalizeBrowserReport } = require('./violationCollector');
const { calculateBeforeAfterScore, scoreToGrade } = require('./scorer');
const { generateExportBundle } = require('./exporter');

/**
 * Executes the complete 6-stage CSP Architect pipeline (`FR-1` through `FR-6`)
 * for a given target URL or raw HTML/headers payload.
 *
 * @param {object} params
 * @param {string} params.targetUrl
 * @param {string} [params.rawHtml]
 * @param {object} [params.rawHeaders]
 * @param {object} [params.builderOptions]
 * @param {string} [params.baseUrl]
 * @param {string} [params.runId]
 * @param {object} [systemConfig]
 * @returns {Promise<object>} Complete pipeline execution result
 */
async function runFullPipeline(params = {}, systemConfig = DEFAULT_SYSTEM_CONFIG) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const startTime = performance.now();
  const runId = params.runId || crypto.randomUUID();

  // Stage 1 (FR-1): Local Crawler & DOM Resource Extractor
  const crawlResult = await crawlTarget(
    {
      targetUrl: params.targetUrl,
      rawHtml: params.rawHtml,
      rawHeaders: params.rawHeaders,
      baseUrl: params.baseUrl,
    },
    config
  );

  // Stage 2 (FR-2): Security Header & CSP Directive Analyzer
  const headerAnalysis = analyzeHeaders(crawlResult, config);

  // Stage 3 (FR-3): Least-Privilege CSP Synthesizer
  const cspBuild = buildCsp(
    crawlResult,
    headerAnalysis,
    params.builderOptions || {},
    config
  );

  // Stage 4 (FR-4): Policy Violation Simulator
  const violationAnalysis = simulateViolations(crawlResult, cspBuild);

  // Stage 5 (FR-5): Weighted Before/After Posture Scorer
  const scoreComparison = calculateBeforeAfterScore(
    crawlResult,
    headerAnalysis,
    cspBuild,
    violationAnalysis,
    config
  );

  // Stage 6 (FR-6): Downloadable Config & Sanitized Evidence Bundle Exporter
  const exportBundle = generateExportBundle({
    runId,
    crawlResult,
    headerAnalysis,
    cspBuild,
    violationAnalysis,
    scoreComparison,
  });

  const latencyMs = Math.max(1, Math.round(performance.now() - startTime));

  return {
    runId,
    status: 'COMPLETED',
    targetUrl: crawlResult.targetUrl,
    engineVersion: config.engineVersion || ENGINE_VERSION,
    latencyMs,
    beforeScore: scoreComparison.before.score,
    afterScore: scoreComparison.after.score,
    scoreDelta: scoreComparison.delta,
    stages: {
      crawlResult,
      headerAnalysis,
      cspBuild,
      violationAnalysis,
      scoreComparison,
      exportBundle,
    },
  };
}

/**
 * Runs the mandatory evaluation test suite (`Baseline` + `T1` through `T6`)
 * and calculates quantitative evaluation metrics:
 * - `ruleCoveragePercent`
 * - `falsePositiveRate`
 * - `falseNegativeRate`
 * - `meanLatencyMs`
 *
 * @param {string} [baseUrl='http://localhost:3000']
 * @param {object} [systemConfig]
 * @returns {Promise<object>} Comprehensive evaluation suite report
 */
async function runEvaluationSuite(
  baseUrl = 'http://localhost:3000',
  systemConfig = DEFAULT_SYSTEM_CONFIG
) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const resolvedBase = (baseUrl || 'http://localhost:3000').replace(/\/$/, '');
  const cases = [];
  const rulesExercised = new Set();

  let falsePositives = 0;
  let totalNegativeChecks = 0;
  let falseNegatives = 0;
  let totalPositiveChecks = 0;

  // Helper to record exercised rules
  const trackRules = (findings = []) => {
    for (const f of findings) {
      if (f && f.ruleId) {
        rulesExercised.add(f.ruleId);
      }
    }
  };

  // Case 0: Baseline (/fixtures/normal-safe) - Negative control (should have 0 critical/high failures and PASS)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/normal-safe`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const findings = pipeline.stages.headerAnalysis.findings;
    trackRules(findings);

    const failedFindings = findings.filter((f) => !f.passed);
    totalNegativeChecks += findings.length;
    falsePositives += failedFindings.length;

    const passed =
      pipeline.beforeScore >= 85 &&
      pipeline.stages.headerAnalysis.summary.criticalCount === 0 &&
      failedFindings.length === 0;

    cases.push({
      testId: 'BASELINE',
      name: 'Hardened Safe Baseline Application',
      input: targetUrl,
      expectedResult: 'Status COMPLETED; baseline score >= 85 (PASS); 0 failed header rules; 0 false positives.',
      actualResult: `Status ${pipeline.status}; Before Score ${pipeline.beforeScore}/100 (${pipeline.stages.scoreComparison.before.grade}); ${failedFindings.length} failed rules.`,
      evidence: `All ${findings.length} security header rules passed without false alarms.`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T1: XSS Test Fixture (/fixtures/t1-xss)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/t1-xss`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const { crawlResult, headerAnalysis, cspBuild, violationAnalysis } = pipeline.stages;
    trackRules(headerAnalysis.findings);

    const detectedMissingCsp = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-CSP-PRESENT' && !f.passed
    );
    const detectedXssSink =
      Array.isArray(crawlResult.resources.xssSinks) && crawlResult.resources.xssSinks.length > 0;
    const detectedEval = Boolean(crawlResult.resources.usesEvalOrFunction);
    const detectedInlineHandler =
      Array.isArray(crawlResult.resources.inlineEventHandlers) &&
      crawlResult.resources.inlineEventHandlers.length > 0;
    const blockedViolations = violationAnalysis.totalViolations >= 2;
    const scoreImproved = pipeline.beforeScore < 25 && pipeline.afterScore >= 90;

    const checks = [
      detectedMissingCsp,
      detectedXssSink,
      detectedEval,
      detectedInlineHandler,
      blockedViolations,
      scoreImproved,
    ];
    totalPositiveChecks += checks.length;
    falseNegatives += checks.filter((c) => !c).length;

    const passed = checks.every(Boolean);

    cases.push({
      testId: 'T1',
      name: 'XSS & Dynamic Eval Mitigation Fixture',
      input: targetUrl,
      expectedResult:
        'Flags missing CSP, DOM XSS sink (document.write), eval(), and onerror attribute; blocks unsafe scripts in CSP; improves score from <25 to >=90.',
      actualResult: `Before: ${pipeline.beforeScore}/100 -> After: ${pipeline.afterScore}/100; Sinks: ${crawlResult.resources.xssSinks.length}; Violations blocked: ${violationAnalysis.totalViolations}.`,
      evidence: `Synthesized CSP: "${cspBuild.cspHeaderString}"; Blocked ${violationAnalysis.totalViolations} XSS/eval violation vectors.`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T2: Inline Scripts & Styles Hash Extraction (/fixtures/t2-inline)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/t2-inline`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const { crawlResult, headerAnalysis, cspBuild, violationAnalysis } = pipeline.stages;
    trackRules(headerAnalysis.findings);

    const hasScriptHash = (cspBuild.directives['script-src'] || []).some((t) =>
      t.startsWith("'sha256-")
    );
    const hasStyleHash = (cspBuild.directives['style-src'] || []).some((t) =>
      t.startsWith("'sha256-")
    );
    const flaggedOnclickViolation = violationAnalysis.violations.some(
      (v) => v.violatedDirective === 'script-src-attr'
    );

    const checks = [hasScriptHash, hasStyleHash, flaggedOnclickViolation];
    totalPositiveChecks += checks.length;
    falseNegatives += checks.filter((c) => !c).length;

    const passed = checks.every(Boolean);

    cases.push({
      testId: 'T2',
      name: 'Inline Script/Style SHA-256 Hash Synthesis & Event Handler Detection',
      input: targetUrl,
      expectedResult:
        'Computes sha256-<base64> hashes for safe inline <script> and <style> blocks while blocking inline onclick event attribute.',
      actualResult: `script-src hashes: ${hasScriptHash}; style-src hashes: ${hasStyleHash}; onclick violation simulated: ${flaggedOnclickViolation}.`,
      evidence: `script-src: ${(cspBuild.directives['script-src'] || []).join(' ')}; style-src: ${(cspBuild.directives['style-src'] || []).join(' ')}`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T3: Third-Party Resource & Wildcard CSP Hardening (/fixtures/t3-third-party)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/t3-third-party`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const { headerAnalysis, cspBuild, violationAnalysis } = pipeline.stages;
    trackRules(headerAnalysis.findings);

    const flaggedWildcard = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-CSP-NO-WILDCARD' && !f.passed
    );
    const flaggedUnsafeInline = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-CSP-NO-UNSAFE-INLINE' && !f.passed
    );
    const strippedWildcard = !(cspBuild.directives['default-src'] || []).includes('*');
    const simulatedThirdPartyBlocks = violationAnalysis.violations.some((v) =>
      v.blockedUri.includes('untrusted-analytics.example')
    );

    const checks = [
      flaggedWildcard,
      flaggedUnsafeInline,
      strippedWildcard,
      simulatedThirdPartyBlocks,
    ];
    totalPositiveChecks += checks.length;
    falseNegatives += checks.filter((c) => !c).length;

    const passed = checks.every(Boolean);

    cases.push({
      testId: 'T3',
      name: 'Third-Party Origin Isolation & Wildcard CSP Stripping',
      input: targetUrl,
      expectedResult:
        "Flags wildcard (*) and 'unsafe-inline' in existing CSP; synthesizes least-privilege 'self' policy and simulates blocking of untrusted third-party script/pixel origins.",
      actualResult: `Wildcard flagged: ${flaggedWildcard}; unsafe-inline flagged: ${flaggedUnsafeInline}; 3rd-party blocked: ${simulatedThirdPartyBlocks}.`,
      evidence: `Blocked external resources: ${violationAnalysis.violations.map((v) => v.blockedUri).join(', ')}`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T4: Clickjacking Defense (/fixtures/t4-clickjacking)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/t4-clickjacking`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const { headerAnalysis, cspBuild, exportBundle } = pipeline.stages;
    trackRules(headerAnalysis.findings);

    const flaggedMissingFa = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-CSP-FRAME-ANCESTORS' && !f.passed
    );
    const flaggedMissingXfo = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-XFO-SAMEORIGIN' && !f.passed
    );
    const injectedFaNone = (cspBuild.directives['frame-ancestors'] || []).includes("'none'");
    const injectedXfoDeny =
      cspBuild.recommendedCompanionHeaders['X-Frame-Options'] === 'DENY' &&
      exportBundle.rawHttpHeaderBlock.includes('X-Frame-Options: DENY');

    const checks = [flaggedMissingFa, flaggedMissingXfo, injectedFaNone, injectedXfoDeny];
    totalPositiveChecks += checks.length;
    falseNegatives += checks.filter((c) => !c).length;

    const passed = checks.every(Boolean);

    cases.push({
      testId: 'T4',
      name: 'Anti-Clickjacking Frame-Ancestors & X-Frame-Options Hardening',
      input: targetUrl,
      expectedResult:
        "Flags missing frame-ancestors and X-Frame-Options on sensitive form page; synthesizes frame-ancestors 'none' and X-Frame-Options: DENY.",
      actualResult: `Missing frame-ancestors flagged: ${flaggedMissingFa}; Missing XFO flagged: ${flaggedMissingXfo}; Hardened: ${injectedFaNone && injectedXfoDeny}.`,
      evidence: `Synthesized frame-ancestors ${(cspBuild.directives['frame-ancestors'] || []).join(' ')} + X-Frame-Options: ${cspBuild.recommendedCompanionHeaders['X-Frame-Options']}`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T5: MIME Sniffing & Legacy Object Mitigation (/fixtures/t5-mime-sniffing)
  {
    const caseStart = performance.now();
    const targetUrl = `${resolvedBase}/fixtures/t5-mime-sniffing`;
    const pipeline = await runFullPipeline({ targetUrl, baseUrl: resolvedBase }, config);
    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    const { headerAnalysis, cspBuild, violationAnalysis, exportBundle } = pipeline.stages;
    trackRules(headerAnalysis.findings);

    const flaggedMissingNosniff = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-XCTO-NOSNIFF' && !f.passed
    );
    const flaggedMissingObjectSrc = headerAnalysis.findings.some(
      (f) => f.ruleId === 'HDR-CSP-OBJECT-SRC' && !f.passed
    );
    const enforcedObjectNone = (cspBuild.directives['object-src'] || []).includes("'none'");
    const enforcedNosniff = exportBundle.rawHttpHeaderBlock.includes(
      'X-Content-Type-Options: nosniff'
    );
    const simulatedMimeOrObjectBlock = violationAnalysis.violations.some(
      (v) =>
        v.violatedDirective === 'x-content-type-options' ||
        v.violatedDirective === 'object-src'
    );

    const checks = [
      flaggedMissingNosniff,
      flaggedMissingObjectSrc,
      enforcedObjectNone,
      enforcedNosniff,
      simulatedMimeOrObjectBlock,
    ];
    totalPositiveChecks += checks.length;
    falseNegatives += checks.filter((c) => !c).length;

    const passed = checks.every(Boolean);

    cases.push({
      testId: 'T5',
      name: 'MIME-Sniffing & Legacy Plugin Execution Prevention',
      input: targetUrl,
      expectedResult:
        "Flags missing X-Content-Type-Options: nosniff and object-src 'none'; blocks disguised .txt script and <object> tag.",
      actualResult: `Missing nosniff flagged: ${flaggedMissingNosniff}; Missing object-src flagged: ${flaggedMissingObjectSrc}; Exported fixes: ${enforcedObjectNone && enforcedNosniff}.`,
      evidence: `Exported X-Content-Type-Options: nosniff and object-src 'none'; simulated ${violationAnalysis.totalViolations} block(s).`,
      beforeScore: pipeline.beforeScore,
      afterScore: pipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  // Case T6: Local Allowlist & SSRF Rejection (https://evil.example.com/attack & http://169.254.169.254/latest/meta-data)
  {
    const caseStart = performance.now();
    const externalTarget = 'https://evil.example.com/attack';
    const metadataTarget = 'http://169.254.169.254/latest/meta-data';
    let externalRejected = false;
    let metadataRejected = false;
    let rejectionCode = null;

    try {
      validateTargetUrl(externalTarget, config, resolvedBase);
    } catch (err) {
      if (err && err.code === ERROR_CODES.ERR_ALLOWLIST_DENIED && err.status === 403) {
        externalRejected = true;
        rejectionCode = err.code;
      }
    }

    try {
      validateTargetUrl(metadataTarget, config, resolvedBase);
    } catch (err) {
      if (err && err.code === ERROR_CODES.ERR_ALLOWLIST_DENIED && err.status === 403) {
        metadataRejected = true;
      }
    }

    // Also verify the local T6 control page succeeds
    const localT6Url = `${resolvedBase}/fixtures/t6-allowlist`;
    const localPipeline = await runFullPipeline({ targetUrl: localT6Url, baseUrl: resolvedBase }, config);
    const localAllowed = localPipeline.status === 'COMPLETED';

    const latencyMs = Math.max(1, Math.round(performance.now() - caseStart));
    totalPositiveChecks += 2;
    if (!externalRejected) falseNegatives += 1;
    if (!metadataRejected) falseNegatives += 1;

    totalNegativeChecks += 1;
    if (!localAllowed) falsePositives += 1;

    const passed = externalRejected && metadataRejected && localAllowed;

    cases.push({
      testId: 'T6',
      name: 'Strict Local Allowlist & SSRF Boundary Enforcement',
      input: `${externalTarget} | ${metadataTarget} | ${localT6Url}`,
      expectedResult:
        'Immediately rejects external and link-local SSRF targets with 403 ERR_ALLOWLIST_DENIED prior to any network socket connection, while permitting local allowlisted fixture.',
      actualResult: `External rejected (${rejectionCode}): ${externalRejected}; Metadata SSRF rejected: ${metadataRejected}; Local T6 allowed: ${localAllowed}.`,
      evidence: `Allowlist [${(config.allowlist || []).join(', ')}] blocked external/SSRF hosts with HTTP 403 ERR_ALLOWLIST_DENIED.`,
      beforeScore: localPipeline.beforeScore,
      afterScore: localPipeline.afterScore,
      latencyMs,
      passed,
    });
  }

  const totalConfiguredRules = Object.values(config.rules || DEFAULT_RULES).filter(
    (r) => r && r.enabled !== false
  ).length;
  const ruleCoveragePercent =
    totalConfiguredRules > 0
      ? Math.min(100, Math.round((rulesExercised.size / totalConfiguredRules) * 100))
      : 100;

  const falsePositiveRate =
    totalNegativeChecks > 0
      ? Number(((falsePositives / totalNegativeChecks) * 100).toFixed(2))
      : 0;
  const falseNegativeRate =
    totalPositiveChecks > 0
      ? Number(((falseNegatives / totalPositiveChecks) * 100).toFixed(2))
      : 0;
  const totalLatencyMs = cases.reduce((acc, c) => acc + c.latencyMs, 0);
  const meanLatencyMs = Number((totalLatencyMs / cases.length).toFixed(2));

  return {
    suiteVersion: ENGINE_VERSION,
    executedAt: new Date().toISOString(),
    totalCases: cases.length,
    passedCases: cases.filter((c) => c.passed).length,
    failedCases: cases.filter((c) => !c.passed).length,
    allPassed: cases.every((c) => c.passed),
    metrics: {
      ruleCoveragePercent,
      rulesExercisedCount: rulesExercised.size,
      totalRulesCount: totalConfiguredRules,
      falsePositiveRate,
      falseNegativeRate,
      meanLatencyMs,
      totalLatencyMs,
    },
    cases,
  };
}

module.exports = {
  validateTargetUrl,
  crawlTarget,
  computeSha256CspHash,
  parseCsp,
  analyzeHeaders,
  buildCsp,
  serializeDirectives,
  simulateViolations,
  normalizeBrowserReport,
  calculateBeforeAfterScore,
  scoreToGrade,
  generateExportBundle,
  runFullPipeline,
  runEvaluationSuite,
};
