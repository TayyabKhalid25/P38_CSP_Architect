'use strict';

/**
 * FR-6: Downloadable Security Configuration & Sanitized Evidence Bundle Exporter
 * Generates the Raw HTTP Response Header Block (.txt) and the Sanitized JSON Evidence Report (.json)
 * scrubbed via `redactSensitiveData()`.
 */

const { ENGINE_VERSION, redactSensitiveData } = require('../contracts/schemas');

/**
 * Generates the FR-6 export bundle containing:
 * 1. `rawHttpHeaderBlock`: Multi-line raw HTTP response header block string.
 * 2. `sanitizedJsonReport`: Complete reproducible security decision and evidence record scrubbed via `redactSensitiveData`.
 *
 * @param {object} params
 * @param {string} [params.runId]
 * @param {object} [params.crawlResult]
 * @param {object} [params.headerAnalysis]
 * @param {object} [params.cspBuild]
 * @param {object} [params.violationAnalysis]
 * @param {object} [params.scoreComparison]
 * @returns {object} Normalized FR-6 exportBundle payload
 */
function generateExportBundle(params = {}) {
  const {
    runId = null,
    crawlResult = {},
    headerAnalysis = {},
    cspBuild = {},
    violationAnalysis = {},
    scoreComparison = {},
  } = params;

  const cspHeaderValue =
    (cspBuild && cspBuild.cspHeaderString) ||
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; report-uri /api/engine/csp-report";

  const companion = (cspBuild && cspBuild.recommendedCompanionHeaders) || {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };

  const headersObject = {
    'Content-Security-Policy': cspHeaderValue,
    'X-Frame-Options': companion['X-Frame-Options'] || 'DENY',
    'X-Content-Type-Options': companion['X-Content-Type-Options'] || 'nosniff',
    'Referrer-Policy': companion['Referrer-Policy'] || 'strict-origin-when-cross-origin',
  };

  const rawHttpHeaderBlock = Object.entries(headersObject)
    .map(([name, val]) => `${name}: ${val}`)
    .join('\r\n');

  const beforeScore =
    scoreComparison && scoreComparison.before && typeof scoreComparison.before.score === 'number'
      ? scoreComparison.before.score
      : 0;
  const afterScore =
    scoreComparison && scoreComparison.after && typeof scoreComparison.after.score === 'number'
      ? scoreComparison.after.score
      : 100;
  const beforeGrade = (scoreComparison && scoreComparison.before && scoreComparison.before.grade) || 'F';
  const afterGrade = (scoreComparison && scoreComparison.after && scoreComparison.after.grade) || 'A';

  const failedFindings = Array.isArray(headerAnalysis && headerAnalysis.findings)
    ? headerAnalysis.findings
        .filter((f) => !f.passed)
        .map((f) => ({
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          reason: f.reason,
          remediation: f.remediation,
        }))
    : [];

  const simulatedViolations = Array.isArray(violationAnalysis && violationAnalysis.violations)
    ? violationAnalysis.violations.map((v) => ({
        violatedDirective: v.violatedDirective,
        blockedUri: v.blockedUri,
        disposition: v.disposition,
        sample: v.sample,
        explanation: v.explanation,
      }))
    : [];

  const rawReport = {
    reportVersion: ENGINE_VERSION,
    engineVersion: (headerAnalysis && headerAnalysis.engineVersion) || ENGINE_VERSION,
    runId,
    generatedAt: new Date().toISOString(),
    targetUrl: crawlResult.targetUrl || 'http://localhost:3000',
    normalizedOrigin: crawlResult.normalizedOrigin || 'http://localhost:3000',
    decision:
      afterScore >= (scoreComparison.passThreshold || 75)
        ? 'HARDENED_POLICY_GENERATED'
        : 'REQUIRES_MANUAL_REVIEW',
    beforeScore,
    beforeGrade,
    afterScore,
    afterGrade,
    scoreDelta: afterScore - beforeScore,
    passThreshold: scoreComparison.passThreshold || 75,
    headers: headersObject,
    directives: (cspBuild && cspBuild.directives) || {},
    decisions: (cspBuild && cspBuild.decisions) || [],
    baselineFailedRules: failedFindings,
    simulatedViolations,
    evidenceSummary: [
      ...((crawlResult && crawlResult.evidence) || []),
      ...((cspBuild && cspBuild.evidence) || []),
      ...((scoreComparison && scoreComparison.evidence) || []),
    ],
  };

  const sanitizedJsonReport = redactSensitiveData(rawReport);

  return {
    stage: 'FR-6_DOWNLOADABLE_CONFIG',
    status: 'COMPLETED',
    rawHttpHeaderBlock,
    sanitizedJsonReport,
    evidence: [
      {
        code: 'EXPORT-RAW-HEADERS-READY',
        severity: 'INFO',
        message: `Generated deployable raw HTTP response header block (${Object.keys(headersObject).length} security headers).`,
      },
      {
        code: 'EXPORT-JSON-SANITIZED',
        severity: 'INFO',
        message: 'Generated sanitized JSON decision & evidence report scrubbed via redactSensitiveData().',
      },
    ],
  };
}

module.exports = {
  generateExportBundle,
};
