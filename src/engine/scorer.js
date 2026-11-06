'use strict';

/**
 * FR-5: Weighted Before/After Security Posture Scoring Engine
 * Computes explainable 0–100 security scores, letter grades (A–F), PASS/FAIL status
 * against `systemConfig.passScoreThreshold`, and itemized rule/risk breakdowns.
 */

const { DEFAULT_SYSTEM_CONFIG } = require('../contracts/schemas');
const { analyzeHeaders } = require('./headerAnalyzer');

/**
 * Maps a numeric 0–100 score to an academic/security letter grade.
 * @param {number} score
 * @returns {'A'|'B'|'C'|'D'|'F'}
 */
function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/**
 * Evaluates a single posture state (either Baseline `before` or Hardened `after`)
 * using `headerAnalyzer` findings and DOM risk penalties.
 *
 * @param {object} analysis - Output from `analyzeHeaders`
 * @param {object} crawlResult - Output from `crawlTarget`
 * @param {boolean} isHardenedAfter - Whether synthesized CSP & companion headers are applied
 * @param {number} passThreshold
 * @returns {{ score: number, grade: string, status: string, breakdown: object[], riskPenalties: object[] }}
 */
function computePostureScore(analysis, crawlResult, isHardenedAfter, passThreshold) {
  const findings = Array.isArray(analysis && analysis.findings) ? analysis.findings : [];
  const totalPossibleWeight = findings.reduce((acc, f) => acc + (Number(f.weight) || 0), 0);
  const earnedWeight = findings.reduce(
    (acc, f) => acc + (f.passed ? Number(f.weight) || 0 : 0),
    0
  );

  let normalizedBaseScore =
    totalPossibleWeight > 0 ? Math.round((earnedWeight / totalPossibleWeight) * 100) : 100;

  const breakdown = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleName: f.ruleName,
    category: f.category,
    severity: f.severity,
    weight: f.weight,
    earnedPoints: f.passed ? f.weight : 0,
    passed: f.passed,
    reason: f.reason,
  }));

  const riskPenalties = [];
  const resources = (crawlResult && crawlResult.resources) || {};

  // Check if active DOM risks remain unmitigated
  const passedMap = {};
  for (const f of findings) {
    passedMap[f.ruleId] = f.passed;
  }

  // Penalty 1: Unmitigated DOM XSS sinks / unsafe inline scripts when unsafe-inline is still possible
  if (!passedMap['HDR-CSP-NO-UNSAFE-INLINE']) {
    const hasXssSinks = Array.isArray(resources.xssSinks) && resources.xssSinks.length > 0;
    const hasInlineHandlers =
      Array.isArray(resources.inlineEventHandlers) && resources.inlineEventHandlers.length > 0;
    if (hasXssSinks || hasInlineHandlers) {
      const penalty = 10;
      normalizedBaseScore -= penalty;
      riskPenalties.push({
        code: 'PENALTY-ACTIVE-XSS-SURFACE',
        pointsDeducted: penalty,
        reason: 'Active DOM XSS sinks or inline event handlers exist while unsafe-inline script execution is unblocked.',
      });
    }
  }

  // Penalty 2: Unmitigated eval() when unsafe-eval is not blocked
  if (!passedMap['HDR-CSP-NO-UNSAFE-EVAL'] && resources.usesEvalOrFunction) {
    const penalty = 5;
    normalizedBaseScore -= penalty;
    riskPenalties.push({
      code: 'PENALTY-ACTIVE-EVAL-SURFACE',
      pointsDeducted: penalty,
      reason: 'Target executes eval() / dynamic code while unsafe-eval is unblocked.',
    });
  }

  // Penalty 3: Unmitigated Clickjacking surface when both frame-ancestors and X-Frame-Options are missing
  if (!passedMap['HDR-CSP-FRAME-ANCESTORS'] && !passedMap['HDR-XFO-SAMEORIGIN']) {
    const hasForms = Array.isArray(resources.forms) && resources.forms.length > 0;
    const penalty = hasForms ? 15 : 10;
    normalizedBaseScore -= penalty;
    riskPenalties.push({
      code: 'PENALTY-CLICKJACKING-EXPOSURE',
      pointsDeducted: penalty,
      reason: 'Interactive forms are exposed to cross-origin UI redressing (Clickjacking) with neither CSP frame-ancestors nor X-Frame-Options enforced.',
    });
  }

  // Penalty 4: Unmitigated MIME-sniffing script or legacy plugin when nosniff/object-src is missing
  if (
    !passedMap['HDR-XCTO-NOSNIFF'] &&
    Array.isArray(resources.ambiguousScripts) &&
    resources.ambiguousScripts.length > 0
  ) {
    const penalty = 15;
    normalizedBaseScore -= penalty;
    riskPenalties.push({
      code: 'PENALTY-AMBIGUOUS-MIME-SCRIPT',
      pointsDeducted: penalty,
      reason: 'Target loads non-script file extension in <script src> without X-Content-Type-Options: nosniff.',
    });
  }

  if (
    !passedMap['HDR-CSP-OBJECT-SRC'] &&
    Array.isArray(resources.objectsAndEmbeds) &&
    resources.objectsAndEmbeds.length > 0
  ) {
    const penalty = 5;
    normalizedBaseScore -= penalty;
    riskPenalties.push({
      code: 'PENALTY-UNRESTRICTED-PLUGIN-OBJECT',
      pointsDeducted: penalty,
      reason: "Target embeds <object>/<embed> plugin resource without object-src 'none'.",
    });
  }

  const finalScore = Math.max(0, Math.min(100, normalizedBaseScore));
  const grade = scoreToGrade(finalScore);
  const status = finalScore >= passThreshold ? 'PASS' : 'FAIL';

  return {
    score: finalScore,
    grade,
    status,
    earnedWeight,
    totalPossibleWeight,
    breakdown,
    riskPenalties,
  };
}

/**
 * Computes weighted Before and After security scores comparing the raw target response headers
 * against the synthesized least-privilege CSP and companion headers.
 *
 * @param {object} crawlResult - FR-1 output
 * @param {object} [headerAnalysis] - FR-2 output (recomputed if omitted)
 * @param {object} cspBuild - FR-3 output
 * @param {object} [violationAnalysis] - FR-4 output
 * @param {object} [systemConfig]
 * @returns {object} Normalized FR-5 scoreComparison payload
 */
function calculateBeforeAfterScore(
  crawlResult = {},
  headerAnalysis = null,
  cspBuild = {},
  violationAnalysis = {},
  systemConfig = DEFAULT_SYSTEM_CONFIG
) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const passThreshold =
    typeof config.passScoreThreshold === 'number'
      ? config.passScoreThreshold
      : DEFAULT_SYSTEM_CONFIG.passScoreThreshold;

  const beforeAnalysis =
    headerAnalysis && Array.isArray(headerAnalysis.findings)
      ? headerAnalysis
      : analyzeHeaders(crawlResult, config);

  const companion = (cspBuild && cspBuild.recommendedCompanionHeaders) || {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };

  const synthesizedHeaders = {
    ...(crawlResult.rawHeaders || {}),
    'content-security-policy':
      (cspBuild && cspBuild.cspHeaderString) ||
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    'x-frame-options': companion['X-Frame-Options'] || 'DENY',
    'x-content-type-options': companion['X-Content-Type-Options'] || 'nosniff',
    'referrer-policy': companion['Referrer-Policy'] || 'strict-origin-when-cross-origin',
  };

  const afterAnalysis = analyzeHeaders({ rawHeaders: synthesizedHeaders }, config);

  const before = computePostureScore(beforeAnalysis, crawlResult, false, passThreshold);
  const after = computePostureScore(afterAnalysis, crawlResult, true, passThreshold);
  const delta = after.score - before.score;

  const mitigatedViolations =
    violationAnalysis && typeof violationAnalysis.totalViolations === 'number'
      ? violationAnalysis.totalViolations
      : 0;

  const explanation =
    delta > 0
      ? `Applying the synthesized least-privilege CSP and companion headers increases security posture from ${before.score}/100 (${before.grade}, ${before.status}) to ${after.score}/100 (${after.grade}, ${after.status}) (+${delta} pts), neutralizing ${mitigatedViolations} policy violation vector(s) across XSS, Clickjacking, and MIME sniffing.`
      : `Target baseline already meets hardened security posture (${before.score}/100, Grade ${before.grade}, ${before.status}); synthesized policy maintains ${after.score}/100 (${after.grade}).`;

  return {
    stage: 'FR-5_BEFORE_AFTER_SCORE',
    status: 'COMPLETED',
    passThreshold,
    before,
    after,
    delta,
    explanation,
    evidence: [
      {
        code: 'SCORE-BEFORE',
        severity: before.status === 'PASS' ? 'INFO' : 'HIGH',
        message: `Baseline posture score: ${before.score}/100 (Grade ${before.grade}, ${before.status}) against threshold ${passThreshold}.`,
      },
      {
        code: 'SCORE-AFTER',
        severity: after.status === 'PASS' ? 'INFO' : 'WARNING',
        message: `Post-hardening posture score: ${after.score}/100 (Grade ${after.grade}, ${after.status}), net improvement: +${delta} points.`,
      },
    ],
  };
}

module.exports = {
  calculateBeforeAfterScore,
  scoreToGrade,
};
