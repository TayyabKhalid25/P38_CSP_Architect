'use strict';

/**
 * FR-4: Deterministic Policy Violation Simulator & Browser W3C Report Normalizer
 * Simulates enforcement of synthesized CSP directives and companion security headers
 * against crawled DOM resources, and normalizes incoming browser W3C `csp-report` payloads.
 */

const crypto = require('node:crypto');
const { extractOrigin } = require('./crawler');
const { parseCsp } = require('./headerAnalyzer');

/**
 * Checks if a resource URL is permitted by a directive's source list.
 * @param {string} resourceUrl
 * @param {string} pageOrigin
 * @param {string[]} allowedTokens
 * @returns {boolean}
 */
function isOriginPermitted(resourceUrl, pageOrigin, allowedTokens = []) {
  if (!Array.isArray(allowedTokens) || allowedTokens.length === 0) return false;
  if (allowedTokens.includes('*')) return true;
  if (allowedTokens.includes("'none'")) return false;

  if (resourceUrl.startsWith('data:')) {
    return allowedTokens.includes('data:');
  }

  const resOrigin = extractOrigin(resourceUrl);
  if (!resOrigin) return true;

  if (resOrigin === pageOrigin && allowedTokens.includes("'self'")) {
    return true;
  }

  return allowedTokens.some((token) => {
    const clean = token.replace(/\/$/, '').toLowerCase();
    return clean === resOrigin.toLowerCase();
  });
}

/**
 * Deterministically simulates CSP and companion header enforcement against `crawlResult.resources`.
 *
 * @param {object} crawlResult - Output from FR-1 `crawlTarget`
 * @param {object} cspBuild - Output from FR-3 `buildCsp`
 * @returns {object} Normalized FR-4 violationAnalysis payload
 */
function simulateViolations(crawlResult = {}, cspBuild = {}) {
  const resources = (crawlResult && crawlResult.resources) || {};
  const rawHeaders = (crawlResult && crawlResult.rawHeaders) || {};
  const pageOrigin = crawlResult.normalizedOrigin || 'http://localhost:3000';
  const documentUri = crawlResult.targetUrl || pageOrigin;

  const directives =
    (cspBuild && cspBuild.directives && Object.keys(cspBuild.directives).length > 0
      ? cspBuild.directives
      : parseCsp(cspBuild && cspBuild.cspHeaderString)) || {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'img-src': ["'self'"],
      'object-src': ["'none'"],
      'frame-ancestors': ["'none'"],
    };

  const companionHeaders = (cspBuild && cspBuild.recommendedCompanionHeaders) || {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
  };

  const scriptSrc = directives['script-src'] || directives['default-src'] || ["'self'"];
  const styleSrc = directives['style-src'] || directives['default-src'] || ["'self'"];
  const imgSrc = directives['img-src'] || directives['default-src'] || ["'self'"];
  const frameSrc = directives['frame-src'] || directives['default-src'] || ["'self'"];
  const objectSrc = directives['object-src'] || ["'none'"];
  const frameAncestors = directives['frame-ancestors'] || ["'none'"];

  const allowsUnsafeInlineScript = scriptSrc.includes("'unsafe-inline'");
  const allowsUnsafeEval = scriptSrc.includes("'unsafe-eval'");
  const allowsUnsafeInlineStyle = styleSrc.includes("'unsafe-inline'");

  const violations = [];

  // 1. Check inline event handlers (onclick, onerror, etc.)
  const inlineEventHandlers = Array.isArray(resources.inlineEventHandlers)
    ? resources.inlineEventHandlers
    : [];
  for (const handler of inlineEventHandlers) {
    if (!allowsUnsafeInlineScript) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'script-src-attr',
        effectiveDirective: 'script-src',
        blockedUri: 'inline',
        disposition: 'enforce',
        sample: `<${handler.tag} ${handler.attr}="${handler.code}">`,
        explanation: `Inline event handler (${handler.tag}[${handler.attr}]) blocked because 'unsafe-inline' is disallowed by the least-privilege script-src directive.`,
      });
    }
  }

  // 2. Check inline <script> blocks (unhashed or unsafe XSS/eval scripts)
  const inlineScripts = Array.isArray(resources.inlineScripts) ? resources.inlineScripts : [];
  for (const scriptBlock of inlineScripts) {
    const hashToken = `'${scriptBlock.sha256}'`;
    const trimmedHashToken = `'${scriptBlock.trimmedSha256}'`;
    const isHashed = scriptSrc.includes(hashToken) || scriptSrc.includes(trimmedHashToken);
    const hasNonce = scriptSrc.some((t) => t.startsWith("'nonce-"));

    if (!allowsUnsafeInlineScript && !isHashed && !(hasNonce && !scriptBlock.isUnsafe)) {
      const sinkDesc =
        scriptBlock.detectedSinks && scriptBlock.detectedSinks.length > 0
          ? ` containing dangerous sink(s) (${scriptBlock.detectedSinks.join(', ')})`
          : '';
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'script-src-elem',
        effectiveDirective: 'script-src',
        blockedUri: 'inline',
        disposition: 'enforce',
        sample: scriptBlock.preview,
        explanation: `Inline <script> block #${scriptBlock.index}${sinkDesc} blocked because its SHA-256 hash (${hashToken}) is not authorized in script-src.`,
      });
    }
  }

  // 3. Check dynamic code evaluation (eval / new Function)
  if (resources.usesEvalOrFunction && !allowsUnsafeEval) {
    violations.push({
      id: crypto.randomUUID(),
      source: 'simulation',
      documentUri,
      violatedDirective: 'script-src',
      effectiveDirective: 'script-src',
      blockedUri: 'eval',
      disposition: 'enforce',
      sample: 'eval() / new Function()',
      explanation: "Dynamic string-to-code execution (eval / new Function) blocked because 'unsafe-eval' is omitted from script-src.",
    });
  }

  // 4. Check external scripts (third-party origins)
  const externalScripts = Array.isArray(resources.externalScripts) ? resources.externalScripts : [];
  for (const extScript of externalScripts) {
    if (!isOriginPermitted(extScript, pageOrigin, scriptSrc)) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'script-src-elem',
        effectiveDirective: 'script-src',
        blockedUri: extScript,
        disposition: 'enforce',
        sample: `<script src="${extScript}">`,
        explanation: `External third-party script "${extScript}" blocked because its origin is not allowlisted in script-src (${scriptSrc.join(' ')}).`,
      });
    }
  }

  // 5. Check ambiguous MIME-sniffed scripts (mitigated by X-Content-Type-Options: nosniff)
  const ambiguousScripts = Array.isArray(resources.ambiguousScripts)
    ? resources.ambiguousScripts
    : externalScripts.filter((s) => /\.(txt|jpg|png|gif|csv|json|html)(\?|$)/i.test(s));
  const enforcesNosniff =
    (companionHeaders['X-Content-Type-Options'] || '').toLowerCase() === 'nosniff';
  for (const ambigUrl of ambiguousScripts) {
    if (enforcesNosniff && !rawHeaders['x-content-type-options']) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'x-content-type-options',
        effectiveDirective: 'script-src',
        blockedUri: ambigUrl,
        disposition: 'enforce',
        sample: `<script src="${ambigUrl}"> (non-script MIME type)`,
        explanation: `Disguised non-script payload "${ambigUrl}" blocked from MIME-sniffing execution by companion header X-Content-Type-Options: nosniff.`,
      });
    }
  }

  // 6. Check legacy plugin objects (<object>, <embed>)
  const objectsAndEmbeds = Array.isArray(resources.objectsAndEmbeds)
    ? resources.objectsAndEmbeds
    : [];
  for (const obj of objectsAndEmbeds) {
    if (objectSrc.includes("'none'") || !isOriginPermitted(obj.url || '', pageOrigin, objectSrc)) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'object-src',
        effectiveDirective: 'object-src',
        blockedUri: obj.url || 'plugin-object',
        disposition: 'enforce',
        sample: `<${obj.tag} data="${obj.url || ''}">`,
        explanation: `Legacy plugin element <${obj.tag}> blocked by object-src 'none'.`,
      });
    }
  }

  // 7. Check external images
  const images = Array.isArray(resources.images) ? resources.images : [];
  for (const imgUrl of images) {
    if (!isOriginPermitted(imgUrl, pageOrigin, imgSrc)) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'img-src',
        effectiveDirective: 'img-src',
        blockedUri: imgUrl,
        disposition: 'enforce',
        sample: `<img src="${imgUrl}">`,
        explanation: `External image/pixel "${imgUrl}" blocked because its origin is not in img-src (${imgSrc.join(' ')}).`,
      });
    }
  }

  // 8. Check external iframes
  const frames = Array.isArray(resources.frames) ? resources.frames : [];
  for (const frameUrl of frames) {
    if (!isOriginPermitted(frameUrl, pageOrigin, frameSrc)) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'frame-src',
        effectiveDirective: 'frame-src',
        blockedUri: frameUrl,
        disposition: 'enforce',
        sample: `<iframe src="${frameUrl}">`,
        explanation: `Embedded frame "${frameUrl}" blocked by frame-src / default-src policy.`,
      });
    }
  }

  // 9. Check unhashed inline styles
  const inlineStyles = Array.isArray(resources.inlineStyles) ? resources.inlineStyles : [];
  for (const st of inlineStyles) {
    const hashToken = `'${st.sha256}'`;
    const trimmedHashToken = `'${st.trimmedSha256}'`;
    if (!allowsUnsafeInlineStyle && !styleSrc.includes(hashToken) && !styleSrc.includes(trimmedHashToken)) {
      violations.push({
        id: crypto.randomUUID(),
        source: 'simulation',
        documentUri,
        violatedDirective: 'style-src-elem',
        effectiveDirective: 'style-src',
        blockedUri: 'inline',
        disposition: 'enforce',
        sample: st.preview,
        explanation: `Inline <style> block #${st.index} blocked because its SHA-256 hash is not included in style-src.`,
      });
    }
  }

  // 10. Check Clickjacking framing protection activation if baseline lacked frame-ancestors & XFO
  const hadBaselineXfo = Boolean(rawHeaders['x-frame-options']);
  const baselineCsp = parseCsp(rawHeaders['content-security-policy']);
  const hadBaselineFa = Boolean(baselineCsp['frame-ancestors']);
  const hasSensitiveForms = Array.isArray(resources.forms) && resources.forms.length > 0;
  if (!hadBaselineXfo && !hadBaselineFa && hasSensitiveForms && frameAncestors.includes("'none'")) {
    violations.push({
      id: crypto.randomUUID(),
      source: 'simulation',
      documentUri,
      violatedDirective: 'frame-ancestors',
      effectiveDirective: 'frame-ancestors',
      blockedUri: 'https://attacker-framing.example',
      disposition: 'enforce',
      sample: '<iframe src="' + documentUri + '">',
      explanation:
        "Simulated cross-origin Clickjacking framing attempt against sensitive form page blocked by synthesized frame-ancestors 'none' and X-Frame-Options: DENY.",
    });
  }

  const evidence =
    violations.length > 0
      ? violations.map((v, idx) => ({
          code: `VIOLATION-SIM-${idx + 1}`,
          severity: 'HIGH',
          directive: v.violatedDirective,
          blockedUri: v.blockedUri,
          message: `[BLOCKED] ${v.violatedDirective} -> ${v.blockedUri}: ${v.explanation}`,
        }))
      : [
          {
            code: 'VIOLATION-SIM-CLEAN',
            severity: 'INFO',
            message: 'Zero policy violations triggered; all legitimate page resources comply with the synthesized least-privilege CSP.',
          },
        ];

  return {
    stage: 'FR-4_VIOLATION_COLLECTOR',
    status: 'COMPLETED',
    totalViolations: violations.length,
    violations,
    evidence,
  };
}

/**
 * Normalizes a real browser W3C CSP violation report (`{ "csp-report": { ... } }` or Reporting API / flat JSON)
 * into a standard database & workbench record.
 *
 * @param {object} payload - Raw request body sent to `POST /api/engine/csp-report`
 * @param {string|null} [runId]
 * @returns {object} Normalized violation report ready for `repo.saveViolationReport`
 */
function normalizeBrowserReport(payload = {}, runId = null) {
  const rawBody = payload && typeof payload === 'object' ? payload : {};
  const inner =
    rawBody['csp-report'] && typeof rawBody['csp-report'] === 'object'
      ? rawBody['csp-report']
      : rawBody.body && typeof rawBody.body === 'object'
        ? rawBody.body
        : rawBody;

  const documentUri = String(
    inner['document-uri'] || inner.documentURI || inner.documentUri || 'http://localhost:3000/fixtures/sandbox-frame'
  ).slice(0, 500);

  const violatedDirective = String(
    inner['violated-directive'] ||
      inner.violatedDirective ||
      inner['effective-directive'] ||
      inner.effectiveDirective ||
      'script-src'
  ).slice(0, 200);

  const effectiveDirective = String(
    inner['effective-directive'] || inner.effectiveDirective || violatedDirective
  ).slice(0, 200);

  const blockedUri = String(
    inner['blocked-uri'] || inner.blockedURI || inner.blockedUri || 'inline'
  ).slice(0, 500);

  const disposition = String(inner.disposition || 'report').toLowerCase().slice(0, 50);
  const sample = String(inner['script-sample'] || inner.sample || '').slice(0, 250);
  const resolvedRunId = runId || rawBody.runId || inner.runId || null;

  return {
    id: crypto.randomUUID(),
    runId: resolvedRunId,
    source: 'browser',
    documentUri,
    violatedDirective,
    effectiveDirective,
    blockedUri,
    disposition,
    sample,
    explanation: `Real browser CSP violation reported on ${documentUri}: directive "${violatedDirective}" blocked "${blockedUri}".`,
    rawReport: rawBody,
    createdAt: new Date().toISOString(),
  };
}

module.exports = {
  simulateViolations,
  normalizeBrowserReport,
};
