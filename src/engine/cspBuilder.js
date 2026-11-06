'use strict';

/**
 * FR-3: Least-Privilege Content-Security-Policy (CSP) Synthesizer
 * Synthesizes hardened CSP directives and companion security headers from
 * FR-1 crawl results and FR-2 header analysis findings.
 */

const crypto = require('node:crypto');
const { DEFAULT_SYSTEM_CONFIG } = require('../contracts/schemas');
const { extractOrigin } = require('./crawler');

/**
 * Serializes a directive map (`{ [directive]: string[] }`) into a canonical CSP header string.
 * @param {Record<string, string[]>} directives
 * @returns {string}
 */
function serializeDirectives(directives) {
  const segments = [];
  for (const [directive, tokens] of Object.entries(directives)) {
    if (!Array.isArray(tokens) || tokens.length === 0) continue;
    segments.push(`${directive} ${tokens.join(' ')}`);
  }
  return segments.join('; ');
}

/**
 * Builds a least-privilege Content-Security-Policy and companion security headers.
 *
 * @param {object} crawlResult - Output from FR-1 `crawlTarget`
 * @param {object} [headerAnalysis] - Output from FR-2 `analyzeHeaders`
 * @param {object} [options] - Builder customization options
 * @param {'strict-hash'|'nonce'|'strict-origin'} [options.mode='strict-hash']
 * @param {boolean} [options.allowInlineHashes=true]
 * @param {boolean} [options.allowFramingSelf=false]
 * @param {string[]} [options.allowedThirdPartyOrigins=[]]
 * @param {boolean} [options.includeReportUri=true]
 * @param {string} [options.nonceValue]
 * @param {object} [systemConfig]
 * @returns {object} Normalized FR-3 cspBuild payload
 */
function buildCsp(
  crawlResult = {},
  headerAnalysis = {},
  options = {},
  systemConfig = DEFAULT_SYSTEM_CONFIG
) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const mode = options.mode || (config.strictModeDefault !== false ? 'strict-hash' : 'strict-origin');
  const allowInlineHashes = options.allowInlineHashes !== undefined ? Boolean(options.allowInlineHashes) : true;
  const allowFramingSelf = Boolean(options.allowFramingSelf);
  const includeReportUri = options.includeReportUri !== undefined ? Boolean(options.includeReportUri) : true;
  const allowedThirdPartyOrigins = Array.isArray(options.allowedThirdPartyOrigins)
    ? options.allowedThirdPartyOrigins
        .map((o) => extractOrigin(String(o).trim()) || String(o).trim())
        .filter(Boolean)
    : [];

  const resources = (crawlResult && crawlResult.resources) || {};
  const normalizedOrigin = crawlResult.normalizedOrigin || 'http://localhost:3000';

  const scriptSrc = ["'self'"];
  const styleSrc = ["'self'"];
  const imgSrc = ["'self'"];
  const connectSrc = ["'self'"];
  const decisions = [];

  // 1. Evaluate external scripts (same-origin vs third-party)
  const externalScripts = Array.isArray(resources.externalScripts) ? resources.externalScripts : [];
  const blockedThirdPartyScripts = [];
  const approvedThirdPartyScripts = [];

  for (const scriptUrl of externalScripts) {
    const orig = extractOrigin(scriptUrl);
    if (orig && orig !== normalizedOrigin) {
      if (allowedThirdPartyOrigins.includes(orig)) {
        if (!scriptSrc.includes(orig)) {
          scriptSrc.push(orig);
        }
        approvedThirdPartyScripts.push(scriptUrl);
      } else {
        blockedThirdPartyScripts.push(scriptUrl);
      }
    }
  }

  if (blockedThirdPartyScripts.length > 0) {
    decisions.push({
      directive: 'script-src',
      decision: `Excluded ${blockedThirdPartyScripts.length} untrusted third-party script origin(s) from script-src to enforce least privilege.`,
      evidence: `Blocked external scripts: ${blockedThirdPartyScripts.join(', ')}`,
    });
  }
  if (approvedThirdPartyScripts.length > 0) {
    decisions.push({
      directive: 'script-src',
      decision: `Explicitly permitted ${approvedThirdPartyScripts.length} operator-approved third-party script(s).`,
      evidence: `Approved scripts: ${approvedThirdPartyScripts.join(', ')}`,
    });
  }

  // 2. Evaluate inline scripts (safe hashes vs unsafe XSS/eval patterns)
  const inlineScripts = Array.isArray(resources.inlineScripts) ? resources.inlineScripts : [];
  const safeInlineScripts = inlineScripts.filter((s) => !s.isUnsafe);
  const unsafeInlineScripts = inlineScripts.filter((s) => s.isUnsafe);

  let generatedNonce = null;
  if (mode === 'nonce') {
    generatedNonce = options.nonceValue || crypto.randomBytes(16).toString('base64');
    scriptSrc.push(`'nonce-${generatedNonce}'`);
    decisions.push({
      directive: 'script-src',
      decision: `Applied cryptographic per-response nonce ('nonce-${generatedNonce}') instead of 'unsafe-inline'.`,
      evidence: 'Nonce mode selected for dynamic script authorization.',
    });
  } else if (mode === 'strict-hash' && allowInlineHashes && safeInlineScripts.length > 0) {
    for (const safeScript of safeInlineScripts) {
      const hashToken = `'${safeScript.sha256}'`;
      if (!scriptSrc.includes(hashToken)) {
        scriptSrc.push(hashToken);
      }
    }
    decisions.push({
      directive: 'script-src',
      decision: `Computed and allowlisted ${safeInlineScripts.length} SHA-256 cryptographic hash(es) for verified safe inline <script> block(s).`,
      evidence: `Hashes added: ${safeInlineScripts.map((s) => `'${s.sha256}'`).join(', ')}`,
    });
  } else if (safeInlineScripts.length > 0 && !allowInlineHashes) {
    decisions.push({
      directive: 'script-src',
      decision: `Omitted SHA-256 hashes for ${safeInlineScripts.length} inline script(s) because strict external-only script mode was requested.`,
      evidence: 'Inline scripts will be blocked until moved to external same-origin .js files.',
    });
  }

  if (unsafeInlineScripts.length > 0) {
    decisions.push({
      directive: 'script-src',
      decision: `Refused to hash or allowlist ${unsafeInlineScripts.length} unsafe inline <script> block(s) containing DOM XSS sinks or eval().`,
      evidence: unsafeInlineScripts
        .map(
          (s) =>
            `inline-script[${s.index}] (sinks: ${(s.detectedSinks || []).concat(s.usesEval ? ['eval()'] : []).join(', ')}) - preview: "${s.preview}"`
        )
        .join(' | '),
    });
  }

  // 3. Evaluate inline event handlers (onclick, onerror, etc.)
  const inlineEventHandlers = Array.isArray(resources.inlineEventHandlers)
    ? resources.inlineEventHandlers
    : [];
  if (inlineEventHandlers.length > 0) {
    decisions.push({
      directive: 'script-src',
      decision: `Blocked ${inlineEventHandlers.length} inline DOM event handler attribute(s) by omitting 'unsafe-inline' and 'unsafe-hashes'.`,
      evidence: `Inline handlers (${inlineEventHandlers.map((h) => `<${h.tag} ${h.attr}="${h.code}">`).join(', ')}) cannot be safely authorized and must be refactored to addEventListener().`,
    });
  }

  // 4. Evaluate dynamic code evaluation (eval / new Function)
  if (resources.usesEvalOrFunction) {
    decisions.push({
      directive: 'script-src',
      decision: "Excluded 'unsafe-eval' from script-src to block dynamic code evaluation (eval / Function).",
      evidence: 'Dynamic string-to-code execution detected in target DOM.',
    });
  }

  // 5. Evaluate inline and external styles
  const inlineStyles = Array.isArray(resources.inlineStyles) ? resources.inlineStyles : [];
  if (allowInlineHashes && inlineStyles.length > 0) {
    for (const st of inlineStyles) {
      const hashToken = `'${st.sha256}'`;
      if (!styleSrc.includes(hashToken)) {
        styleSrc.push(hashToken);
      }
    }
    decisions.push({
      directive: 'style-src',
      decision: `Added ${inlineStyles.length} SHA-256 hash(es) for inline <style> block(s) to avoid 'unsafe-inline' in style-src.`,
      evidence: `Style hashes: ${inlineStyles.map((s) => `'${s.sha256}'`).join(', ')}`,
    });
  }

  // 6. Evaluate images (same-origin vs third-party vs data:)
  const images = Array.isArray(resources.images) ? resources.images : [];
  const blockedThirdPartyImages = [];
  for (const imgUrl of images) {
    if (imgUrl.startsWith('data:')) {
      if (!imgSrc.includes('data:')) {
        imgSrc.push('data:');
      }
      continue;
    }
    const orig = extractOrigin(imgUrl);
    if (orig && orig !== normalizedOrigin) {
      if (allowedThirdPartyOrigins.includes(orig)) {
        if (!imgSrc.includes(orig)) {
          imgSrc.push(orig);
        }
      } else {
        blockedThirdPartyImages.push(imgUrl);
      }
    }
  }
  if (blockedThirdPartyImages.length > 0) {
    decisions.push({
      directive: 'img-src',
      decision: `Restricted img-src to 'self', blocking ${blockedThirdPartyImages.length} untrusted external tracking/image resource(s).`,
      evidence: `Blocked external images: ${blockedThirdPartyImages.join(', ')}`,
    });
  }

  // 7. Anti-Clickjacking (frame-ancestors & X-Frame-Options)
  const frameAncestorsValue = allowFramingSelf ? ["'self'"] : ["'none'"];
  const xfoValue = allowFramingSelf ? 'SAMEORIGIN' : 'DENY';
  decisions.push({
    directive: 'frame-ancestors',
    decision: `Enforced frame-ancestors ${frameAncestorsValue.join(' ')} and companion X-Frame-Options: ${xfoValue} to prevent UI redressing / Clickjacking.`,
    evidence:
      (resources.forms || []).length > 0
        ? `Protects ${resources.forms.length} interactive form(s) discovered on the target page from framing attacks.`
        : 'Hardens framing policy against cross-origin embedding.',
  });

  // 8. Plugin & Base-URI & MIME Sniffing Hardening
  decisions.push({
    directive: 'object-src',
    decision: "Enforced object-src 'none' and base-uri 'self' to disable legacy plugin injection and <base> tag hijacking.",
    evidence:
      (resources.objectsAndEmbeds || []).length > 0
        ? `Neutralizes ${resources.objectsAndEmbeds.length} discovered <object>/<embed> element(s).`
        : 'Eliminates plugin attack surface.',
  });

  const directives = {
    'default-src': ["'self'"],
    'script-src': scriptSrc,
    'style-src': styleSrc,
    'img-src': imgSrc,
    'connect-src': connectSrc,
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': frameAncestorsValue,
  };

  if (includeReportUri) {
    directives['report-uri'] = ['/api/engine/csp-report'];
  }

  const cspHeaderString = serializeDirectives(directives);

  const recommendedCompanionHeaders = {
    'X-Frame-Options': xfoValue,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };

  return {
    stage: 'FR-3_CSP_BUILDER',
    status: 'COMPLETED',
    mode,
    nonce: generatedNonce,
    directives,
    cspHeaderString,
    recommendedCompanionHeaders,
    decisions,
    evidence: decisions.map((d, idx) => ({
      code: `CSP-DECISION-${idx + 1}`,
      severity: 'INFO',
      directive: d.directive,
      message: `${d.directive}: ${d.decision} (${d.evidence})`,
    })),
  };
}

module.exports = {
  buildCsp,
  serializeDirectives,
};
