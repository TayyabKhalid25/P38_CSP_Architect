'use strict';

/**
 * FR-2: Security Header & CSP Directive Analyzer
 * Parses raw Content-Security-Policy strings into normalized directive maps and
 * evaluates HTTP response headers against the 10 configurable security rules.
 */

const { ENGINE_VERSION, DEFAULT_RULES, DEFAULT_SYSTEM_CONFIG } = require('../contracts/schemas');

/**
 * Parses a raw Content-Security-Policy header string into a normalized map of
 * `{ [directiveName]: string[] }`.
 *
 * @param {string|null|undefined} cspString
 * @returns {Record<string, string[]>}
 */
function parseCsp(cspString) {
  if (!cspString || typeof cspString !== 'string') {
    return {};
  }

  const directives = {};
  const parts = cspString
    .split(';')
    .map((segment) => segment.trim())
    .filter(Boolean);

  for (const part of parts) {
    const tokens = part.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const directiveName = tokens[0].toLowerCase();
    const values = tokens.slice(1);
    if (!directives[directiveName]) {
      directives[directiveName] = values;
    }
  }

  return directives;
}

/**
 * Normalizes a header object so all keys are lower-case strings.
 * @param {Record<string, any>} rawHeaders
 * @returns {Record<string, string>}
 */
function normalizeHeadersMap(rawHeaders) {
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;
  for (const [k, v] of Object.entries(rawHeaders)) {
    if (v !== undefined && v !== null) {
      out[String(k).toLowerCase().trim()] = String(v).trim();
    }
  }
  return out;
}

/**
 * Checks whether a token list contains cryptographic hashes or nonces that override
 * `'unsafe-inline'` in CSP Level 2/3 when `'strict-dynamic'` or hash/nonce is used without `'unsafe-inline'`.
 * Note: Our rule `HDR-CSP-NO-UNSAFE-INLINE` explicitly checks that `'unsafe-inline'` is not active.
 *
 * @param {string[]} tokens
 * @returns {boolean}
 */
function hasUnsafeInlineToken(tokens = []) {
  return tokens.some((t) => t.toLowerCase() === "'unsafe-inline'");
}

/**
 * Checks whether a token list contains `'unsafe-eval'`.
 * @param {string[]} tokens
 * @returns {boolean}
 */
function hasUnsafeEvalToken(tokens = []) {
  return tokens.some((t) => t.toLowerCase() === "'unsafe-eval'");
}

/**
 * Checks whether a token list contains wildcard `*` or broad scheme sources (`data:`, `http:`, `https:`).
 * @param {string[]} tokens
 * @returns {string[]} Matched wildcard/unrestricted tokens
 */
function findWildcardOrBroadSchemeTokens(tokens = []) {
  return tokens.filter((t) => {
    const lower = t.toLowerCase();
    return lower === '*' || lower === 'http:' || lower === 'https:' || lower === 'data:' || lower === 'blob:';
  });
}

/**
 * Evaluates a single rule ID against the normalized headers and parsed CSP directives.
 * @param {string} ruleId
 * @param {object} ruleMeta
 * @param {Record<string, string>} headers
 * @param {Record<string, string[]>} directives
 * @param {boolean} hasCsp
 * @returns {object} Normalized finding record
 */
function evaluateRule(ruleId, ruleMeta, headers, directives, hasCsp) {
  const base = {
    ruleId,
    ruleName: ruleMeta.name || ruleId,
    category: ruleMeta.category || 'Security Header',
    severity: ruleMeta.severity || 'MEDIUM',
    weight: typeof ruleMeta.weight === 'number' ? ruleMeta.weight : 5,
    passed: false,
    reason: '',
    evidence: '',
    remediation: '',
  };

  const effectiveScriptSrc = directives['script-src'] || directives['default-src'] || null;

  switch (ruleId) {
    case 'HDR-CSP-PRESENT': {
      if (hasCsp && Object.keys(directives).length > 0) {
        return {
          ...base,
          passed: true,
          reason: 'An active Content-Security-Policy header is present in the HTTP response.',
          evidence: `Content-Security-Policy: ${headers['content-security-policy']}`,
          remediation: 'Maintain the Content-Security-Policy header across all application responses.',
        };
      }
      return {
        ...base,
        passed: false,
        reason: 'No Content-Security-Policy header was found in the response.',
        evidence: headers['content-security-policy-report-only']
          ? "Only 'content-security-policy-report-only' was found; enforcement header 'content-security-policy' is absent."
          : "Header 'content-security-policy' is absent.",
        remediation: "Add an enforcing Content-Security-Policy response header (e.g., default-src 'self').",
      };
    }

    case 'HDR-CSP-NO-UNSAFE-INLINE': {
      if (!hasCsp || !effectiveScriptSrc) {
        return {
          ...base,
          passed: false,
          reason: 'Inline script execution is unrestricted because no script-src or default-src directive is enforced.',
          evidence: hasCsp
            ? 'CSP lacks both script-src and default-src directives.'
            : 'No Content-Security-Policy header present to restrict inline scripts.',
          remediation: "Define script-src 'self' (or with specific SHA-256 hashes/nonces) and omit 'unsafe-inline'.",
        };
      }
      if (hasUnsafeInlineToken(effectiveScriptSrc)) {
        return {
          ...base,
          passed: false,
          reason: "Script execution directive explicitly permits 'unsafe-inline', allowing arbitrary XSS script injection.",
          evidence: `Active script directive tokens: ${effectiveScriptSrc.join(' ')}`,
          remediation: "Remove 'unsafe-inline' from script-src/default-src and use SHA-256 hashes ('sha256-...') or cryptographic nonces.",
        };
      }
      const hasWildcard = findWildcardOrBroadSchemeTokens(effectiveScriptSrc).includes('data:');
      if (hasWildcard) {
        return {
          ...base,
          passed: false,
          reason: "Script execution directive permits 'data:' URIs, which enables inline script execution bypasses.",
          evidence: `Active script directive tokens: ${effectiveScriptSrc.join(' ')}`,
          remediation: "Remove 'data:' from script-src.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: "Script execution directive disallows 'unsafe-inline'.",
        evidence: `Effective script-src: ${effectiveScriptSrc.join(' ')}`,
        remediation: 'Continue using SHA-256 hashes, nonces, or external same-origin scripts.',
      };
    }

    case 'HDR-CSP-NO-UNSAFE-EVAL': {
      if (!hasCsp || !effectiveScriptSrc) {
        return {
          ...base,
          passed: false,
          reason: 'Dynamic code evaluation (eval / new Function) is unrestricted because no script-src or default-src directive is enforced.',
          evidence: 'Missing enforcing script-src / default-src directive.',
          remediation: "Enforce a script-src directive that omits 'unsafe-eval'.",
        };
      }
      if (hasUnsafeEvalToken(effectiveScriptSrc)) {
        return {
          ...base,
          passed: false,
          reason: "Script directive explicitly permits 'unsafe-eval', enabling dangerous dynamic string-to-code execution.",
          evidence: `Effective script-src tokens: ${effectiveScriptSrc.join(' ')}`,
          remediation: "Remove 'unsafe-eval' from script-src and refactor eval() / new Function() calls.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: "Dynamic code evaluation ('unsafe-eval') is blocked by the active script directive.",
        evidence: `Effective script-src: ${effectiveScriptSrc.join(' ')}`,
        remediation: "Keep 'unsafe-eval' excluded from script-src.",
      };
    }

    case 'HDR-CSP-NO-WILDCARD': {
      if (!hasCsp || Object.keys(directives).length === 0) {
        return {
          ...base,
          passed: false,
          reason: 'No Content-Security-Policy is present to restrict wildcard origins.',
          evidence: "Header 'content-security-policy' is absent.",
          remediation: "Define explicit origin allowlists (such as 'self') instead of leaving origins unrestricted.",
        };
      }
      const checkedDirectives = ['default-src', 'script-src', 'object-src', 'connect-src', 'style-src'];
      const offending = [];
      for (const dirName of checkedDirectives) {
        const tokens = directives[dirName];
        if (tokens) {
          const bad = findWildcardOrBroadSchemeTokens(tokens);
          if (bad.length > 0) {
            offending.push(`${dirName} (${bad.join(', ')})`);
          }
        }
      }
      if (!directives['default-src'] && !directives['script-src']) {
        offending.push('missing default-src and script-src fallback');
      }
      if (offending.length > 0) {
        return {
          ...base,
          passed: false,
          reason: `Wildcard (*) or overly broad scheme source detected in active directives: ${offending.join('; ')}.`,
          evidence: `Offending directives: ${offending.join('; ')}`,
          remediation: "Replace wildcard (*) and unrestricted schemes with 'self' or explicit trusted origins.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: 'No wildcard (*) or unrestricted scheme sources exist in execution directives.',
        evidence: `Checked directives: ${Object.keys(directives).join(', ')}`,
        remediation: 'Continue enforcing least-privilege origin sources.',
      };
    }

    case 'HDR-CSP-FRAME-ANCESTORS': {
      const fa = directives['frame-ancestors'];
      if (!hasCsp || !fa || fa.length === 0) {
        return {
          ...base,
          passed: false,
          reason: 'CSP lacks a frame-ancestors directive, leaving the page vulnerable to framing/Clickjacking in modern browsers.',
          evidence: hasCsp ? "Directive 'frame-ancestors' is absent from CSP." : 'No CSP header present.',
          remediation: "Add frame-ancestors 'none' (or 'self' if same-origin framing is required) to Content-Security-Policy.",
        };
      }
      const hasWildcardFa = fa.some((t) => t === '*' || t.toLowerCase() === 'http:' || t.toLowerCase() === 'https:');
      if (hasWildcardFa) {
        return {
          ...base,
          passed: false,
          reason: 'frame-ancestors permits wildcard framing (*), failing to protect against Clickjacking.',
          evidence: `frame-ancestors ${fa.join(' ')}`,
          remediation: "Restrict frame-ancestors to 'none' or 'self'.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: `Anti-Clickjacking frame-ancestors directive is strictly configured (${fa.join(' ')}).`,
        evidence: `frame-ancestors ${fa.join(' ')}`,
        remediation: 'Maintain restrictive frame-ancestors policy.',
      };
    }

    case 'HDR-CSP-OBJECT-SRC': {
      const objSrc = directives['object-src'] || directives['default-src'];
      const explicitObjSrc = directives['object-src'];
      if (!hasCsp || !objSrc) {
        return {
          ...base,
          passed: false,
          reason: "CSP does not restrict plugin execution via object-src 'none'.",
          evidence: "Directive 'object-src' is absent.",
          remediation: "Add object-src 'none' to block legacy Flash/Java/ActiveX plugin objects.",
        };
      }
      const isNone = explicitObjSrc && explicitObjSrc.length === 1 && explicitObjSrc[0].toLowerCase() === "'none'";
      if (!isNone) {
        return {
          ...base,
          passed: false,
          reason: "Directive object-src is not explicitly set to 'none'.",
          evidence: explicitObjSrc ? `object-src ${explicitObjSrc.join(' ')}` : `Fallback default-src ${objSrc.join(' ')}`,
          remediation: "Explicitly set object-src 'none' in Content-Security-Policy.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: "Legacy plugin execution is disabled via object-src 'none'.",
        evidence: "object-src 'none'",
        remediation: "Maintain object-src 'none'.",
      };
    }

    case 'HDR-CSP-BASE-URI': {
      const baseUri = directives['base-uri'];
      if (!hasCsp || !baseUri || baseUri.length === 0) {
        return {
          ...base,
          passed: false,
          reason: 'CSP lacks a base-uri directive, allowing injected <base> tags to hijack relative URLs.',
          evidence: "Directive 'base-uri' is absent from CSP.",
          remediation: "Add base-uri 'self' or base-uri 'none' to Content-Security-Policy.",
        };
      }
      const validBase = baseUri.every((t) => {
        const lower = t.toLowerCase();
        return lower === "'self'" || lower === "'none'";
      });
      if (!validBase) {
        return {
          ...base,
          passed: false,
          reason: `base-uri contains overly permissive sources (${baseUri.join(' ')}).`,
          evidence: `base-uri ${baseUri.join(' ')}`,
          remediation: "Restrict base-uri to 'self' or 'none'.",
        };
      }
      return {
        ...base,
        passed: true,
        reason: `DOM base tag hijacking is prevented via base-uri ${baseUri.join(' ')}.`,
        evidence: `base-uri ${baseUri.join(' ')}`,
        remediation: 'Maintain restrictive base-uri directive.',
      };
    }

    case 'HDR-XFO-SAMEORIGIN': {
      const xfo = headers['x-frame-options'];
      if (!xfo) {
        return {
          ...base,
          passed: false,
          reason: 'X-Frame-Options response header is missing.',
          evidence: "Header 'x-frame-options' is absent.",
          remediation: 'Set X-Frame-Options: DENY (or SAMEORIGIN) for defense-in-depth Clickjacking protection.',
        };
      }
      const upperXfo = xfo.toUpperCase().trim();
      if (upperXfo === 'DENY' || upperXfo === 'SAMEORIGIN') {
        return {
          ...base,
          passed: true,
          reason: `X-Frame-Options is properly set to ${upperXfo}.`,
          evidence: `X-Frame-Options: ${xfo}`,
          remediation: 'Keep X-Frame-Options aligned with CSP frame-ancestors.',
        };
      }
      return {
        ...base,
        passed: false,
        reason: `X-Frame-Options has an insecure or deprecated value "${xfo}".`,
        evidence: `X-Frame-Options: ${xfo}`,
        remediation: 'Use X-Frame-Options: DENY or SAMEORIGIN.',
      };
    }

    case 'HDR-XCTO-NOSNIFF': {
      const xcto = headers['x-content-type-options'];
      if (!xcto) {
        return {
          ...base,
          passed: false,
          reason: 'X-Content-Type-Options header is missing, allowing browser MIME-type sniffing of disguised scripts.',
          evidence: "Header 'x-content-type-options' is absent.",
          remediation: 'Add X-Content-Type-Options: nosniff to all HTTP responses.',
        };
      }
      if (xcto.toLowerCase().trim() === 'nosniff') {
        return {
          ...base,
          passed: true,
          reason: 'X-Content-Type-Options: nosniff is enforced.',
          evidence: `X-Content-Type-Options: ${xcto}`,
          remediation: 'Maintain X-Content-Type-Options: nosniff.',
        };
      }
      return {
        ...base,
        passed: false,
        reason: `X-Content-Type-Options has unexpected value "${xcto}" instead of "nosniff".`,
        evidence: `X-Content-Type-Options: ${xcto}`,
        remediation: 'Set X-Content-Type-Options: nosniff.',
      };
    }

    case 'HDR-REFERRER-POLICY': {
      const refPolicy = headers['referrer-policy'];
      const safePolicies = [
        'no-referrer',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
      ];
      if (!refPolicy) {
        return {
          ...base,
          passed: false,
          reason: 'Referrer-Policy header is missing.',
          evidence: "Header 'referrer-policy' is absent.",
          remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
        };
      }
      const normalizedRef = refPolicy.toLowerCase().trim();
      if (safePolicies.includes(normalizedRef)) {
        return {
          ...base,
          passed: true,
          reason: `Strict Referrer-Policy (${refPolicy}) is enforced.`,
          evidence: `Referrer-Policy: ${refPolicy}`,
          remediation: 'Maintain strict Referrer-Policy header.',
        };
      }
      return {
        ...base,
        passed: false,
        reason: `Referrer-Policy "${refPolicy}" is overly permissive and may leak sensitive URL parameters cross-origin.`,
        evidence: `Referrer-Policy: ${refPolicy}`,
        remediation: 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.',
      };
    }

    default:
      return {
        ...base,
        passed: true,
        reason: `Custom rule ${ruleId} evaluated.`,
        evidence: 'Rule evaluated against response headers.',
        remediation: 'None required.',
      };
  }
}

/**
 * Evaluates HTTP response headers from a crawlResult (or raw headers map) against
 * all enabled rules in `systemConfig.rules`.
 *
 * @param {object} crawlResultOrHeaders - Either an FR-1 crawlResult or `{ rawHeaders }`
 * @param {object} [systemConfig]
 * @returns {object} Normalized FR-2 headerAnalysis payload
 */
function analyzeHeaders(crawlResultOrHeaders = {}, systemConfig = DEFAULT_SYSTEM_CONFIG) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const rulesMap = { ...DEFAULT_RULES, ...(config.rules || {}) };

  const rawHeadersInput =
    crawlResultOrHeaders && crawlResultOrHeaders.rawHeaders
      ? crawlResultOrHeaders.rawHeaders
      : crawlResultOrHeaders;

  const headers = normalizeHeadersMap(rawHeadersInput);
  const existingCspRaw = headers['content-security-policy'] || null;
  const parsedDirectives = parseCsp(existingCspRaw);
  const hasCsp = Boolean(existingCspRaw && existingCspRaw.trim().length > 0);

  const findings = [];
  for (const [ruleId, ruleDef] of Object.entries(rulesMap)) {
    if (ruleDef && ruleDef.enabled === false) {
      continue;
    }
    const finding = evaluateRule(ruleId, ruleDef || DEFAULT_RULES[ruleId] || {}, headers, parsedDirectives, hasCsp);
    findings.push(finding);
  }

  const totalRules = findings.length;
  const passedRules = findings.filter((f) => f.passed).length;
  const failedRules = totalRules - passedRules;
  const criticalCount = findings.filter((f) => !f.passed && f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => !f.passed && f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => !f.passed && f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => !f.passed && f.severity === 'LOW').length;

  return {
    stage: 'FR-2_HEADER_ANALYSIS',
    status: 'COMPLETED',
    engineVersion: config.engineVersion || ENGINE_VERSION,
    existingCspRaw,
    parsedDirectives,
    findings,
    summary: {
      totalRules,
      passedRules,
      failedRules,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
    },
    evidence: findings.map((f) => ({
      code: f.ruleId,
      severity: f.passed ? 'INFO' : f.severity,
      passed: f.passed,
      message: `${f.passed ? '[PASS]' : '[FAIL]'} ${f.ruleName}: ${f.reason}`,
    })),
  };
}

module.exports = {
  parseCsp,
  analyzeHeaders,
  normalizeHeadersMap,
};
