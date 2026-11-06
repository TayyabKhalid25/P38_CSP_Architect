'use strict';

/**
 * Shared System Contracts, Schemas, Error Codes, and Default Security Rules
 * CSP Architect: Browser Security Header Workbench (Proposal 38)
 */

const ENGINE_VERSION = '1.0.0';

const ROLES = Object.freeze({
  ADMIN: 'admin',
  OPERATOR: 'operator',
  VIEWER: 'viewer',
});

const ERROR_CODES = Object.freeze({
  ERR_AUTH_REQUIRED: 'ERR_AUTH_REQUIRED',
  ERR_AUTH_INVALID: 'ERR_AUTH_INVALID',
  ERR_AUTH_FORBIDDEN: 'ERR_AUTH_FORBIDDEN',
  ERR_CSRF_INVALID: 'ERR_CSRF_INVALID',
  ERR_RATE_LIMITED: 'ERR_RATE_LIMITED',
  ERR_VALIDATION_FAILED: 'ERR_VALIDATION_FAILED',
  ERR_PAYLOAD_TOO_LARGE: 'ERR_PAYLOAD_TOO_LARGE',
  ERR_ALLOWLIST_DENIED: 'ERR_ALLOWLIST_DENIED',
  ERR_TARGET_UNREACHABLE: 'ERR_TARGET_UNREACHABLE',
  ERR_NOT_FOUND: 'ERR_NOT_FOUND',
  ERR_INTERNAL: 'ERR_INTERNAL',
});

const DEFAULT_RULES = Object.freeze({
  'HDR-CSP-PRESENT': {
    id: 'HDR-CSP-PRESENT',
    name: 'Content-Security-Policy Header Present',
    category: 'CSP Core',
    weight: 25,
    enabled: true,
    severity: 'CRITICAL',
    description: 'Verifies that an active Content-Security-Policy header is delivered with the HTTP response.',
  },
  'HDR-CSP-NO-UNSAFE-INLINE': {
    id: 'HDR-CSP-NO-UNSAFE-INLINE',
    name: 'Disallow unsafe-inline in Script Execution',
    category: 'XSS Mitigation',
    weight: 15,
    enabled: true,
    severity: 'HIGH',
    description: 'Ensures script-src (or fallback default-src) does not permit unsafe-inline without cryptographic nonces or hashes.',
  },
  'HDR-CSP-NO-UNSAFE-EVAL': {
    id: 'HDR-CSP-NO-UNSAFE-EVAL',
    name: 'Disallow unsafe-eval in Script Execution',
    category: 'XSS Mitigation',
    weight: 10,
    enabled: true,
    severity: 'HIGH',
    description: 'Ensures dynamic code evaluation (eval, Function, string setTimeout) is blocked in script-src.',
  },
  'HDR-CSP-NO-WILDCARD': {
    id: 'HDR-CSP-NO-WILDCARD',
    name: 'No Wildcard (*) or Unrestricted Scheme Sources',
    category: 'Least Privilege',
    weight: 10,
    enabled: true,
    severity: 'HIGH',
    description: 'Rejects wildcard (*), data:, or http: schemes in active execution directives (default-src, script-src, object-src, connect-src).',
  },
  'HDR-CSP-FRAME-ANCESTORS': {
    id: 'HDR-CSP-FRAME-ANCESTORS',
    name: 'Anti-Clickjacking frame-ancestors Directive',
    category: 'Clickjacking Defense',
    weight: 10,
    enabled: true,
    severity: 'HIGH',
    description: 'Requires frame-ancestors to be restricted to \'none\' or \'self\' to prevent UI redressing attacks.',
  },
  'HDR-CSP-OBJECT-SRC': {
    id: 'HDR-CSP-OBJECT-SRC',
    name: 'Restrict Legacy Plugin Execution (object-src)',
    category: 'Attack Surface Reduction',
    weight: 5,
    enabled: true,
    severity: 'MEDIUM',
    description: 'Requires object-src \'none\' to block legacy Flash/Java/ActiveX plugin injection.',
  },
  'HDR-CSP-BASE-URI': {
    id: 'HDR-CSP-BASE-URI',
    name: 'Restrict Base Tag Hijacking (base-uri)',
    category: 'DOM Integrity',
    weight: 5,
    enabled: true,
    severity: 'MEDIUM',
    description: 'Requires base-uri \'self\' or \'none\' to prevent relative URL hijacking via injected <base> tags.',
  },
  'HDR-XFO-SAMEORIGIN': {
    id: 'HDR-XFO-SAMEORIGIN',
    name: 'X-Frame-Options Legacy Clickjacking Header',
    category: 'Clickjacking Defense',
    weight: 8,
    enabled: true,
    severity: 'MEDIUM',
    description: 'Requires X-Frame-Options to be DENY or SAMEORIGIN for defense-in-depth alongside CSP frame-ancestors.',
  },
  'HDR-XCTO-NOSNIFF': {
    id: 'HDR-XCTO-NOSNIFF',
    name: 'X-Content-Type-Options MIME Sniffing Protection',
    category: 'MIME Security',
    weight: 7,
    enabled: true,
    severity: 'HIGH',
    description: 'Requires X-Content-Type-Options: nosniff to prevent browsers from executing disguised non-script MIME payloads.',
  },
  'HDR-REFERRER-POLICY': {
    id: 'HDR-REFERRER-POLICY',
    name: 'Strict Referrer-Policy Header',
    category: 'Privacy & Leakage',
    weight: 5,
    enabled: true,
    severity: 'LOW',
    description: 'Requires Referrer-Policy (e.g., strict-origin-when-cross-origin or no-referrer) to prevent cross-origin URL token leakage.',
  },
});

const DEFAULT_SYSTEM_CONFIG = Object.freeze({
  allowlist: ['localhost', '127.0.0.1'],
  allowedPorts: [3000, 4000, 8080],
  maxCrawlSizeBytes: 524288,
  passScoreThreshold: 75,
  criticalWarningThreshold: 50,
  strictModeDefault: true,
  engineVersion: ENGINE_VERSION,
  rules: DEFAULT_RULES,
});

const SENSITIVE_KEYS_REGEX = /(password|pass|secret|token|authorization|cookie|set-cookie|session|api[-_]?key|csrf)/i;

/**
 * Recursively redacts sensitive keys or bearer/cookie tokens from any object before logging or exporting.
 * @param {any} input
 * @returns {any}
 */
function redactSensitiveData(input) {
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    return input
      .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, '$1[REDACTED]')
      .replace(/(session_token|csrf_token|password)=([^;&\s]+)/gi, '$1=[REDACTED]');
  }
  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveData(item));
  }
  if (typeof input === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(input)) {
      if (SENSITIVE_KEYS_REGEX.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactSensitiveData(v);
      }
    }
    return out;
  }
  return input;
}

/**
 * Standard API Error Constructor with stable code and HTTP status
 */
class AppError extends Error {
  constructor(code, message, status = 400, details = null) {
    super(message);
    this.name = 'AppError';
    this.code = code || ERROR_CODES.ERR_INTERNAL;
    this.status = status;
    this.details = details ? redactSensitiveData(details) : null;
  }
}

module.exports = {
  ENGINE_VERSION,
  ROLES,
  ERROR_CODES,
  DEFAULT_RULES,
  DEFAULT_SYSTEM_CONFIG,
  redactSensitiveData,
  AppError,
};
