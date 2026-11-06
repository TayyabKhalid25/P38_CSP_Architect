'use strict';

const repo = require('../repositories/repo');
const { ERROR_CODES, AppError, redactSensitiveData } = require('../contracts/schemas');

const rateLimitStore = new Map();

/**
 * Extracts a normalized client IP address from the Express request.
 * @param {import('express').Request} req
 * @returns {string}
 */
function getClientIp(req) {
  const forwarded = req.headers?.['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim().length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Extracts raw session token from cookie or Authorization Bearer header.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractSessionToken(req) {
  if (req.cookies && typeof req.cookies.csp_session === 'string' && req.cookies.csp_session.trim()) {
    return req.cookies.csp_session.trim();
  }
  const authHeader = req.headers?.authorization;
  if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) return token;
  }
  return null;
}

/**
 * Middleware: Resolves session from cookie or Bearer header and populates req.user.
 */
function attachSession(req, _res, next) {
  try {
    const rawToken = extractSessionToken(req);
    if (!rawToken) {
      req.user = null;
      return next();
    }
    const session = repo.getSession(rawToken);
    if (!session) {
      req.user = null;
      return next();
    }
    req.user = {
      id: session.id,
      username: session.username,
      role: session.role,
      csrfToken: session.csrfToken,
      sessionToken: rawToken,
    };
    return next();
  } catch (_err) {
    req.user = null;
    return next();
  }
}

/**
 * Middleware: Requires an authenticated session, logging DENIED events to audit_logs.
 */
function requireAuth(req, res, next) {
  if (!req.user) {
    repo.appendAuditLog({
      actorUsername: 'anonymous',
      actorRole: 'unauthenticated',
      action: 'AUTH_ACCESS_DENIED',
      resource: `${req.method} ${req.originalUrl || req.url}`,
      outcome: 'DENIED',
      ipAddress: getClientIp(req),
      details: { reason: 'Unauthenticated request to protected endpoint' },
    });

    return res.status(401).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_AUTH_REQUIRED,
        message: 'Authentication required: please sign in to access this resource.',
        details: null,
      },
    });
  }
  return next();
}

/**
 * Middleware factory: Enforces RBAC role membership with generic denial messages and audit logging.
 * @param {string[]|string} allowedRoles
 */
function requireRole(allowedRoles) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  return function roleMiddleware(req, res, next) {
    if (!req.user) {
      return requireAuth(req, res, next);
    }

    if (!roles.includes(req.user.role)) {
      repo.appendAuditLog({
        actorUsername: req.user.username,
        actorRole: req.user.role,
        action: 'RBAC_ACCESS_DENIED',
        resource: `${req.method} ${req.originalUrl || req.url}`,
        outcome: 'DENIED',
        ipAddress: getClientIp(req),
        details: {
          reason: 'Insufficient role privileges',
          requiredRoles: roles,
          actualRole: req.user.role,
        },
      });

      return res.status(403).json({
        ok: false,
        error: {
          code: ERROR_CODES.ERR_AUTH_FORBIDDEN,
          message: 'Access denied: insufficient privileges for this operation.',
          details: null,
        },
      });
    }

    return next();
  };
}

/**
 * Middleware: Validates X-CSRF-Token header against session csrfToken on state-changing requests.
 */
function verifyCsrf(req, res, next) {
  const method = (req.method || 'GET').toUpperCase();
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return next();
  }

  const fullPath = req.originalUrl || req.url || '';
  if (
    fullPath.startsWith('/api/auth/login') ||
    fullPath.startsWith('/api/engine/csp-report')
  ) {
    return next();
  }

  if (!req.user || !req.user.csrfToken) {
    return requireAuth(req, res, next);
  }

  const providedToken = req.headers?.['x-csrf-token'];
  if (
    !providedToken ||
    typeof providedToken !== 'string' ||
    providedToken !== req.user.csrfToken
  ) {
    repo.appendAuditLog({
      actorUsername: req.user.username,
      actorRole: req.user.role,
      action: 'CSRF_VALIDATION_FAILED',
      resource: `${req.method} ${req.originalUrl || req.url}`,
      outcome: 'DENIED',
      ipAddress: getClientIp(req),
      details: { reason: 'Missing or mismatched X-CSRF-Token header' },
    });

    return res.status(403).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_CSRF_INVALID,
        message: 'CSRF validation failed: missing or invalid X-CSRF-Token header.',
        details: null,
      },
    });
  }

  return next();
}

/**
 * Middleware factory: Sliding-window in-memory rate limiter with audit logging.
 * @param {object} options
 * @param {number} [options.windowMs=60000]
 * @param {number} [options.max=30]
 * @param {string} [options.actionName]
 * @param {string} [options.keyPrefix]
 */
function createRateLimiter(options = {}) {
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : 60000;
  const max = Number(options.max) > 0 ? Number(options.max) : 30;
  const prefix = options.actionName || options.keyPrefix || 'RATE_LIMIT';

  return function rateLimiterMiddleware(req, res, next) {
    const now = Date.now();
    const clientIp = getClientIp(req);
    const key = `${prefix}:${clientIp}`;

    const history = rateLimitStore.get(key) || [];
    const activeTimestamps = history.filter((ts) => now - ts < windowMs);

    if (activeTimestamps.length >= max) {
      rateLimitStore.set(key, activeTimestamps);

      repo.appendAuditLog({
        actorUsername: req.user?.username || 'anonymous',
        actorRole: req.user?.role || 'unauthenticated',
        action: prefix,
        resource: `${req.method} ${req.originalUrl || req.url}`,
        outcome: 'DENIED',
        ipAddress: clientIp,
        details: {
          reason: 'Rate limit threshold exceeded',
          windowMs,
          max,
        },
      });

      return res.status(429).json({
        ok: false,
        error: {
          code: ERROR_CODES.ERR_RATE_LIMITED,
          message: 'Too many requests: rate limit exceeded. Please wait before retrying.',
          details: { retryAfterMs: windowMs },
        },
      });
    }

    activeTimestamps.push(now);
    rateLimitStore.set(key, activeTimestamps);
    return next();
  };
}

/**
 * Clears all in-memory rate-limiting counters (used by automated test suites).
 */
function resetRateLimiters() {
  rateLimitStore.clear();
}

/**
 * Global Express error-handling middleware that prevents stack trace leakage.
 */
function errorHandler(err, _req, res, _next) {
  if (!err) {
    return res.status(500).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_INTERNAL,
        message: 'An unexpected internal server error occurred.',
        details: null,
      },
    });
  }

  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_PAYLOAD_TOO_LARGE,
        message: 'Request payload exceeds the maximum allowed size limit (100 KB).',
        details: null,
      },
    });
  }

  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_VALIDATION_FAILED,
        message: 'Malformed JSON payload in request body.',
        details: null,
      },
    });
  }

  if (err instanceof AppError || err.name === 'AppError' || (err.code && err.status)) {
    const status = Number(err.status) || 400;
    return res.status(status).json({
      ok: false,
      error: {
        code: err.code || ERROR_CODES.ERR_VALIDATION_FAILED,
        message: err.message || 'Request validation failed.',
        details: err.details ? redactSensitiveData(err.details) : null,
      },
    });
  }

  return res.status(500).json({
    ok: false,
    error: {
      code: ERROR_CODES.ERR_INTERNAL,
      message: 'An unexpected internal server error occurred.',
      details: null,
    },
  });
}

module.exports = {
  attachSession,
  requireAuth,
  requireRole,
  verifyCsrf,
  createRateLimiter,
  resetRateLimiters,
  errorHandler,
  getClientIp,
};
