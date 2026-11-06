'use strict';

const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const repo = require('../repositories/repo');
const { ERROR_CODES } = require('../contracts/schemas');
const {
  requireAuth,
  verifyCsrf,
  createRateLimiter,
  getClientIp,
} = require('../middleware/security');

const router = express.Router();

const loginRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 15,
  actionName: 'AUTH_LOGIN_RATE_LIMIT',
});

/**
 * POST /api/auth/login
 * Authenticates a user with username and password, issuing a session cookie and CSRF token.
 */
router.post('/login', loginRateLimiter, (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    const clientIp = getClientIp(req);

    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      !username.trim() ||
      !password ||
      username.trim().length > 64 ||
      password.length > 128
    ) {
      repo.appendAuditLog({
        actorUsername: typeof username === 'string' && username.trim() ? username.trim() : 'anonymous',
        actorRole: 'unauthenticated',
        action: 'AUTH_LOGIN',
        resource: 'POST /api/auth/login',
        outcome: 'FAILURE',
        ipAddress: clientIp,
        details: { reason: 'Missing or invalid credential format' },
      });

      return res.status(400).json({
        ok: false,
        error: {
          code: ERROR_CODES.ERR_VALIDATION_FAILED,
          message: 'Both username and password are required strings.',
          details: null,
        },
      });
    }

    const cleanUsername = username.trim();
    const user = repo.findUserByUsername(cleanUsername);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      repo.appendAuditLog({
        actorUsername: cleanUsername,
        actorRole: 'unauthenticated',
        action: 'AUTH_LOGIN',
        resource: 'POST /api/auth/login',
        outcome: 'FAILURE',
        ipAddress: clientIp,
        details: { reason: 'Invalid username or password' },
      });

      return res.status(401).json({
        ok: false,
        error: {
          code: ERROR_CODES.ERR_AUTH_INVALID,
          message: 'Invalid username or password.',
          details: null,
        },
      });
    }

    const rawSessionToken = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const ttlMs = 2 * 60 * 60 * 1000;

    repo.createSession(user.id, rawSessionToken, csrfToken, ttlMs);

    res.cookie('csp_session', rawSessionToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: ttlMs,
    });

    repo.appendAuditLog({
      actorUsername: user.username,
      actorRole: user.role,
      action: 'AUTH_LOGIN',
      resource: 'POST /api/auth/login',
      outcome: 'SUCCESS',
      ipAddress: clientIp,
      details: { userId: user.id, role: user.role },
    });

    return res.status(200).json({
      ok: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        csrfToken,
        sessionToken: rawSessionToken,
      },
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * POST /api/auth/logout
 * Terminates the active session and clears the session cookie.
 */
router.post('/logout', requireAuth, verifyCsrf, (req, res, next) => {
  try {
    const clientIp = getClientIp(req);
    repo.deleteSession(req.user.sessionToken);
    res.clearCookie('csp_session', { path: '/' });

    repo.appendAuditLog({
      actorUsername: req.user.username,
      actorRole: req.user.role,
      action: 'AUTH_LOGOUT',
      resource: 'POST /api/auth/logout',
      outcome: 'SUCCESS',
      ipAddress: clientIp,
      details: { userId: req.user.id },
    });

    return res.status(200).json({
      ok: true,
      data: {
        message: 'Logged out successfully.',
      },
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * GET /api/auth/me
 * Returns the currently authenticated user profile and active CSRF token.
 */
router.get('/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_AUTH_REQUIRED,
        message: 'Authentication required: no active session found.',
        details: null,
      },
    });
  }

  return res.status(200).json({
    ok: true,
    data: {
      user: {
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
      },
      csrfToken: req.user.csrfToken,
    },
  });
});

module.exports = router;
