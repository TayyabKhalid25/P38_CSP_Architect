'use strict';

const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');
const { initDb } = require('./db/database');
const { attachSession, errorHandler } = require('./middleware/security');
const { ERROR_CODES } = require('./contracts/schemas');

/**
 * Safely requires an Express router module if present on the current branch/worktree.
 * @param {string} modulePath
 * @returns {import('express').Router|null}
 */
function safeRequireRouter(modulePath) {
  try {
    const mod = require(modulePath);
    if (typeof mod === 'function') return mod;
    if (mod && typeof mod.router === 'function') return mod.router;
    if (mod && typeof mod.createRouter === 'function') return mod.createRouter();
    return null;
  } catch (err) {
    if (err && err.code === 'MODULE_NOT_FOUND') {
      return null;
    }
    throw err;
  }
}

/**
 * Creates and configures the Express application instance.
 * @returns {import('express').Application}
 */
function createApp() {
  initDb();

  const app = express();
  app.disable('x-powered-by');

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use(
    express.json({
      limit: '100kb',
      type: ['application/json', 'application/csp-report', 'application/reports+json'],
    })
  );
  app.use(cookieParser());
  app.use(attachSession);

  const publicDir = path.join(__dirname, '../public');
  app.use(express.static(publicDir));

  app.get('/api/health', (_req, res) => {
    res.status(200).json({
      ok: true,
      data: {
        status: 'healthy',
        service: 'CSP Architect Workbench',
      },
    });
  });

  const fixturesRouter = safeRequireRouter('./fixtures/fixturesRouter');
  if (fixturesRouter) {
    app.use('/fixtures', fixturesRouter);
  }

  const authRouter = safeRequireRouter('./routes/auth');
  if (authRouter) {
    app.use('/api/auth', authRouter);
  }

  const adminRouter = safeRequireRouter('./routes/admin');
  if (adminRouter) {
    app.use('/api/admin', adminRouter);
  }

  const auditRouter = safeRequireRouter('./routes/audit');
  if (auditRouter) {
    app.use('/api/audit', auditRouter);
  }

  const engineRouter = safeRequireRouter('./routes/engine');
  if (engineRouter) {
    app.use('/api/engine', engineRouter);
  }

  const reportsRouter = safeRequireRouter('./routes/reports');
  if (reportsRouter) {
    app.use('/api/reports', reportsRouter);
  }

  app.use('/api', (req, res) => {
    res.status(404).json({
      ok: false,
      error: {
        code: ERROR_CODES.ERR_NOT_FOUND,
        message: `API endpoint not found: ${req.method} ${req.originalUrl}`,
        details: null,
      },
    });
  });

  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
