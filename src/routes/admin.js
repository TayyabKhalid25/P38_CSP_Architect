'use strict';

const express = require('express');
const repo = require('../repositories/repo');
const { ROLES, ERROR_CODES, AppError } = require('../contracts/schemas');
const {
  requireAuth,
  requireRole,
  verifyCsrf,
  getClientIp,
} = require('../middleware/security');

const router = express.Router();

const HOSTNAME_REGEX = /^[a-zA-Z0-9.-]+$/;

/**
 * Validates incoming system configuration updates.
 * @param {object} payload
 */
function validateConfigUpdate(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new AppError(
      ERROR_CODES.ERR_VALIDATION_FAILED,
      'Configuration update body must be a JSON object.',
      400
    );
  }

  if (payload.allowlist !== undefined) {
    if (!Array.isArray(payload.allowlist) || payload.allowlist.length === 0) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'allowlist must be a non-empty array of valid hostnames.',
        400
      );
    }
    for (const host of payload.allowlist) {
      if (
        typeof host !== 'string' ||
        !host.trim() ||
        host.length > 253 ||
        host.includes('*') ||
        !HOSTNAME_REGEX.test(host.trim())
      ) {
        throw new AppError(
          ERROR_CODES.ERR_VALIDATION_FAILED,
          `Invalid hostname in allowlist: "${String(host)}". Wildcards and schemes are prohibited.`,
          400
        );
      }
    }
  }

  if (payload.allowedPorts !== undefined) {
    if (!Array.isArray(payload.allowedPorts) || payload.allowedPorts.length === 0) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'allowedPorts must be a non-empty array of valid TCP port numbers.',
        400
      );
    }
    for (const port of payload.allowedPorts) {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new AppError(
          ERROR_CODES.ERR_VALIDATION_FAILED,
          `Invalid TCP port in allowedPorts: "${String(port)}".`,
          400
        );
      }
    }
  }

  if (payload.passScoreThreshold !== undefined) {
    const val = Number(payload.passScoreThreshold);
    if (!Number.isFinite(val) || val < 1 || val > 100) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'passScoreThreshold must be a number between 1 and 100.',
        400
      );
    }
  }

  if (payload.criticalWarningThreshold !== undefined) {
    const val = Number(payload.criticalWarningThreshold);
    if (!Number.isFinite(val) || val < 0 || val > 100) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'criticalWarningThreshold must be a number between 0 and 100.',
        400
      );
    }
  }

  if (payload.maxCrawlSizeBytes !== undefined) {
    const val = Number(payload.maxCrawlSizeBytes);
    if (!Number.isInteger(val) || val < 1024 || val > 5 * 1024 * 1024) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'maxCrawlSizeBytes must be an integer between 1024 and 5242880.',
        400
      );
    }
  }

  if (payload.rules !== undefined) {
    if (typeof payload.rules !== 'object' || payload.rules === null || Array.isArray(payload.rules)) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        'rules must be an object mapping rule IDs to configuration overrides.',
        400
      );
    }
    for (const [ruleId, ruleCfg] of Object.entries(payload.rules)) {
      if (typeof ruleCfg !== 'object' || ruleCfg === null) {
        throw new AppError(
          ERROR_CODES.ERR_VALIDATION_FAILED,
          `Invalid configuration override for rule "${ruleId}".`,
          400
        );
      }
      if (ruleCfg.weight !== undefined) {
        const w = Number(ruleCfg.weight);
        if (!Number.isFinite(w) || w < 0 || w > 100) {
          throw new AppError(
            ERROR_CODES.ERR_VALIDATION_FAILED,
            `Rule "${ruleId}" weight must be a number between 0 and 100.`,
            400
          );
        }
      }
      if (ruleCfg.enabled !== undefined && typeof ruleCfg.enabled !== 'boolean') {
        throw new AppError(
          ERROR_CODES.ERR_VALIDATION_FAILED,
          `Rule "${ruleId}" enabled flag must be a boolean.`,
          400
        );
      }
    }
  }
}

/**
 * GET /api/admin/config
 * Returns the active system configuration.
 */
router.get('/config', requireAuth, (_req, res, next) => {
  try {
    const config = repo.getSystemConfig();
    return res.status(200).json({
      ok: true,
      data: config,
    });
  } catch (err) {
    return next(err);
  }
});

/**
 * PUT /api/admin/config
 * Updates system configuration (Admin only, CSRF protected) and records before/after diff in audit_logs.
 */
router.put(
  '/config',
  requireAuth,
  requireRole([ROLES.ADMIN]),
  verifyCsrf,
  (req, res, next) => {
    try {
      validateConfigUpdate(req.body);

      const beforeConfig = repo.getSystemConfig();
      const normalizedBody = { ...req.body };
      if (Array.isArray(normalizedBody.allowlist)) {
        normalizedBody.allowlist = normalizedBody.allowlist.map((h) => String(h).trim());
      }
      if (Array.isArray(normalizedBody.allowedPorts)) {
        normalizedBody.allowedPorts = normalizedBody.allowedPorts.map((p) => Number(p));
      }

      const updatedConfig = repo.updateSystemConfig(normalizedBody, req.user.username);

      repo.appendAuditLog({
        actorUsername: req.user.username,
        actorRole: req.user.role,
        action: 'ADMIN_CONFIG_UPDATE',
        resource: 'PUT /api/admin/config',
        outcome: 'SUCCESS',
        ipAddress: getClientIp(req),
        details: {
          before: {
            allowlist: beforeConfig.allowlist,
            passScoreThreshold: beforeConfig.passScoreThreshold,
            criticalWarningThreshold: beforeConfig.criticalWarningThreshold,
          },
          after: {
            allowlist: updatedConfig.allowlist,
            passScoreThreshold: updatedConfig.passScoreThreshold,
            criticalWarningThreshold: updatedConfig.criticalWarningThreshold,
          },
        },
      });

      return res.status(200).json({
        ok: true,
        data: updatedConfig,
      });
    } catch (err) {
      return next(err);
    }
  }
);

/**
 * POST /api/admin/config/reset
 * Resets system configuration back to DEFAULT_SYSTEM_CONFIG (Admin only, CSRF protected).
 */
router.post(
  '/config/reset',
  requireAuth,
  requireRole([ROLES.ADMIN]),
  verifyCsrf,
  (req, res, next) => {
    try {
      const resetConfig = repo.resetSystemConfig(req.user.username);

      repo.appendAuditLog({
        actorUsername: req.user.username,
        actorRole: req.user.role,
        action: 'ADMIN_CONFIG_RESET',
        resource: 'POST /api/admin/config/reset',
        outcome: 'SUCCESS',
        ipAddress: getClientIp(req),
        details: {
          message: 'System configuration restored to factory defaults.',
        },
      });

      return res.status(200).json({
        ok: true,
        data: resetConfig,
      });
    } catch (err) {
      return next(err);
    }
  }
);

/**
 * GET /api/admin/users
 * Lists all registered RBAC accounts (Admin only).
 */
router.get('/users', requireAuth, requireRole([ROLES.ADMIN]), (_req, res, next) => {
  try {
    const users = repo.listUsers();
    return res.status(200).json({
      ok: true,
      data: users,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
