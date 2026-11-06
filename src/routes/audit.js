'use strict';

const express = require('express');
const repo = require('../repositories/repo');
const { ROLES } = require('../contracts/schemas');
const { requireAuth, requireRole, getClientIp } = require('../middleware/security');

const router = express.Router();

/**
 * GET /api/audit/logs
 * Returns append-only security audit logs with optional filtering (Admin only).
 */
router.get('/logs', requireAuth, requireRole([ROLES.ADMIN]), (req, res, next) => {
  try {
    const { limit, action, outcome, actor } = req.query || {};

    repo.appendAuditLog({
      actorUsername: req.user.username,
      actorRole: req.user.role,
      action: 'AUDIT_LOGS_VIEWED',
      resource: 'GET /api/audit/logs',
      outcome: 'SUCCESS',
      ipAddress: getClientIp(req),
      details: {
        filters: {
          limit: limit || 100,
          action: action || null,
          outcome: outcome || null,
          actor: actor || null,
        },
      },
    });

    const logs = repo.listAuditLogs({
      limit: limit ? Number(limit) : 100,
      action,
      outcome,
      actor,
    });

    return res.status(200).json({
      ok: true,
      data: logs,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
