'use strict';

const crypto = require('node:crypto');
const { getDb } = require('../db/database');
const {
  DEFAULT_SYSTEM_CONFIG,
  ENGINE_VERSION,
  redactSensitiveData,
} = require('../contracts/schemas');

/**
 * Computes SHA-256 hex digest of a session token so raw tokens are never stored in SQLite.
 * @param {string} rawToken
 * @returns {string}
 */
function hashToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken)).digest('hex');
}

/**
 * Finds a user record by username (includes password_hash for authentication checks).
 * @param {string} username
 * @returns {object|null}
 */
function findUserByUsername(username) {
  if (!username || typeof username !== 'string') return null;
  const db = getDb();
  const row = db
    .prepare(
      'SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?'
    )
    .get(username.trim());
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    password_hash: row.password_hash,
    role: row.role,
    created_at: row.created_at,
    createdAt: row.created_at,
  };
}

/**
 * Finds a user record by numeric ID (excludes password_hash).
 * @param {number} id
 * @returns {object|null}
 */
function findUserById(id) {
  if (id === undefined || id === null) return null;
  const db = getDb();
  const row = db
    .prepare('SELECT id, username, role, created_at FROM users WHERE id = ?')
    .get(Number(id));
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    created_at: row.created_at,
    createdAt: row.created_at,
  };
}

/**
 * Lists all users without password hashes.
 * @returns {Array<object>}
 */
function listUsers() {
  const db = getDb();
  const rows = db
    .prepare('SELECT id, username, role, created_at FROM users ORDER BY id ASC')
    .all();
  return rows.map((row) => ({
    id: row.id,
    username: row.username,
    role: row.role,
    created_at: row.created_at,
    createdAt: row.created_at,
  }));
}

/**
 * Creates a new authenticated session with a hashed session token and CSRF token.
 * @param {number|object} userIdOrOpts
 * @param {string} [rawTokenArg]
 * @param {string} [csrfTokenArg]
 * @param {number} [ttlMsArg]
 * @returns {object}
 */
function createSession(userIdOrOpts, rawTokenArg, csrfTokenArg, ttlMsArg) {
  let userId = userIdOrOpts;
  let rawToken = rawTokenArg;
  let csrfToken = csrfTokenArg;
  let ttlMs = ttlMsArg;

  if (typeof userIdOrOpts === 'object' && userIdOrOpts !== null) {
    userId = userIdOrOpts.userId;
    rawToken = userIdOrOpts.rawToken || userIdOrOpts.sessionToken;
    csrfToken = userIdOrOpts.csrfToken;
    ttlMs = userIdOrOpts.ttlMs;
  }

  const finalRawToken = rawToken || crypto.randomBytes(32).toString('hex');
  const finalCsrfToken = csrfToken || crypto.randomBytes(24).toString('hex');
  const finalTtlMs = Number(ttlMs) > 0 ? Number(ttlMs) : 2 * 60 * 60 * 1000;

  const tokenHash = hashToken(finalRawToken);
  const now = Date.now();
  const expiresAt = now + finalTtlMs;
  const createdAt = new Date(now).toISOString();

  const db = getDb();
  db.prepare(
    `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(tokenHash, Number(userId), finalCsrfToken, expiresAt, createdAt);

  return {
    userId: Number(userId),
    sessionToken: finalRawToken,
    tokenHash,
    csrfToken: finalCsrfToken,
    expiresAt,
    createdAt,
  };
}

/**
 * Resolves an active session by raw session token, purging expired tokens automatically.
 * @param {string} rawToken
 * @returns {object|null}
 */
function getSession(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') return null;
  const tokenHash = hashToken(rawToken);
  const db = getDb();

  const row = db
    .prepare(
      `SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, s.created_at,
              u.username, u.role
       FROM sessions s
       INNER JOIN users u ON s.user_id = u.id
       WHERE s.token_hash = ?`
    )
    .get(tokenHash);

  if (!row) return null;

  if (Number(row.expires_at) <= Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }

  return {
    id: row.user_id,
    userId: row.user_id,
    username: row.username,
    role: row.role,
    csrfToken: row.csrf_token,
    sessionToken: rawToken,
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

/**
 * Deletes an active session by raw token.
 * @param {string} rawToken
 * @returns {boolean}
 */
function deleteSession(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') return false;
  const tokenHash = hashToken(rawToken);
  const db = getDb();
  const result = db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
  return result.changes > 0;
}

/**
 * Retrieves the current system configuration from SQLite.
 * @returns {object}
 */
function getSystemConfig() {
  const db = getDb();
  const row = db
    .prepare('SELECT value_json, updated_by, updated_at FROM system_config WHERE key = ?')
    .get('main');

  if (!row) {
    return JSON.parse(JSON.stringify(DEFAULT_SYSTEM_CONFIG));
  }

  try {
    const parsed = JSON.parse(row.value_json);
    return {
      ...JSON.parse(JSON.stringify(DEFAULT_SYSTEM_CONFIG)),
      ...parsed,
      rules: {
        ...JSON.parse(JSON.stringify(DEFAULT_SYSTEM_CONFIG.rules)),
        ...(parsed.rules || {}),
      },
      updatedBy: row.updated_by,
      updatedAt: row.updated_at,
    };
  } catch (_err) {
    return JSON.parse(JSON.stringify(DEFAULT_SYSTEM_CONFIG));
  }
}

/**
 * Updates and persists the system configuration.
 * @param {object} newConfig
 * @param {string} [updatedBy='admin']
 * @returns {object}
 */
function updateSystemConfig(newConfig, updatedBy = 'admin') {
  const db = getDb();
  const current = getSystemConfig();
  const now = new Date().toISOString();

  const mergedRules = { ...current.rules };
  if (newConfig && typeof newConfig.rules === 'object' && newConfig.rules !== null) {
    for (const [ruleId, ruleOverride] of Object.entries(newConfig.rules)) {
      if (mergedRules[ruleId] && typeof ruleOverride === 'object' && ruleOverride !== null) {
        mergedRules[ruleId] = {
          ...mergedRules[ruleId],
          ...ruleOverride,
          id: ruleId,
        };
      }
    }
  }

  const nextConfig = {
    allowlist: Array.isArray(newConfig?.allowlist) ? newConfig.allowlist : current.allowlist,
    allowedPorts: Array.isArray(newConfig?.allowedPorts)
      ? newConfig.allowedPorts
      : current.allowedPorts,
    maxCrawlSizeBytes:
      newConfig?.maxCrawlSizeBytes !== undefined
        ? Number(newConfig.maxCrawlSizeBytes)
        : current.maxCrawlSizeBytes,
    passScoreThreshold:
      newConfig?.passScoreThreshold !== undefined
        ? Number(newConfig.passScoreThreshold)
        : current.passScoreThreshold,
    criticalWarningThreshold:
      newConfig?.criticalWarningThreshold !== undefined
        ? Number(newConfig.criticalWarningThreshold)
        : current.criticalWarningThreshold,
    strictModeDefault:
      newConfig?.strictModeDefault !== undefined
        ? Boolean(newConfig.strictModeDefault)
        : current.strictModeDefault,
    engineVersion: current.engineVersion || ENGINE_VERSION,
    rules: mergedRules,
  };

  db.prepare(
    `INSERT INTO system_config (key, value_json, updated_by, updated_at)
     VALUES ('main', ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       value_json = excluded.value_json,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`
  ).run(JSON.stringify(nextConfig), String(updatedBy), now);

  return getSystemConfig();
}

/**
 * Resets the system configuration back to DEFAULT_SYSTEM_CONFIG.
 * @param {string} [updatedBy='admin']
 * @returns {object}
 */
function resetSystemConfig(updatedBy = 'admin') {
  const db = getDb();
  const now = new Date().toISOString();
  const defaultCopy = JSON.parse(JSON.stringify(DEFAULT_SYSTEM_CONFIG));

  db.prepare(
    `INSERT INTO system_config (key, value_json, updated_by, updated_at)
     VALUES ('main', ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       value_json = excluded.value_json,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`
  ).run(JSON.stringify(defaultCopy), String(updatedBy), now);

  return getSystemConfig();
}

/**
 * Formats a database workflow_runs row into a normalized object with parsed stages.
 * @param {object} row
 * @returns {object|null}
 */
function mapWorkflowRunRow(row) {
  if (!row) return null;
  let stages = {};
  try {
    stages = row.stages_json ? JSON.parse(row.stages_json) : {};
  } catch (_err) {
    stages = {};
  }
  return {
    id: row.id,
    userId: row.user_id,
    user_id: row.user_id,
    username: row.username,
    targetUrl: row.target_url,
    target_url: row.target_url,
    status: row.status,
    beforeScore: row.before_score,
    before_score: row.before_score,
    afterScore: row.after_score,
    after_score: row.after_score,
    engineVersion: row.engine_version,
    engine_version: row.engine_version,
    latencyMs: row.latency_ms,
    latency_ms: row.latency_ms,
    stages,
    createdAt: row.created_at,
    created_at: row.created_at,
  };
}

/**
 * Persists a 6-stage workflow execution record.
 * @param {object} runObj
 * @returns {object}
 */
function saveWorkflowRun(runObj = {}) {
  const db = getDb();
  const id = runObj.id || crypto.randomUUID();
  const userId = Number(runObj.userId ?? runObj.user_id ?? 0);
  const username = String(runObj.username || 'anonymous');
  const targetUrl = String(runObj.targetUrl ?? runObj.target_url ?? '');
  const status = String(runObj.status || 'COMPLETED');
  const beforeScore = Number(runObj.beforeScore ?? runObj.before_score ?? 0);
  const afterScore = Number(runObj.afterScore ?? runObj.after_score ?? 0);
  const engineVersion = String(
    runObj.engineVersion ?? runObj.engine_version ?? ENGINE_VERSION
  );
  const latencyMs = Number(runObj.latencyMs ?? runObj.latency_ms ?? 0);
  const stagesObj =
    runObj.stages !== undefined
      ? runObj.stages
      : typeof runObj.stages_json === 'string'
      ? JSON.parse(runObj.stages_json)
      : {};
  const stagesJson = JSON.stringify(stagesObj);
  const createdAt = runObj.createdAt || runObj.created_at || new Date().toISOString();

  db.prepare(
    `INSERT INTO workflow_runs (
      id, user_id, username, target_url, status,
      before_score, after_score, engine_version, latency_ms,
      stages_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      status = excluded.status,
      before_score = excluded.before_score,
      after_score = excluded.after_score,
      latency_ms = excluded.latency_ms,
      stages_json = excluded.stages_json`
  ).run(
    id,
    userId,
    username,
    targetUrl,
    status,
    beforeScore,
    afterScore,
    engineVersion,
    latencyMs,
    stagesJson,
    createdAt
  );

  return getWorkflowRunById(id);
}

/**
 * Retrieves a single workflow run by ID with parsed stages.
 * @param {string} id
 * @returns {object|null}
 */
function getWorkflowRunById(id) {
  if (!id) return null;
  const db = getDb();
  const row = db.prepare('SELECT * FROM workflow_runs WHERE id = ?').get(String(id));
  return mapWorkflowRunRow(row);
}

/**
 * Lists workflow runs with optional filtering by status and search term.
 * @param {object} [filters]
 * @returns {Array<object>}
 */
function listWorkflowRuns(filters = {}) {
  const db = getDb();
  const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 500);
  const conditions = [];
  const params = [];

  if (filters.status) {
    conditions.push('status = ?');
    params.push(String(filters.status));
  }

  if (filters.search) {
    conditions.push('(target_url LIKE ? OR username LIKE ? OR id LIKE ?)');
    const pattern = `%${String(filters.search).trim()}%`;
    params.push(pattern, pattern, pattern);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sql = `SELECT * FROM workflow_runs ${whereClause} ORDER BY created_at DESC, rowid DESC LIMIT ?`;
  params.push(limit);

  const rows = db.prepare(sql).all(...params);
  return rows.map(mapWorkflowRunRow);
}

/**
 * Formats a database violation_reports row into a normalized object.
 * @param {object} row
 * @returns {object|null}
 */
function mapViolationReportRow(row) {
  if (!row) return null;
  let rawReport = {};
  try {
    rawReport = row.raw_report_json ? JSON.parse(row.raw_report_json) : {};
  } catch (_err) {
    rawReport = {};
  }
  return {
    id: row.id,
    runId: row.run_id,
    run_id: row.run_id,
    source: row.source,
    documentUri: row.document_uri,
    document_uri: row.document_uri,
    violatedDirective: row.violated_directive,
    violated_directive: row.violated_directive,
    blockedUri: row.blocked_uri,
    blocked_uri: row.blocked_uri,
    disposition: row.disposition,
    rawReport,
    raw_report_json: row.raw_report_json,
    createdAt: row.created_at,
    created_at: row.created_at,
  };
}

/**
 * Saves a normalized W3C or simulated CSP violation report.
 * @param {object} reportObj
 * @returns {object}
 */
function saveViolationReport(reportObj = {}) {
  const db = getDb();
  const id = reportObj.id || crypto.randomUUID();
  const runId = reportObj.runId ?? reportObj.run_id ?? null;
  const source = String(reportObj.source || 'browser');
  const documentUri = String(
    reportObj.documentUri ?? reportObj.document_uri ?? 'unknown'
  );
  const violatedDirective = String(
    reportObj.violatedDirective ?? reportObj.violated_directive ?? 'unknown'
  );
  const blockedUri = String(reportObj.blockedUri ?? reportObj.blocked_uri ?? 'unknown');
  const disposition = String(reportObj.disposition || 'enforce');
  const rawPayload =
    reportObj.rawReport !== undefined
      ? reportObj.rawReport
      : reportObj.raw_report_json !== undefined
      ? typeof reportObj.raw_report_json === 'string'
        ? JSON.parse(reportObj.raw_report_json)
        : reportObj.raw_report_json
      : reportObj;
  const sanitizedRaw = redactSensitiveData(rawPayload);
  const rawReportJson = JSON.stringify(sanitizedRaw);
  const createdAt = reportObj.createdAt || reportObj.created_at || new Date().toISOString();

  db.prepare(
    `INSERT INTO violation_reports (
      id, run_id, source, document_uri, violated_directive,
      blocked_uri, disposition, raw_report_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    runId,
    source,
    documentUri,
    violatedDirective,
    blockedUri,
    disposition,
    rawReportJson,
    createdAt
  );

  const row = db.prepare('SELECT * FROM violation_reports WHERE id = ?').get(id);
  return mapViolationReportRow(row);
}

/**
 * Lists recorded CSP violation reports.
 * @param {object} [filters]
 * @returns {Array<object>}
 */
function listViolationReports(filters = {}) {
  const db = getDb();
  const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
  const conditions = [];
  const params = [];

  const runId = filters.runId ?? filters.run_id;
  if (runId) {
    conditions.push('run_id = ?');
    params.push(String(runId));
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sql = `SELECT * FROM violation_reports ${whereClause} ORDER BY created_at DESC, rowid DESC LIMIT ?`;
  params.push(limit);

  const rows = db.prepare(sql).all(...params);
  return rows.map(mapViolationReportRow);
}

/**
 * Formats an audit_logs row into a normalized object.
 * @param {object} row
 * @returns {object|null}
 */
function mapAuditLogRow(row) {
  if (!row) return null;
  let details = {};
  try {
    details = row.details_json ? JSON.parse(row.details_json) : {};
  } catch (_err) {
    details = {};
  }
  return {
    id: row.id,
    timestamp: row.timestamp,
    actorUsername: row.actor_username,
    actor_username: row.actor_username,
    actorRole: row.actor_role,
    actor_role: row.actor_role,
    action: row.action,
    resource: row.resource,
    outcome: row.outcome,
    ipAddress: row.ip_address,
    ip_address: row.ip_address,
    details,
    details_json: row.details_json,
  };
}

/**
 * Appends an immutable, redacted security audit log entry (append-only table).
 * @param {object} entry
 * @returns {object}
 */
function appendAuditLog(entry = {}) {
  const db = getDb();
  const timestamp = entry.timestamp || new Date().toISOString();
  const actorUsername = String(
    entry.actorUsername ?? entry.actor_username ?? 'anonymous'
  );
  const actorRole = String(entry.actorRole ?? entry.actor_role ?? 'unauthenticated');
  const action = String(entry.action || 'UNKNOWN_ACTION');
  const resource = String(entry.resource || 'unknown');
  const outcome = String(entry.outcome || 'SUCCESS');
  const ipAddress = String(entry.ipAddress ?? entry.ip_address ?? '127.0.0.1');
  const sanitizedDetails = redactSensitiveData(entry.details ?? {});
  const detailsJson = JSON.stringify(sanitizedDetails);

  const result = db
    .prepare(
      `INSERT INTO audit_logs (
        timestamp, actor_username, actor_role, action,
        resource, outcome, ip_address, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      timestamp,
      actorUsername,
      actorRole,
      action,
      resource,
      outcome,
      ipAddress,
      detailsJson
    );

  const row = db
    .prepare('SELECT * FROM audit_logs WHERE id = ?')
    .get(Number(result.lastInsertRowid));
  return mapAuditLogRow(row);
}

/**
 * Lists append-only audit logs with optional filtering.
 * @param {object} [filters]
 * @returns {Array<object>}
 */
function listAuditLogs(filters = {}) {
  const db = getDb();
  const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 1000);
  const conditions = [];
  const params = [];

  if (filters.action) {
    conditions.push('action = ?');
    params.push(String(filters.action));
  }

  if (filters.outcome) {
    conditions.push('outcome = ?');
    params.push(String(filters.outcome));
  }

  if (filters.actor) {
    conditions.push('actor_username = ?');
    params.push(String(filters.actor));
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sql = `SELECT * FROM audit_logs ${whereClause} ORDER BY id DESC LIMIT ?`;
  params.push(limit);

  const rows = db.prepare(sql).all(...params);
  return rows.map(mapAuditLogRow);
}

module.exports = {
  findUserByUsername,
  findUserById,
  listUsers,
  createSession,
  getSession,
  deleteSession,
  getSystemConfig,
  updateSystemConfig,
  resetSystemConfig,
  saveWorkflowRun,
  getWorkflowRunById,
  listWorkflowRuns,
  saveViolationReport,
  listViolationReports,
  appendAuditLog,
  listAuditLogs,
};
