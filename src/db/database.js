'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const { DEFAULT_SYSTEM_CONFIG, ROLES } = require('../contracts/schemas');

let dbInstance = null;
let currentDbPath = null;

/**
 * Resolves the target SQLite database file path.
 * @param {string} [customPath]
 * @returns {string}
 */
function resolveDbPath(customPath) {
  if (customPath) return customPath;
  if (process.env.DB_PATH) return process.env.DB_PATH;
  return path.join(__dirname, '../../data/csp_architect.sqlite');
}

/**
 * Initializes the SQLite database connection, schema tables, and default seed records.
 * @param {string} [customPath]
 * @returns {DatabaseSync}
 */
function initDb(customPath) {
  const targetPath = resolveDbPath(customPath);

  if (dbInstance && currentDbPath === targetPath) {
    return dbInstance;
  }

  if (dbInstance && currentDbPath !== targetPath) {
    try {
      dbInstance.close();
    } catch (_err) {
      // Ignore close error on re-init
    }
    dbInstance = null;
  }

  if (targetPath !== ':memory:') {
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
  }

  dbInstance = new DatabaseSync(targetPath);
  currentDbPath = targetPath;

  dbInstance.exec('PRAGMA journal_mode = WAL;');
  dbInstance.exec('PRAGMA foreign_keys = ON;');

  createTables(dbInstance);
  seedDefaults(dbInstance);

  return dbInstance;
}

/**
 * Creates all required application tables if they do not exist.
 * @param {DatabaseSync} db
 */
function createTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'viewer')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      csrf_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_by TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS workflow_runs (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      target_url TEXT NOT NULL,
      status TEXT NOT NULL,
      before_score INTEGER NOT NULL DEFAULT 0,
      after_score INTEGER NOT NULL DEFAULT 0,
      engine_version TEXT NOT NULL,
      latency_ms INTEGER NOT NULL DEFAULT 0,
      stages_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS violation_reports (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      source TEXT NOT NULL,
      document_uri TEXT NOT NULL,
      violated_directive TEXT NOT NULL,
      blocked_uri TEXT NOT NULL,
      disposition TEXT NOT NULL,
      raw_report_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      actor_username TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      outcome TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      details_json TEXT NOT NULL
    );
  `);
}

/**
 * Seeds default RBAC user accounts and default system configuration if not already present.
 * @param {DatabaseSync} db
 */
function seedDefaults(db) {
  const now = new Date().toISOString();

  const defaultUsers = [
    { username: 'admin', password: 'Admin@CSP2026!', role: ROLES.ADMIN },
    { username: 'operator', password: 'Operator@CSP2026!', role: ROLES.OPERATOR },
    { username: 'viewer', password: 'Viewer@CSP2026!', role: ROLES.VIEWER },
  ];

  const checkUserStmt = db.prepare('SELECT id FROM users WHERE username = ?');
  const insertUserStmt = db.prepare(
    'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
  );

  for (const u of defaultUsers) {
    const existing = checkUserStmt.get(u.username);
    if (!existing) {
      const hash = bcrypt.hashSync(u.password, 10);
      insertUserStmt.run(u.username, hash, u.role, now);
    }
  }

  const existingConfig = db.prepare('SELECT key FROM system_config WHERE key = ?').get('main');
  if (!existingConfig) {
    db.prepare(
      'INSERT INTO system_config (key, value_json, updated_by, updated_at) VALUES (?, ?, ?, ?)'
    ).run('main', JSON.stringify(DEFAULT_SYSTEM_CONFIG), 'system', now);
  }
}

/**
 * Returns the active SQLite database instance, initializing it if needed.
 * @returns {DatabaseSync}
 */
function getDb() {
  if (!dbInstance) {
    return initDb();
  }
  return dbInstance;
}

/**
 * Resets transient runtime state and restores default system configuration for isolated testing.
 */
function resetDbForTests() {
  const db = getDb();
  const now = new Date().toISOString();

  db.exec('DELETE FROM sessions;');
  db.exec('DELETE FROM workflow_runs;');
  db.exec('DELETE FROM violation_reports;');

  db.prepare(
    `INSERT INTO system_config (key, value_json, updated_by, updated_at)
     VALUES ('main', ?, 'system', ?)
     ON CONFLICT(key) DO UPDATE SET
       value_json = excluded.value_json,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`
  ).run(JSON.stringify(DEFAULT_SYSTEM_CONFIG), now);

  seedDefaults(db);
}

module.exports = {
  initDb,
  getDb,
  resetDbForTests,
};
