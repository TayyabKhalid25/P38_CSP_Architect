# 01 - Abdul Nafay Khan Burki: Backend, SQLite Repository, Authentication & RBAC Plan
**Owner:** Abdul Nafay Khan Burki  
**Git Branch:** `feat/nafay-backend-auth`  
**Git Author:** `Abdul Nafay Khan Burki <165305926+abdulnafaykhan@users.noreply.github.com>`  
**Assigned Layers:** Layer 2 (API, Auth, RBAC, CSRF, Rate Limiting) & Layer 4 (SQLite Data Store & Append-Only Audit Log)

---

## 1. Exclusive File Ownership
You may **only** create/modify the following files:
1. `src/db/database.js` - SQLite connection (`node:sqlite` `DatabaseSync`), schema creation, and default seed data (`admin`, `operator`, `viewer` accounts + default `system_config`).
2. `src/repositories/repo.js` - Data access layer for users, sessions, system config, workflow runs, violation reports, and append-only audit logs.
3. `src/middleware/security.js` - Session resolution, RBAC enforcement (`requireAuth`, `requireRole`), CSRF protection (`verifyCsrf`), rate limiting (`createRateLimiter`), and safe global error handling (`errorHandler`).
4. `src/routes/auth.js` - `/api/auth` endpoints (`POST /login`, `POST /logout`, `GET /me`).
5. `src/routes/admin.js` - `/api/admin` endpoints (`GET /config`, `PUT /config`, `POST /config/reset`, `GET /users`).
6. `src/routes/audit.js` - `/api/audit` endpoints (`GET /logs`).
7. `src/app.js` - Main Express application factory (`createApp()`) wiring static files (`public/`), cookies, security headers, and mounting `/api/auth`, `/api/admin`, `/api/audit`, `/api/engine`, `/api/reports`, and `/fixtures`.

---

## 2. Database Schema (`src/db/database.js`)
Use Node's built-in `const { DatabaseSync } = require('node:sqlite');`.
Database file path: `process.env.DB_PATH || path.join(__dirname, '../../data/csp_architect.sqlite')`.

### Required Tables
1. `users`:
   - `id INTEGER PRIMARY KEY AUTOINCREMENT`
   - `username TEXT UNIQUE NOT NULL`
   - `password_hash TEXT NOT NULL`
   - `role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'viewer'))`
   - `created_at TEXT NOT NULL`
2. `sessions`:
   - `token_hash TEXT PRIMARY KEY` (SHA-256 of session cookie token)
   - `user_id INTEGER NOT NULL`
   - `csrf_token TEXT NOT NULL`
   - `expires_at INTEGER NOT NULL` (epoch ms; default TTL = 2 hours)
   - `created_at TEXT NOT NULL`
3. `system_config`:
   - `key TEXT PRIMARY KEY` (`'main'`)
   - `value_json TEXT NOT NULL` (JSON string of `DEFAULT_SYSTEM_CONFIG`)
   - `updated_by TEXT NOT NULL`
   - `updated_at TEXT NOT NULL`
4. `workflow_runs`:
   - `id TEXT PRIMARY KEY` (UUID)
   - `user_id INTEGER NOT NULL`
   - `username TEXT NOT NULL`
   - `target_url TEXT NOT NULL`
   - `status TEXT NOT NULL` (`'COMPLETED'`, `'REJECTED'`, `'FAILED'`)
   - `before_score INTEGER NOT NULL DEFAULT 0`
   - `after_score INTEGER NOT NULL DEFAULT 0`
   - `engine_version TEXT NOT NULL`
   - `latency_ms INTEGER NOT NULL DEFAULT 0`
   - `stages_json TEXT NOT NULL`
   - `created_at TEXT NOT NULL`
5. `violation_reports`:
   - `id TEXT PRIMARY KEY` (UUID)
   - `run_id TEXT`
   - `source TEXT NOT NULL` (`'browser'` | `'simulation'`)
   - `document_uri TEXT NOT NULL`
   - `violated_directive TEXT NOT NULL`
   - `blocked_uri TEXT NOT NULL`
   - `disposition TEXT NOT NULL`
   - `raw_report_json TEXT NOT NULL`
   - `created_at TEXT NOT NULL`
6. `audit_logs` (Append-Only - never `UPDATE` or `DELETE` rows):
   - `id INTEGER PRIMARY KEY AUTOINCREMENT`
   - `timestamp TEXT NOT NULL`
   - `actor_username TEXT NOT NULL`
   - `actor_role TEXT NOT NULL`
   - `action TEXT NOT NULL`
   - `resource TEXT NOT NULL`
   - `outcome TEXT NOT NULL` (`'SUCCESS'` | `'DENIED'` | `'FAILURE'`)
   - `ip_address TEXT NOT NULL`
   - `details_json TEXT NOT NULL` (Sanitized via `redactSensitiveData()`)

### Seeded Default Accounts (Manual Login Only - documented in `README.md`)
- `admin` / `Admin@CSP2026!` (`role: 'admin'`)
- `operator` / `Operator@CSP2026!` (`role: 'operator'`)
- `viewer` / `Viewer@CSP2026!` (`role: 'viewer'`)

### Exports from `src/db/database.js`
- `initDb(customPath)` - initializes tables and seeds defaults if empty.
- `getDb()` - returns the active `DatabaseSync` instance (initializing if needed).
- `resetDbForTests()` - clears transient tables (`workflow_runs`, `violation_reports`, `sessions`) and resets `system_config` for clean test runs.

---

## 3. Repository Layer Exports (`src/repositories/repo.js`)
Must export:
- `findUserByUsername(username)`
- `findUserById(id)`
- `listUsers()` (returns id, username, role, created_at - never password_hash)
- `createSession(userId, rawToken, csrfToken, ttlMs)`
- `getSession(rawToken)` (joins `users`, checks `expires_at > Date.now()`, deletes if expired)
- `deleteSession(rawToken)`
- `getSystemConfig()` (parses `value_json`)
- `updateSystemConfig(newConfig, updatedBy)`
- `saveWorkflowRun(runObj)`
- `getWorkflowRunById(id)`
- `listWorkflowRuns({ limit, status, search })`
- `saveViolationReport(reportObj)`
- `listViolationReports({ runId, limit })`
- `appendAuditLog({ actorUsername, actorRole, action, resource, outcome, ipAddress, details })`
- `listAuditLogs({ limit, action, outcome, actor })`

---

## 4. Security Middleware Exports (`src/middleware/security.js`)
- `attachSession(req, res, next)` - reads `csp_session` cookie or `Authorization: Bearer <token>`, populates `req.user` (`{ id, username, role, csrfToken }`) if valid.
- `requireAuth(req, res, next)` - returns `401` (`ERR_AUTH_REQUIRED`) and writes an `audit_logs` `DENIED` event if `!req.user`.
- `requireRole(allowedRoles)` - returns `403` (`ERR_AUTH_FORBIDDEN`) with a generic denial message and writes an `audit_logs` `DENIED` event if `!allowedRoles.includes(req.user.role)`.
- `verifyCsrf(req, res, next)` - for `POST`, `PUT`, `PATCH`, `DELETE` (except `/api/auth/login` and `/api/engine/csp-report` which receives browser W3C violation reports), verifies `req.headers['x-csrf-token'] === req.user.csrfToken`. Returns `403` (`ERR_CSRF_INVALID`) on mismatch.
- `createRateLimiter({ windowMs, max, keyPrefix })` - sliding window in-memory rate limiter; logs `DENIED` audit event and returns `429` (`ERR_RATE_LIMITED`) when exceeded.
- `errorHandler(err, req, res, next)` - catches body-parser `entity.too.large` (`413 ERR_PAYLOAD_TOO_LARGE`), `SyntaxError` (`400 ERR_VALIDATION_FAILED`), `AppError`, and unexpected errors (`500 ERR_INTERNAL`), never leaking stack traces.
