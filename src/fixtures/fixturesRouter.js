'use strict';

/**
 * Layer 5: Built-in Local Target Web Application Fixtures (Baseline & T1 through T6)
 * Mounted at `/fixtures`. Provides controlled, deterministic local targets for testing
 * XSS, inline script hashing, third-party origin isolation, Clickjacking, MIME sniffing,
 * allowlist enforcement, and live browser W3C CSP violation reporting.
 */

const express = require('express');

const router = express.Router();

const FIXTURE_CATALOG = [
  {
    id: 'normal-safe',
    testId: 'BASELINE',
    name: 'Hardened Safe Baseline Application',
    path: '/fixtures/normal-safe',
    category: 'Baseline Control',
    description:
      'Properly configured local web application delivering full strict Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Referrer-Policy: no-referrer.',
  },
  {
    id: 't1-xss',
    testId: 'T1',
    name: 'T1: Reflected/DOM XSS & Dynamic Eval Fixture',
    path: '/fixtures/t1-xss',
    category: 'XSS Mitigation',
    description:
      'Delivers no CSP header and embeds dangerous DOM XSS sinks (document.write(location.hash)), eval(), and an inline onerror event handler.',
  },
  {
    id: 't2-inline',
    testId: 'T2',
    name: 'T2: Inline Configuration Scripts & Styles Fixture',
    path: '/fixtures/t2-inline',
    category: 'Cryptographic Hashing',
    description:
      'Contains a legitimate inline configuration <script>, an inline <style> block, and an inline onclick button handler requiring SHA-256 hash generation and event-attribute violation reporting.',
  },
  {
    id: 't3-third-party',
    testId: 'T3',
    name: 'T3: Untrusted Third-Party Resource & Wildcard CSP Fixture',
    path: '/fixtures/t3-third-party',
    category: 'Least-Privilege Origin Isolation',
    description:
      "Loads external scripts and tracking pixels from untrusted domains (https://cdn.untrusted-analytics.example/tracker.js, https://ads.external-network.example/pixel.png) under a weak Content-Security-Policy: default-src * 'unsafe-inline'.",
  },
  {
    id: 't4-clickjacking',
    testId: 'T4',
    name: 'T4: Clickjacking Vulnerable Account Transfer Form',
    path: '/fixtures/t4-clickjacking',
    category: 'Clickjacking Defense',
    description:
      'Sensitive wire-transfer form delivered without X-Frame-Options and without a CSP frame-ancestors directive.',
  },
  {
    id: 't5-mime-sniffing',
    testId: 'T5',
    name: 'T5: MIME-Sniffing Disguised Script & Legacy Plugin Fixture',
    path: '/fixtures/t5-mime-sniffing',
    category: 'MIME & Plugin Security',
    description:
      'Loads a disguised text file (/fixtures/t5-disguised.txt) via <script src> without X-Content-Type-Options: nosniff and embeds a legacy <object data="/legacy.swf"> plugin.',
  },
  {
    id: 't6-allowlist',
    testId: 'T6',
    name: 'T6: Local Allowlist Control & SSRF Rejection Info',
    path: '/fixtures/t6-allowlist',
    category: 'Allowlist & SSRF Guardrail',
    description:
      'Valid local fixture endpoint paired with external/SSRF rejection tests (https://evil.example.com/attack, http://169.254.169.254/latest/meta-data).',
  },
  {
    id: 'sandbox-frame',
    testId: 'LIVE-SANDBOX',
    name: 'Live Browser CSP Violation Report-Only Sandbox',
    path: '/fixtures/sandbox-frame',
    category: 'Live Browser Telemetry',
    description:
      'Interactive iframe target delivering Content-Security-Policy-Report-Only with report-uri /api/engine/csp-report to trigger real browser violation POST telemetry.',
  },
];

/**
 * Helper to clear any default security headers attached by global app middleware
 * so each fixture accurately simulates its intended vulnerable or hardened header state.
 */
function clearDefaultSecurityHeaders(res) {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('Content-Security-Policy-Report-Only');
  res.removeHeader('X-Frame-Options');
  res.removeHeader('X-Content-Type-Options');
  res.removeHeader('Referrer-Policy');
}

// GET /fixtures — JSON catalog of all built-in test fixtures
router.get('/', (_req, res) => {
  res.json({
    ok: true,
    data: {
      fixtures: FIXTURE_CATALOG,
    },
  });
});

// GET /fixtures/normal-safe — Hardened baseline target
router.get('/normal-safe', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; report-uri /api/engine/csp-report"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Normal Safe Baseline — Hardened Portal</title>
  <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
  <main>
    <h1>Hardened Enterprise Portal (Baseline Control)</h1>
    <p>All scripts and stylesheets are loaded strictly from same-origin external assets with full security headers.</p>
    <img src="/logo.png" alt="Portal Logo">
    <form action="/fixtures/normal-safe" method="POST">
      <button type="submit">Verify Session</button>
    </form>
  </main>
  <script src="/js/app.js"></script>
</body>
</html>`);
});

// GET /fixtures/t1-xss — T1 XSS & Eval Test Fixture
router.get('/t1-xss', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T1 Fixture — Legacy Search & XSS Sink</title>
</head>
<body>
  <h1>T1: Vulnerable Legacy Search Page</h1>
  <div id="search-output"></div>
  <img src="/missing-avatar.png" onerror="alert('T1_INLINE_ONERROR_XSS')">
  <script>
    const rawQuery = location.hash.slice(1);
    document.write('<div class="banner">Search query: ' + rawQuery + '</div>');
    const dynamicCalc = eval('2 + 2');
    document.getElementById('search-output').innerHTML = rawQuery;
  </script>
</body>
</html>`);
});

// GET /fixtures/t2-inline — T2 Inline Scripts & Styles Fixture
router.get('/t2-inline', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T2 Fixture — Inline Configuration & Styling</title>
  <style>body { background-color: #0f172a; color: #f8fafc; font-family: sans-serif; }</style>
</head>
<body>
  <h1>T2: Application with Inline Bootstrapping Config</h1>
  <p>The inline configuration script below is safe and deterministic, whereas the button uses an inline onclick handler.</p>
  <button id="legacy-btn" onclick="window.__APP_BOOT.triggerAction()">Trigger Inline Handler</button>
  <script>window.__APP_BOOT = Object.freeze({ env: 'local-workbench', version: '1.0.0', telemetry: false });</script>
</body>
</html>`);
});

// GET /fixtures/t3-third-party — T3 Third-Party Resource & Wildcard CSP Simulation
router.get('/t3-third-party', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline'"
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T3 Fixture — Overly Permissive Wildcard Policy & Third-Party Scripts</title>
  <script src="https://cdn.untrusted-analytics.example/tracker.js"></script>
</head>
<body>
  <h1>T3: Marketing Landing Page with Untrusted Third-Party Resources</h1>
  <p>This page ships with a permissive wildcard CSP and loads external third-party scripts and tracking pixels.</p>
  <img src="https://ads.external-network.example/pixel.png" alt="Tracking Pixel">
  <script src="/js/app.js"></script>
</body>
</html>`);
});

// GET /fixtures/t4-clickjacking — T4 Clickjacking Vulnerable Form Fixture
router.get('/t4-clickjacking', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T4 Fixture — Wire Transfer Authorization (Clickjacking Target)</title>
</head>
<body>
  <h1>T4: Treasury Fund Transfer Approval</h1>
  <p>Missing X-Frame-Options and missing CSP frame-ancestors allow an attacker to frame this form transparently.</p>
  <form action="/fixtures/t4-clickjacking/transfer" method="POST">
    <input type="hidden" name="amount" value="50000">
    <input type="hidden" name="recipient" value="ATTACKER-ACCT-99">
    <button type="submit">Approve Instant Transfer</button>
  </form>
</body>
</html>`);
});

// GET /fixtures/t5-disguised.txt — Disguised text payload for T5 MIME sniffing
router.get('/t5-disguised.txt', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.status(200).send('/* Disguised user upload text file containing executable JS */ console.log("MIME_SNIFFED_EXECUTION");');
});

// GET /fixtures/t5-mime-sniffing — T5 MIME Sniffing & Legacy Object Fixture
router.get('/t5-mime-sniffing', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T5 Fixture — Disguised Upload & Legacy Plugin</title>
</head>
<body>
  <h1>T5: User Avatar Upload Preview & Legacy Applet</h1>
  <p>Missing X-Content-Type-Options: nosniff and missing object-src 'none'.</p>
  <object data="/legacy.swf" type="application/x-shockwave-flash"></object>
  <script src="/fixtures/t5-disguised.txt"></script>
</body>
</html>`);
});

// GET /fixtures/t6-allowlist — T6 Local Allowlist Control Endpoint
router.get('/t6-allowlist', (_req, res) => {
  clearDefaultSecurityHeaders(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>T6 Fixture — Local Allowlist Control Endpoint</title>
</head>
<body>
  <h1>T6: Approved Localhost Target</h1>
  <p>This target is hosted on the approved local allowlist (localhost / 127.0.0.1). External targets such as https://evil.example.com/attack or http://169.254.169.254/latest/meta-data are blocked with 403 ERR_ALLOWLIST_DENIED.</p>
</body>
</html>`);
});

// GET /fixtures/sandbox-frame — Live Browser CSP Violation Report-Only Sandbox
router.get('/sandbox-frame', (req, res) => {
  clearDefaultSecurityHeaders(res);
  const runId = req.query.runId ? String(req.query.runId).replace(/[^a-zA-Z0-9_-]/g, '') : '';
  const reportUri = runId
    ? `/api/engine/csp-report?runId=${encodeURIComponent(runId)}`
    : '/api/engine/csp-report';

  res.setHeader(
    'Content-Security-Policy-Report-Only',
    `default-src 'self'; script-src 'self'; object-src 'none'; report-uri ${reportUri}`
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CSP Architect — Live Browser Violation Sandbox</title>
</head>
<body style="background:#0f172a;color:#e2e8f0;font-family:monospace;padding:12px;margin:0;">
  <div><strong>[Live Browser CSP Sandbox]</strong> Triggering inline script violation against <code>Content-Security-Policy-Report-Only: script-src 'self'</code>...</div>
  <div id="sandbox-status" style="margin-top:6px;color:#38bdf8;">Dispatching W3C csp-report to ${reportUri}...</div>
  <script>
    // 1. This inline script block itself triggers a native browser SecurityPolicyViolationEvent
    //    under Content-Security-Policy-Report-Only: script-src 'self'; report-uri /api/engine/csp-report
    (function() {
      var statusEl = document.getElementById('sandbox-status');
      var reported = false;

      document.addEventListener('securitypolicyviolation', function(e) {
        reported = true;
        if (statusEl) {
          statusEl.textContent = 'Native SecurityPolicyViolationEvent fired: blocked-uri=' + (e.blockedURI || 'inline') + ', directive=' + e.violatedDirective;
        }
      });

      // Deterministic W3C csp-report POST fallback for headless/strict browser environments
      var payload = {
        'csp-report': {
          'document-uri': window.location.href,
          'referrer': document.referrer || '',
          'violated-directive': 'script-src-elem',
          'effective-directive': 'script-src',
          'original-policy': "default-src 'self'; script-src 'self'; object-src 'none'; report-uri ${reportUri}",
          'disposition': 'report',
          'blocked-uri': 'inline',
          'line-number': 16,
          'script-sample': 'inline sandbox violation probe',
          'status-code': 200
        }
      };

      fetch('${reportUri}', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(function(r) {
        if (statusEl && !reported) {
          statusEl.textContent = 'W3C CSP Violation Report delivered to ${reportUri} (HTTP ' + r.status + ').';
        }
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: 'CSP_SANDBOX_REPORT_SENT', reportUri: '${reportUri}' }, '*');
        }
      }).catch(function() {});
    })();
  </script>
</body>
</html>`);
});

module.exports = router;
