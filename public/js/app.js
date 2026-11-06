'use strict';

/**
 * CSP Architect - Browser Security Header Workbench
 * Frontend Application Controller (Vanilla ES6+)
 * Owner: Fasih Ur Rehman (Layer 1 Browser Interface)
 */

(function () {
  const state = {
    user: null,
    csrfToken: null,
    activeTab: 'workbench',
    activeRunId: null,
    activeLatencyMs: null,
    stages: {
      crawlResult: null,
      headerAnalysis: null,
      cspBuild: null,
      violationAnalysis: null,
      scoreComparison: null,
      exportBundle: null,
    },
    historyRuns: [],
    adminConfig: null,
    pendingConfirmAction: null,
  };

  /* ========================================================================
     UTILITIES & DOM HELPERS
     ======================================================================== */
  function $(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatTimestamp(isoString) {
    if (!isoString) return ' - ';
    try {
      const d = new Date(isoString);
      if (Number.isNaN(d.getTime())) return String(isoString);
      return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    } catch (_e) {
      return String(isoString);
    }
  }

  function resolveTargetUrl(rawVal) {
    const trimmed = String(rawVal || '').trim();
    if (!trimmed) return `${window.location.origin}/fixtures/t1-xss`;
    if (trimmed.startsWith('/')) {
      return `${window.location.origin}${trimmed}`;
    }
    return trimmed;
  }

  function showToast(message, type = 'info') {
    const container = $('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 4200);
  }

  function showGlobalAlert(code, message) {
    const container = $('global-alert-container');
    const codeEl = $('global-alert-code');
    const msgEl = $('global-alert-message');
    if (!container || !codeEl || !msgEl) return;
    codeEl.textContent = code || 'NOTICE';
    msgEl.textContent = message || 'An unexpected condition occurred.';
    container.classList.remove('hidden');
  }

  function hideGlobalAlert() {
    const container = $('global-alert-container');
    if (container) container.classList.add('hidden');
  }

  async function copyTextToClipboard(text, label) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement('textarea');
        area.value = text;
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        area.remove();
      }
      showToast(`${label} copied to clipboard.`, 'success');
    } catch (_err) {
      showToast(`Unable to copy ${label}.`, 'error');
    }
  }

  /* ========================================================================
     CENTRALIZED API CLIENT (WITH AUTOMATIC X-CSRF-TOKEN INJECTION)
     ======================================================================== */
  async function apiRequest(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = Object.assign({}, options.headers || {});

    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && state.csrfToken) {
      headers['X-CSRF-Token'] = state.csrfToken;
    }

    const fetchOptions = {
      method,
      headers,
      credentials: 'same-origin',
    };

    if (options.body !== undefined) {
      fetchOptions.body =
        typeof options.body === 'object' && !(options.body instanceof FormData)
          ? JSON.stringify(options.body)
          : options.body;
    }

    const response = await fetch(path, fetchOptions);
    const contentType = response.headers.get('content-type') || '';

    let payload = null;
    if (contentType.includes('application/json')) {
      try {
        payload = await response.json();
      } catch (_e) {
        payload = null;
      }
    } else {
      const text = await response.text();
      payload = { ok: response.ok, rawText: text };
    }

    if (!response.ok || (payload && payload.ok === false)) {
      const errCode = payload?.error?.code || `HTTP_${response.status}`;
      const errMsg =
        payload?.error?.message ||
        `Request failed with HTTP status ${response.status}.`;
      const err = new Error(errMsg);
      err.code = errCode;
      err.status = response.status;
      err.details = payload?.error?.details || null;

      if (response.status === 401 && !options.silentAuth) {
        handleSessionExpired();
      } else if (!options.silentAlert) {
        showGlobalAlert(errCode, errMsg);
        showToast(`${errCode}: ${errMsg}`, 'error');
      }
      throw err;
    }

    return payload?.data !== undefined ? payload.data : payload;
  }

  /* ========================================================================
     AUTHENTICATION & SESSION FLOW
     ======================================================================== */
  function setAuthenticatedSession(authData) {
    const user = authData?.user || authData;
    state.user = {
      id: user?.id,
      username: user?.username || 'operator',
      role: (user?.role || 'operator').toLowerCase(),
    };
    state.csrfToken = authData?.csrfToken || user?.csrfToken || state.csrfToken;

    $('login-screen').classList.add('hidden');
    $('app-shell').classList.remove('hidden');
    $('login-error-banner').classList.add('hidden');

    $('header-username').textContent = state.user.username;
    const roleBadge = $('header-role-badge');
    roleBadge.textContent = state.user.role.toUpperCase();
    roleBadge.className = `role-badge role-${state.user.role}`;

    const adminBanner = $('admin-rbac-banner');
    if (adminBanner) {
      if (state.user.role !== 'admin') {
        adminBanner.classList.remove('hidden');
      } else {
        adminBanner.classList.add('hidden');
      }
    }
  }

  function handleSessionExpired() {
    state.user = null;
    state.csrfToken = null;
    $('app-shell').classList.add('hidden');
    $('login-screen').classList.remove('hidden');
    const pwdInput = $('login-password');
    if (pwdInput) pwdInput.value = '';
  }

  async function checkExistingSession() {
    try {
      const data = await apiRequest('/api/auth/me', {
        method: 'GET',
        silentAuth: true,
        silentAlert: true,
      });
      if (data && (data.user || data.username)) {
        setAuthenticatedSession(data);
        await loadInitialData();
      }
    } catch (_err) {
      handleSessionExpired();
    }
  }

  async function handleLoginSubmit(event) {
    event.preventDefault();
    hideGlobalAlert();
    const banner = $('login-error-banner');
    banner.classList.add('hidden');

    const username = $('login-username').value.trim();
    const password = $('login-password').value;

    if (!username || !password) {
      banner.textContent = 'Please enter both username and password.';
      banner.classList.remove('hidden');
      return;
    }

    const submitBtn = $('login-submit-btn');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying Credentials...';

    try {
      const data = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { username, password },
        silentAlert: true,
        silentAuth: true,
      });
      $('login-password').value = '';
      setAuthenticatedSession(data);
      showToast(`Signed in as ${state.user.username} (${state.user.role.toUpperCase()}).`, 'success');
      await loadInitialData();
    } catch (err) {
      banner.textContent = `${err.code || 'ERR_AUTH_INVALID'}: ${err.message}`;
      banner.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign In to Security Workbench';
    }
  }

  async function handleLogout() {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST', silentAlert: true });
    } catch (_err) {
      // Ignore logout transport errors
    }
    handleSessionExpired();
    showToast('Signed out of CSP Architect.', 'info');
  }

  async function loadInitialData() {
    const presetVal = $('target-preset-select')?.value || '/fixtures/t1-xss';
    const fullUrl = resolveTargetUrl(presetVal);
    if ($('target-url-input')) $('target-url-input').value = fullUrl;
    if ($('header-active-target')) $('header-active-target').textContent = fullUrl;

    await loadHistoryRuns({ silent: true });
  }

  /* ========================================================================
     NAVIGATION TABS
     ======================================================================== */
  function switchTab(tabKey) {
    state.activeTab = tabKey;
    const tabs = ['workbench', 'evaluation', 'history', 'admin'];
    for (const key of tabs) {
      const btn = $(`tab-btn-${key}`);
      const panel = $(`panel-${key}`);
      const isMatch = key === tabKey;
      if (btn) {
        btn.classList.toggle('active', isMatch);
        btn.setAttribute('aria-selected', isMatch ? 'true' : 'false');
      }
      if (panel) {
        panel.classList.toggle('active', isMatch);
        panel.classList.toggle('hidden', !isMatch);
      }
    }

    if (tabKey === 'history') {
      loadHistoryRuns({ silent: true });
    } else if (tabKey === 'admin') {
      loadAdminConsoleData();
    }
  }

  /* ========================================================================
     STAGE STATUS PILLS & BADGES
     ======================================================================== */
  function setStageStatus(stageNum, statusText) {
    const normalized = String(statusText || 'IDLE').toUpperCase();
    const pill = $(`pill-status-${stageNum}`);
    const badge = $(`stage${stageNum}-status-badge`);

    let pillClass = 'status-dot status-idle';
    let badgeClass = 'badge badge-neutral';

    if (normalized === 'COMPLETED' || normalized === 'PASS') {
      pillClass = 'status-dot status-completed';
      badgeClass = 'badge badge-success';
    } else if (normalized === 'REJECTED' || normalized === 'FAILED' || normalized === 'FAIL') {
      pillClass = 'status-dot status-rejected';
      badgeClass = 'badge badge-danger';
    } else if (normalized === 'WARNING' || normalized === 'RUNNING') {
      pillClass = 'status-dot status-warning';
      badgeClass = 'badge badge-warning';
    }

    if (pill) {
      pill.className = pillClass;
      pill.textContent = normalized;
    }
    if (badge) {
      badge.className = badgeClass;
      badge.textContent = normalized;
    }
  }

  function updateRunMetaHeader(runId, latencyMs) {
    state.activeRunId = runId || state.activeRunId;
    state.activeLatencyMs = latencyMs ?? state.activeLatencyMs;
    $('active-run-id-label').textContent = state.activeRunId
      ? String(state.activeRunId).slice(0, 12)
      : 'Interactive';
    $('active-run-latency-label').textContent =
      state.activeLatencyMs !== null && state.activeLatencyMs !== undefined
        ? `${state.activeLatencyMs} ms`
        : ' - ';
  }

  function getBuilderOptions() {
    const mode = $('csp-mode-select')?.value || 'strict-hash';
    const allowInlineHashes = Boolean($('csp-allow-hashes-toggle')?.checked);
    const allowFramingSelf = Boolean($('csp-allow-framing-toggle')?.checked);
    const includeReportUri = Boolean($('csp-include-report-toggle')?.checked);
    const rawOrigins = $('csp-trusted-origins-input')?.value || '';
    const allowedThirdPartyOrigins = rawOrigins
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    return {
      mode,
      allowInlineHashes,
      allowFramingSelf,
      includeReportUri,
      allowedThirdPartyOrigins,
    };
  }

  /* ========================================================================
     6-STAGE WORKBENCH EXECUTION & RENDERING
     ======================================================================== */
  function extractStagesFromPayload(data) {
    const root = data?.stages || data?.run?.stages || data || {};
    return {
      crawlResult: root.crawlResult || root.fr1 || data?.crawlResult || null,
      headerAnalysis: root.headerAnalysis || root.fr2 || data?.headerAnalysis || null,
      cspBuild: root.cspBuild || root.fr3 || data?.cspBuild || null,
      violationAnalysis: root.violationAnalysis || root.fr4 || data?.violationAnalysis || null,
      scoreComparison: root.scoreComparison || root.fr5 || data?.scoreComparison || null,
      exportBundle: root.exportBundle || root.fr6 || data?.exportBundle || null,
    };
  }

  async function runFullPipeline() {
    hideGlobalAlert();
    const targetUrl = resolveTargetUrl($('target-url-input').value);
    $('target-url-input').value = targetUrl;
    $('header-active-target').textContent = targetUrl;

    const btn = $('run-pipeline-btn');
    btn.disabled = true;
    btn.textContent = 'Running 6-Stage Pipeline...';

    for (let i = 1; i <= 6; i++) setStageStatus(i, 'RUNNING');

    const startedAt = performance.now();
    try {
      const data = await apiRequest('/api/engine/run-pipeline', {
        method: 'POST',
        body: {
          targetUrl,
          options: getBuilderOptions(),
        },
      });

      const elapsed = Math.round(performance.now() - startedAt);
      const runObj = data?.run || data;
      const runId = runObj?.id || data?.runId || null;
      const latencyMs = runObj?.latencyMs ?? runObj?.latency_ms ?? data?.latencyMs ?? elapsed;

      const stages = extractStagesFromPayload(data);
      state.stages = stages;

      updateRunMetaHeader(runId, latencyMs);
      renderAllStages(stages);
      showToast(`Completed 6-stage security pipeline for ${targetUrl} in ${latencyMs} ms.`, 'success');
      loadHistoryRuns({ silent: true });
    } catch (err) {
      renderPipelineRejection(targetUrl, err);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Run Full 6-Stage Pipeline';
    }
  }

  function renderPipelineRejection(targetUrl, err) {
    setStageStatus(1, 'REJECTED');
    for (let i = 2; i <= 6; i++) setStageStatus(i, 'IDLE');

    $('s1-http-status').textContent = `${err.status || 403} BLOCKED`;
    $('s1-origin').textContent = targetUrl;
    $('s1-ext-scripts').textContent = '0';
    $('s1-inline-scripts').textContent = '0';
    $('s1-event-handlers').textContent = '0';
    $('s1-eval-sinks').textContent = 'Blocked at Allowlist Gate';
    $('stage1-raw-headers').textContent = `Request aborted before network socket connection.\nReason: ${err.code || 'ERR_ALLOWLIST_DENIED'} - ${err.message}`;

    const evList = $('stage1-evidence-list');
    evList.innerHTML = `
      <li class="evidence-item">
        <span class="badge badge-danger">${escapeHtml(err.code || 'ERR_ALLOWLIST_DENIED')}</span>
        <span>${escapeHtml(err.message)}</span>
      </li>
    `;
  }

  function renderAllStages(stages) {
    if (stages.crawlResult) renderStage1(stages.crawlResult);
    if (stages.headerAnalysis) renderStage2(stages.headerAnalysis);
    if (stages.cspBuild) renderStage3(stages.cspBuild);
    if (stages.violationAnalysis) renderStage4(stages.violationAnalysis);
    if (stages.scoreComparison) renderStage5(stages.scoreComparison);
    if (stages.exportBundle) renderStage6(stages.exportBundle);
  }

  /* ---- Stage 1: Local Crawler ---- */
  async function runStage1Only() {
    hideGlobalAlert();
    const targetUrl = resolveTargetUrl($('target-url-input').value);
    $('target-url-input').value = targetUrl;
    $('header-active-target').textContent = targetUrl;

    setStageStatus(1, 'RUNNING');
    try {
      const data = await apiRequest('/api/engine/crawl', {
        method: 'POST',
        body: { targetUrl },
      });
      const crawlResult = data?.crawlResult || data;
      state.stages.crawlResult = crawlResult;
      renderStage1(crawlResult);
      showToast('Stage 1 (Local Crawler) completed.', 'success');
    } catch (err) {
      renderPipelineRejection(targetUrl, err);
    }
  }

  function renderStage1(crawl) {
    if (!crawl) return;
    setStageStatus(1, crawl.status || 'COMPLETED');

    const res = crawl.resources || {};
    const extScripts = res.externalScripts || [];
    const inlineScripts = res.inlineScripts || [];
    const handlers = res.inlineEventHandlers || [];
    const extStyles = res.externalStyles || [];
    const inlineStyles = res.inlineStyles || [];
    const frames = res.frames || [];
    const dangerousSinks = res.dangerousSinks || res.xssSinks || [];

    $('s1-http-status').textContent = `${crawl.httpStatus || 200} OK`;
    $('s1-origin').textContent = crawl.normalizedOrigin || crawl.targetUrl || ' - ';
    $('s1-ext-scripts').textContent = String(extScripts.length);
    $('s1-inline-scripts').textContent = String(inlineScripts.length);
    $('s1-event-handlers').textContent = String(handlers.length);
    $('s1-eval-sinks').textContent =
      crawl.resources?.usesEvalOrFunction || dangerousSinks.length > 0
        ? 'DETECTED (HIGH RISK)'
        : 'None';

    // Scripts, styles & hashes table
    const rows = [];
    for (const src of extScripts) {
      rows.push(`
        <tr>
          <td><span class="badge badge-info">External Script</span></td>
          <td class="code-text">${escapeHtml(src)}</td>
          <td><span class="badge badge-neutral">Origin Check Required</span></td>
        </tr>
      `);
    }
    for (const s of inlineScripts) {
      const unsafe = Boolean(s.unsafe || s.usesEval || s.hasXssSink);
      rows.push(`
        <tr>
          <td><span class="badge ${unsafe ? 'badge-danger' : 'badge-warning'}">Inline Script #${escapeHtml(s.index ?? 0)}</span></td>
          <td class="code-text">${escapeHtml(s.preview || s.code || '(inline script)')}</td>
          <td class="code-text">
            ${s.sha256 ? `'${escapeHtml(s.sha256)}'` : ' - '}
            ${unsafe ? ' <span class="badge badge-danger">UNSAFE SINK</span>' : ' <span class="badge badge-success">HASHABLE</span>'}
          </td>
        </tr>
      `);
    }
    for (const st of inlineStyles) {
      rows.push(`
        <tr>
          <td><span class="badge badge-neutral">Inline Style #${escapeHtml(st.index ?? 0)}</span></td>
          <td class="code-text">${escapeHtml(st.preview || '(inline style block)')}</td>
          <td class="code-text">${st.sha256 ? `'${escapeHtml(st.sha256)}'` : ' - '}</td>
        </tr>
      `);
    }
    for (const styleHref of extStyles) {
      rows.push(`
        <tr>
          <td><span class="badge badge-neutral">External Style</span></td>
          <td class="code-text">${escapeHtml(styleHref)}</td>
          <td>Same/Trusted Origin</td>
        </tr>
      `);
    }
    for (const fr of frames) {
      rows.push(`
        <tr>
          <td><span class="badge badge-warning">Embedded Frame</span></td>
          <td class="code-text">${escapeHtml(fr)}</td>
          <td>Requires frame-src</td>
        </tr>
      `);
    }

    $('stage1-scripts-tbody').innerHTML =
      rows.length > 0
        ? rows.join('')
        : '<tr><td colspan="3" class="empty-cell">No scripts, styles, or embedded frames discovered.</td></tr>';

    // Event handlers & dynamic sinks table
    const hRows = [];
    for (const h of handlers) {
      hRows.push(`
        <tr>
          <td class="code-text">&lt;${escapeHtml(h.tag || 'element')}&gt;</td>
          <td><span class="badge badge-danger">${escapeHtml(h.attr || 'on*')}</span></td>
          <td class="code-text">${escapeHtml(h.code || '')}</td>
        </tr>
      `);
    }
    if (res.usesEvalOrFunction) {
      hRows.push(`
        <tr>
          <td class="code-text">Inline Script</td>
          <td><span class="badge badge-danger">eval() / Function()</span></td>
          <td class="code-text">Dynamic code evaluation detected (requires unsafe-eval mitigation).</td>
        </tr>
      `);
    }
    for (const sink of dangerousSinks) {
      hRows.push(`
        <tr>
          <td class="code-text">DOM Sink</td>
          <td><span class="badge badge-danger">${escapeHtml(sink.sink || sink.type || 'DOM XSS Sink')}</span></td>
          <td class="code-text">${escapeHtml(sink.preview || sink.evidence || String(sink))}</td>
        </tr>
      `);
    }

    $('stage1-handlers-tbody').innerHTML =
      hRows.length > 0
        ? hRows.join('')
        : '<tr><td colspan="3" class="empty-cell">No unsafe inline event handlers or eval/DOM sinks detected.</td></tr>';

    // Raw headers
    const rawHeaders = crawl.rawHeaders || {};
    const headerLines = Object.entries(rawHeaders).map(
      ([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`
    );
    $('stage1-raw-headers').textContent =
      headerLines.length > 0 ? headerLines.join('\n') : '(No HTTP headers returned)';

    // Evidence log
    const evArr = Array.isArray(crawl.evidence) ? crawl.evidence : [];
    $('stage1-evidence-list').innerHTML =
      evArr.length > 0
        ? evArr
            .map((ev) => {
              const sev = String(ev.severity || 'INFO').toUpperCase();
              const cls =
                sev === 'CRITICAL' || sev === 'HIGH'
                  ? 'badge-danger'
                  : sev === 'WARN' || sev === 'WARNING' || sev === 'MEDIUM'
                    ? 'badge-warning'
                    : 'badge-info';
              return `
                <li class="evidence-item">
                  <span class="badge ${cls}">${escapeHtml(ev.code || sev)}</span>
                  <span>${escapeHtml(ev.message || JSON.stringify(ev))}</span>
                </li>
              `;
            })
            .join('')
        : '<li class="evidence-empty">Target crawled cleanly.</li>';
  }

  /* ---- Stage 2: Header Analysis ---- */
  async function runStage2Only() {
    hideGlobalAlert();
    if (!state.stages.crawlResult) {
      await runStage1Only();
      if (!state.stages.crawlResult) return;
    }
    setStageStatus(2, 'RUNNING');
    try {
      const data = await apiRequest('/api/engine/analyze-headers', {
        method: 'POST',
        body: {
          targetUrl: state.stages.crawlResult.targetUrl,
          crawlResult: state.stages.crawlResult,
        },
      });
      const headerAnalysis = data?.headerAnalysis || data;
      state.stages.headerAnalysis = headerAnalysis;
      renderStage2(headerAnalysis);
      showToast('Stage 2 (Header Analysis) completed.', 'success');
    } catch (_err) {
      setStageStatus(2, 'FAILED');
    }
  }

  function renderStage2(analysis) {
    if (!analysis) return;
    setStageStatus(2, analysis.status || 'COMPLETED');

    const findings = Array.isArray(analysis.findings) ? analysis.findings : [];
    const summary = analysis.summary || {
      totalRules: findings.length,
      passedRules: findings.filter((f) => f.passed).length,
      failedRules: findings.filter((f) => !f.passed).length,
      criticalCount: findings.filter((f) => !f.passed && f.severity === 'CRITICAL').length,
      highCount: findings.filter((f) => !f.passed && f.severity === 'HIGH').length,
    };

    $('s2-total-rules').textContent = String(summary.totalRules ?? findings.length);
    $('s2-passed-rules').textContent = String(summary.passedRules ?? 0);
    $('s2-failed-rules').textContent = String(summary.failedRules ?? 0);
    $('s2-critical-high').textContent = `${summary.criticalCount ?? 0} Crit / ${summary.highCount ?? 0} High`;
    $('s2-existing-csp').textContent = analysis.existingCspRaw || 'Absent (Missing)';

    $('stage2-findings-tbody').innerHTML =
      findings.length > 0
        ? findings
            .map((f) => {
              const sev = String(f.severity || 'MEDIUM').toUpperCase();
              const sevBadge =
                sev === 'CRITICAL' || sev === 'HIGH'
                  ? 'badge-danger'
                  : sev === 'MEDIUM'
                    ? 'badge-warning'
                    : 'badge-info';
              const verdictBadge = f.passed
                ? '<span class="badge badge-success">PASS</span>'
                : '<span class="badge badge-danger">FAIL</span>';

              return `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(f.ruleId)}</strong></td>
                  <td>
                    <strong>${escapeHtml(f.ruleName)}</strong>
                    <div class="section-Note" style="margin-top:2px;">${escapeHtml(f.category || '')}</div>
                  </td>
                  <td><span class="badge ${sevBadge}">${escapeHtml(sev)}</span></td>
                  <td>${verdictBadge}</td>
                  <td class="code-text">${escapeHtml(f.weight ?? 0)} pts</td>
                  <td>
                    <div>${escapeHtml(f.reason || '')}</div>
                    <code style="font-size:11px;color:var(--text-muted);">${escapeHtml(f.evidence || '')}</code>
                  </td>
                  <td>${escapeHtml(f.remediation || ' - ')}</td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="7" class="empty-cell">No rules evaluated.</td></tr>';
  }

  /* ---- Stage 3: CSP Builder (Cascades live to Stages 4, 5, 6) ---- */
  async function runStage3AndCascade() {
    hideGlobalAlert();
    if (!state.stages.crawlResult) {
      await runStage1Only();
      if (!state.stages.crawlResult) return;
    }
    if (!state.stages.headerAnalysis) {
      await runStage2Only();
    }

    setStageStatus(3, 'RUNNING');
    try {
      const options = getBuilderOptions();
      const data3 = await apiRequest('/api/engine/build-csp', {
        method: 'POST',
        body: {
          targetUrl: state.stages.crawlResult.targetUrl,
          crawlResult: state.stages.crawlResult,
          headerAnalysis: state.stages.headerAnalysis,
          options,
        },
      });
      const cspBuild = data3?.cspBuild || data3;
      state.stages.cspBuild = cspBuild;
      renderStage3(cspBuild);

      // Cascade to Stage 4, Stage 5, Stage 6
      await runStage4Only({ silentToast: true });
      await runStage5Only({ silentToast: true });
      await runStage6Only({ silentToast: true });

      showToast('Recalculated CSP policy, simulated violations, score, and export bundle.', 'success');
    } catch (_err) {
      setStageStatus(3, 'FAILED');
    }
  }

  function renderStage3(cspBuild) {
    if (!cspBuild) return;
    setStageStatus(3, cspBuild.status || 'COMPLETED');

    $('stage3-csp-output').textContent =
      cspBuild.cspHeaderString || "default-src 'self'; object-src 'none'";

    const directives = cspBuild.directives || {};
    const dirEntries = Object.entries(directives);
    $('stage3-directives-grid').innerHTML =
      dirEntries.length > 0
        ? dirEntries
            .map(([dir, vals]) => {
              const valStr = Array.isArray(vals) ? vals.join(' ') : String(vals);
              return `
                <div class="directive-card">
                  <span class="directive-name">${escapeHtml(dir)}</span>
                  <div class="directive-values">${escapeHtml(valStr)}</div>
                </div>
              `;
            })
            .join('')
        : '<div class="empty-cell">No directives generated.</div>';

    const companions = cspBuild.recommendedCompanionHeaders || {};
    const compEntries = Object.entries(companions);
    $('stage3-companion-tbody').innerHTML =
      compEntries.length > 0
        ? compEntries
            .map(
              ([hName, hVal]) => `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(hName)}</strong></td>
                  <td class="code-text">${escapeHtml(hVal)}</td>
                </tr>
              `
            )
            .join('')
        : '<tr><td colspan="2" class="empty-cell">None</td></tr>';

    const decisions = Array.isArray(cspBuild.decisions) ? cspBuild.decisions : [];
    $('stage3-decisions-tbody').innerHTML =
      decisions.length > 0
        ? decisions
            .map(
              (d) => `
                <tr>
                  <td class="code-text"><span class="badge badge-info">${escapeHtml(d.directive || 'policy')}</span></td>
                  <td>${escapeHtml(d.decision || '')}</td>
                  <td class="code-text">${escapeHtml(d.evidence || ' - ')}</td>
                </tr>
              `
            )
            .join('')
        : '<tr><td colspan="3" class="empty-cell">Least-privilege defaults applied.</td></tr>';
  }

  /* ---- Stage 4: Violation Collector & Live Browser Sandbox ---- */
  async function runStage4Only(opts = {}) {
    if (!state.stages.crawlResult || !state.stages.cspBuild) {
      if (!opts.silentToast) {
        showToast('Run Stages 1-3 or Full Pipeline first.', 'warning');
      }
      return;
    }

    setStageStatus(4, 'RUNNING');
    try {
      const data = await apiRequest('/api/engine/collect-violations', {
        method: 'POST',
        body: {
          runId: state.activeRunId,
          targetUrl: state.stages.crawlResult.targetUrl,
          crawlResult: state.stages.crawlResult,
          cspBuild: state.stages.cspBuild,
        },
      });
      const violationAnalysis = data?.violationAnalysis || data;
      state.stages.violationAnalysis = violationAnalysis;
      renderStage4(violationAnalysis);
      if (!opts.silentToast) {
        showToast('Stage 4 (Violation Collector) updated.', 'success');
      }
    } catch (_err) {
      setStageStatus(4, 'FAILED');
    }
  }

  function renderStage4(violationAnalysis) {
    if (!violationAnalysis) return;
    setStageStatus(4, violationAnalysis.status || 'COMPLETED');

    const violations = Array.isArray(violationAnalysis.violations)
      ? violationAnalysis.violations
      : [];
    const simCount = violations.filter((v) => (v.source || 'simulation') === 'simulation').length;
    const browserCount = violations.filter((v) => v.source === 'browser').length;

    $('s4-total-violations').textContent = String(
      violationAnalysis.totalViolations ?? violations.length
    );
    $('s4-sim-violations').textContent = String(simCount);
    $('s4-browser-violations').textContent = String(browserCount);

    $('stage4-violations-tbody').innerHTML =
      violations.length > 0
        ? violations
            .map((v) => {
              const isBrowser = v.source === 'browser';
              return `
                <tr>
                  <td>
                    <span class="badge ${isBrowser ? 'badge-info' : 'badge-warning'}">
                      ${escapeHtml(v.source || 'simulation')}
                    </span>
                  </td>
                  <td class="code-text"><strong>${escapeHtml(v.violatedDirective || v.violated_directive || 'script-src')}</strong></td>
                  <td class="code-text">${escapeHtml(v.effectiveDirective || v.violatedDirective || 'script-src')}</td>
                  <td class="code-text">${escapeHtml(v.blockedUri || v.blocked_uri || 'inline')}</td>
                  <td><span class="badge badge-danger">${escapeHtml(v.disposition || 'enforce')}</span></td>
                  <td class="code-text">${escapeHtml(v.sample || ' - ')}</td>
                  <td>${escapeHtml(v.explanation || 'Blocked by synthesized least-privilege Content-Security-Policy.')}</td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="7" class="empty-cell">0 policy violations detected - all page resources comply with the synthesized CSP.</td></tr>';
  }

  function launchLiveBrowserSandbox() {
    const container = $('live-sandbox-container');
    const iframe = $('csp-sandbox-iframe');
    if (!container || !iframe) return;

    container.classList.remove('hidden');
    const runParam = state.activeRunId ? `runId=${encodeURIComponent(state.activeRunId)}&` : '';
    iframe.src = `/fixtures/sandbox-frame?${runParam}ts=${Date.now()}`;
    showToast('Launched Live Browser CSP Sandbox (/fixtures/sandbox-frame). Collecting telemetry...', 'info');

    setTimeout(() => {
      refreshStoredViolationReports();
    }, 900);
  }

  function closeLiveBrowserSandbox() {
    const container = $('live-sandbox-container');
    const iframe = $('csp-sandbox-iframe');
    if (iframe) iframe.src = 'about:blank';
    if (container) container.classList.add('hidden');
  }

  async function refreshStoredViolationReports() {
    if (state.stages.crawlResult && state.stages.cspBuild) {
      await runStage4Only({ silentToast: true });
    }
    if (state.activeRunId) {
      try {
        const runData = await apiRequest(`/api/reports/runs/${encodeURIComponent(state.activeRunId)}`, {
          method: 'GET',
          silentAlert: true,
        });
        const storedReports = Array.isArray(runData?.violationReports)
          ? runData.violationReports
          : [];
        if (storedReports.length > 0) {
          const currentViolations = Array.isArray(state.stages.violationAnalysis?.violations)
            ? [...state.stages.violationAnalysis.violations]
            : [];
          for (const sr of storedReports) {
            const exists = currentViolations.some(
              (v) =>
                v.source === 'browser' &&
                (v.blockedUri || v.blocked_uri) === (sr.blocked_uri || sr.blockedUri) &&
                (v.violatedDirective || v.violated_directive) ===
                  (sr.violated_directive || sr.violatedDirective)
            );
            if (!exists) {
              currentViolations.unshift({
                source: sr.source || 'browser',
                violatedDirective: sr.violated_directive || sr.violatedDirective || 'script-src',
                effectiveDirective: sr.violated_directive || sr.violatedDirective || 'script-src',
                blockedUri: sr.blocked_uri || sr.blockedUri || 'inline',
                disposition: sr.disposition || 'report',
                sample: 'W3C Browser SecurityPolicyViolationEvent',
                explanation: 'Real browser CSP telemetry captured via POST /api/engine/csp-report.',
              });
            }
          }
          state.stages.violationAnalysis = {
            stage: 'FR-4_VIOLATION_COLLECTOR',
            status: 'COMPLETED',
            totalViolations: currentViolations.length,
            violations: currentViolations,
          };
          renderStage4(state.stages.violationAnalysis);
        }
      } catch (_err) {
        // Ignore if run isn't persisted yet
      }
    }
    showToast('Refreshed violation reports.', 'success');
  }

  /* ---- Stage 5: Before/After Posture Score ---- */
  async function runStage5Only(opts = {}) {
    if (!state.stages.crawlResult || !state.stages.headerAnalysis || !state.stages.cspBuild) {
      if (!opts.silentToast) {
        showToast('Run Stages 1-3 first to calculate Before/After score.', 'warning');
      }
      return;
    }

    setStageStatus(5, 'RUNNING');
    try {
      const data = await apiRequest('/api/engine/score', {
        method: 'POST',
        body: {
          targetUrl: state.stages.crawlResult.targetUrl,
          crawlResult: state.stages.crawlResult,
          headerAnalysis: state.stages.headerAnalysis,
          cspBuild: state.stages.cspBuild,
          violationAnalysis: state.stages.violationAnalysis,
        },
      });
      const scoreComparison = data?.scoreComparison || data;
      state.stages.scoreComparison = scoreComparison;
      renderStage5(scoreComparison);
      if (!opts.silentToast) {
        showToast('Stage 5 (Before/After Score) updated.', 'success');
      }
    } catch (_err) {
      setStageStatus(5, 'FAILED');
    }
  }

  function renderStage5(scoreComp) {
    if (!scoreComp) return;
    setStageStatus(5, scoreComp.status || 'COMPLETED');

    const before = scoreComp.before || { score: 0, grade: 'F', status: 'FAIL', breakdown: [] };
    const after = scoreComp.after || { score: 0, grade: 'A', status: 'PASS', breakdown: [] };
    const delta = Number(scoreComp.delta ?? after.score - before.score);
    const threshold = scoreComp.passThreshold ?? 75;

    $('score-before-val').textContent = String(before.score ?? 0);
    $('score-after-val').textContent = String(after.score ?? 0);

    const bGrade = String(before.grade || 'F').toUpperCase();
    const aGrade = String(after.grade || 'A').toUpperCase();
    const bGradeEl = $('score-before-grade');
    const aGradeEl = $('score-after-grade');
    bGradeEl.textContent = bGrade;
    bGradeEl.className = `grade-circle grade-${bGrade.toLowerCase()}`;
    aGradeEl.textContent = aGrade;
    aGradeEl.className = `grade-circle grade-${aGrade.toLowerCase()}`;

    const bStatusEl = $('score-before-status');
    bStatusEl.textContent = before.status || (before.score >= threshold ? 'PASS' : 'FAIL');
    bStatusEl.className = `badge ${before.score >= threshold ? 'badge-success' : 'badge-danger'}`;

    const aStatusEl = $('score-after-status');
    aStatusEl.textContent = after.status || (after.score >= threshold ? 'PASS' : 'FAIL');
    aStatusEl.className = `badge ${after.score >= threshold ? 'badge-success' : 'badge-danger'}`;

    $('score-before-bar').style.width = `${Math.min(Math.max(before.score || 0, 0), 100)}%`;
    $('score-after-bar').style.width = `${Math.min(Math.max(after.score || 0, 0), 100)}%`;

    $('score-delta-badge').textContent = `${delta >= 0 ? '+' : ''}${delta} pts`;
    $('score-threshold-label').textContent = `${threshold} / 100`;
    $('score-explanation-text').textContent =
      scoreComp.explanation ||
      `Hardened headers change security posture from ${before.score}/100 (${bGrade}) to ${after.score}/100 (${aGrade}).`;

    // Breakdown table
    const beforeList = Array.isArray(before.breakdown) ? before.breakdown : [];
    const afterList = Array.isArray(after.breakdown) ? after.breakdown : [];
    const afterMap = new Map(afterList.map((item) => [item.ruleId, item]));
    const sourceItems = beforeList.length > 0 ? beforeList : afterList;

    $('stage5-breakdown-tbody').innerHTML =
      sourceItems.length > 0
        ? sourceItems
            .map((bItem) => {
              const aItem = afterMap.get(bItem.ruleId) || {};
              const weight = bItem.weight ?? aItem.weight ?? 0;
              const bPass = Boolean(bItem.passed);
              const aPass = Boolean(aItem.passed ?? true);
              const netGain = (aPass ? weight : 0) - (bPass ? weight : 0);

              return `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(bItem.ruleId)}</strong></td>
                  <td>${escapeHtml(bItem.ruleName || aItem.ruleName || bItem.ruleId)}</td>
                  <td class="code-text">${escapeHtml(weight)} pts</td>
                  <td>
                    <span class="badge ${bPass ? 'badge-success' : 'badge-danger'}">
                      ${bPass ? 'PASS' : 'FAIL'} (${bPass ? weight : 0}/${weight})
                    </span>
                  </td>
                  <td>
                    <span class="badge ${aPass ? 'badge-success' : 'badge-danger'}">
                      ${aPass ? 'PASS' : 'FAIL'} (${aPass ? weight : 0}/${weight})
                    </span>
                  </td>
                  <td class="code-text ${netGain > 0 ? 'text-emerald' : ''}">
                    <strong>${netGain > 0 ? `+${netGain} pts` : '0 pts'}</strong>
                  </td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="6" class="empty-cell">Detailed breakdown not available.</td></tr>';
  }

  /* ---- Stage 6: Downloadable Configuration (.txt & .json) ---- */
  async function runStage6Only(opts = {}) {
    if (!state.stages.cspBuild) {
      if (!opts.silentToast) {
        showToast('Run Stages 1-5 first to generate the export bundle.', 'warning');
      }
      return;
    }

    setStageStatus(6, 'RUNNING');
    try {
      const data = await apiRequest('/api/engine/export', {
        method: 'POST',
        body: {
          runId: state.activeRunId,
          targetUrl: state.stages.crawlResult?.targetUrl,
          crawlResult: state.stages.crawlResult,
          headerAnalysis: state.stages.headerAnalysis,
          cspBuild: state.stages.cspBuild,
          violationAnalysis: state.stages.violationAnalysis,
          scoreComparison: state.stages.scoreComparison,
        },
      });
      const exportBundle = data?.exportBundle || data;
      state.stages.exportBundle = exportBundle;
      renderStage6(exportBundle);
      if (!opts.silentToast) {
        showToast('Stage 6 (Downloadable Configuration) generated.', 'success');
      }
    } catch (_err) {
      setStageStatus(6, 'FAILED');
    }
  }

  function renderStage6(exportBundle) {
    if (!exportBundle) return;
    setStageStatus(6, exportBundle.status || 'COMPLETED');

    $('stage6-raw-headers-output').textContent =
      exportBundle.rawHttpHeaderBlock || 'No header block generated.';
    $('stage6-json-report-output').textContent = exportBundle.sanitizedJsonReport
      ? JSON.stringify(exportBundle.sanitizedJsonReport, null, 2)
      : '{}';
  }

  async function downloadRunArtifact(runId, type) {
    hideGlobalAlert();
    const targetRunId = runId || state.activeRunId;

    if (targetRunId) {
      const endpoint =
        type === 'headers'
          ? `/api/reports/runs/${encodeURIComponent(targetRunId)}/export-headers`
          : `/api/reports/runs/${encodeURIComponent(targetRunId)}/export-json`;

      try {
        const response = await fetch(endpoint, {
          method: 'GET',
          credentials: 'same-origin',
        });

        if (!response.ok) {
          let errPayload = null;
          try {
            errPayload = await response.json();
          } catch (_e) {
            errPayload = null;
          }
          const code = errPayload?.error?.code || `HTTP_${response.status}`;
          const msg =
            errPayload?.error?.message ||
            'Export denied by role-based access control policy.';
          showGlobalAlert(code, msg);
          showToast(`${code}: ${msg}`, 'error');
          return;
        }

        const blob = await response.blob();
        const ext = type === 'headers' ? 'txt' : 'json';
        const prefix = type === 'headers' ? 'csp-headers' : 'csp-report';
        triggerBlobDownload(blob, `${prefix}-${String(targetRunId).slice(0, 12)}.${ext}`);
        showToast(`Downloaded ${ext.toUpperCase()} artifact for run ${String(targetRunId).slice(0, 8)}.`, 'success');
      } catch (err) {
        showToast(`Download failed: ${err.message}`, 'error');
      }
      return;
    }

    // Fallback if interactive stages were run without a saved runId
    if (state.user?.role === 'viewer') {
      showGlobalAlert(
        'ERR_AUTH_FORBIDDEN',
        'Role viewer is not permitted to export deployment configuration bundles.'
      );
      showToast('ERR_AUTH_FORBIDDEN: Export restricted to Operator and Admin roles.', 'error');
      return;
    }

    if (type === 'headers') {
      const text = $('stage6-raw-headers-output')?.textContent || '';
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      triggerBlobDownload(blob, 'csp-headers-interactive.txt');
      showToast('Downloaded Raw HTTP Response Header Block (.txt).', 'success');
    } else {
      const text = $('stage6-json-report-output')?.textContent || '{}';
      const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
      triggerBlobDownload(blob, 'csp-report-interactive.json');
      showToast('Downloaded Sanitized JSON Evidence Report (.json).', 'success');
    }
  }

  function triggerBlobDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  /* ========================================================================
     TAB 2: MANDATORY EVALUATION SUITE (T1 - T6)
     ======================================================================== */
  async function runEvaluationSuite() {
    hideGlobalAlert();
    const btn = $('run-eval-suite-btn');
    btn.disabled = true;
    btn.textContent = 'Running Mandatory Evaluation Suite (T1-T6)...';

    try {
      const data = await apiRequest('/api/engine/evaluate-suite', {
        method: 'POST',
        body: {},
      });
      renderEvaluationSuite(data);
      showToast('Mandatory Evaluation Suite (Baseline + T1-T6) completed.', 'success');
    } catch (_err) {
      // Alert handled by apiRequest
    } finally {
      btn.disabled = false;
      btn.textContent = 'Run Mandatory Evaluation Suite (T1-T6)';
    }
  }

  function renderEvaluationSuite(data) {
    const metrics = data?.metrics || data?.summary || {};
    const cases = Array.isArray(data?.results)
      ? data.results
      : Array.isArray(data?.cases)
        ? data.cases
        : [];

    const passedCount = cases.filter((c) => c.passed).length;
    const totalCount = cases.length || 1;
    const passRate =
      metrics.passRate !== undefined
        ? `${metrics.passRate}%`
        : `${Math.round((passedCount / totalCount) * 100)}% (${passedCount}/${cases.length})`;

    $('eval-kpi-pass-rate').textContent = passRate;
    $('eval-kpi-coverage').textContent = `${metrics.ruleCoveragePct ?? metrics.ruleCoverage ?? 100}%`;
    $('eval-kpi-fpr').textContent = `${metrics.falsePositiveRatePct ?? metrics.falsePositiveRate ?? 0}%`;
    $('eval-kpi-fnr').textContent = `${metrics.falseNegativeRatePct ?? metrics.falseNegativeRate ?? 0}%`;
    $('eval-kpi-latency').textContent = `${metrics.meanLatencyMs ?? metrics.avgLatencyMs ?? ' - '} ms`;

    $('eval-results-tbody').innerHTML =
      cases.length > 0
        ? cases
            .map((c) => {
              const passed = Boolean(c.passed);
              return `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(c.testId || c.id)}</strong></td>
                  <td>
                    <strong>${escapeHtml(c.name || c.title || c.testId)}</strong>
                    <div class="code-text" style="font-size:11px;color:var(--accent-cyan);">${escapeHtml(c.input || c.targetUrl || '')}</div>
                  </td>
                  <td>${escapeHtml(c.expected || c.expectedResult || '')}</td>
                  <td>${escapeHtml(c.actual || c.actualResult || '')}</td>
                  <td class="code-text" style="font-size:11.5px;">${escapeHtml(
                    Array.isArray(c.evidence) ? c.evidence.join('; ') : c.evidence || ''
                  )}</td>
                  <td class="code-text">${escapeHtml(c.latencyMs ?? 0)} ms</td>
                  <td>
                    <span class="badge ${passed ? 'badge-success' : 'badge-danger'}">
                      ${passed ? 'PASS' : 'FAIL'}
                    </span>
                  </td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="7" class="empty-cell">No evaluation cases returned.</td></tr>';
  }

  /* ========================================================================
     TAB 3: WORKFLOW RUN HISTORY & SIDE-BY-SIDE COMPARISON
     ======================================================================== */
  async function loadHistoryRuns(opts = {}) {
    const status = $('history-status-filter')?.value || '';
    const search = $('history-search-input')?.value.trim() || '';

    const params = new URLSearchParams();
    params.set('limit', '50');
    if (status) params.set('status', status);
    if (search) params.set('search', search);

    try {
      const data = await apiRequest(`/api/reports/runs?${params.toString()}`, {
        method: 'GET',
        silentAlert: Boolean(opts.silent),
      });
      const runs = Array.isArray(data?.runs) ? data.runs : [];
      state.historyRuns = runs;
      renderHistoryTable(runs);
      populateComparisonSelects(runs);
    } catch (_err) {
      // Handled by apiRequest
    }
  }

  function renderHistoryTable(runs) {
    const tbody = $('history-runs-tbody');
    if (!tbody) return;

    if (!runs.length) {
      tbody.innerHTML =
        '<tr><td colspan="9" class="empty-cell">No saved workflow runs match the current filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = runs
      .map((r) => {
        const status = String(r.status || 'COMPLETED').toUpperCase();
        const statusCls =
          status === 'COMPLETED'
            ? 'badge-success'
            : status === 'REJECTED'
              ? 'badge-danger'
              : 'badge-warning';
        const before = Number(r.beforeScore ?? r.before_score ?? 0);
        const after = Number(r.afterScore ?? r.after_score ?? 0);
        const delta = after - before;

        return `
          <tr>
            <td class="code-text" title="${escapeHtml(r.id)}">${escapeHtml(String(r.id).slice(0, 8))}</td>
            <td class="code-text">${escapeHtml(formatTimestamp(r.createdAt || r.created_at))}</td>
            <td><strong>${escapeHtml(r.username || 'operator')}</strong></td>
            <td class="code-text">${escapeHtml(r.targetUrl || r.target_url)}</td>
            <td><span class="badge ${statusCls}">${escapeHtml(status)}</span></td>
            <td class="code-text">
              ${before} &rarr; <strong>${after}</strong>
              <span class="${delta >= 0 ? 'text-emerald' : 'text-rose'}">(${delta >= 0 ? '+' : ''}${delta})</span>
            </td>
            <td class="code-text">v${escapeHtml(r.engineVersion || r.engine_version || '1.0.0')}</td>
            <td class="code-text">${escapeHtml(r.latencyMs ?? r.latency_ms ?? 0)} ms</td>
            <td>
              <div class="btn-group">
                <button type="button" class="btn btn-secondary btn-xs" data-action="load-run" data-run-id="${escapeHtml(r.id)}">Load</button>
                <button type="button" class="btn btn-secondary btn-xs" data-action="set-run-a" data-run-id="${escapeHtml(r.id)}">Run A</button>
                <button type="button" class="btn btn-secondary btn-xs" data-action="set-run-b" data-run-id="${escapeHtml(r.id)}">Run B</button>
                <button type="button" class="btn btn-primary btn-xs" data-action="export-txt" data-run-id="${escapeHtml(r.id)}">.txt</button>
                <button type="button" class="btn btn-primary btn-xs" data-action="export-json" data-run-id="${escapeHtml(r.id)}">.json</button>
              </div>
            </td>
          </tr>
        `;
      })
      .join('');
  }

  function populateComparisonSelects(runs) {
    const selA = $('compare-run-a-select');
    const selB = $('compare-run-b-select');
    if (!selA || !selB) return;

    const prevA = selA.value;
    const prevB = selB.value;

    const optionsHtml = runs
      .map((r) => {
        const shortId = String(r.id).slice(0, 8);
        const before = r.beforeScore ?? r.before_score ?? 0;
        const after = r.afterScore ?? r.after_score ?? 0;
        const target = r.targetUrl || r.target_url || '';
        return `<option value="${escapeHtml(r.id)}">[${escapeHtml(shortId)}] ${escapeHtml(target)} (${before} -> ${after})</option>`;
      })
      .join('');

    selA.innerHTML = '<option value="">Select Run A...</option>' + optionsHtml;
    selB.innerHTML = '<option value="">Select Run B...</option>' + optionsHtml;

    if (prevA && runs.some((r) => r.id === prevA)) selA.value = prevA;
    else if (runs[1]) selA.value = runs[1].id;
    else if (runs[0]) selA.value = runs[0].id;

    if (prevB && runs.some((r) => r.id === prevB)) selB.value = prevB;
    else if (runs[0]) selB.value = runs[0].id;
  }

  async function loadRunIntoWorkbench(runId) {
    hideGlobalAlert();
    try {
      const data = await apiRequest(`/api/reports/runs/${encodeURIComponent(runId)}`, {
        method: 'GET',
      });
      const run = data?.run || data;
      if (!run) return;

      const stages = extractStagesFromPayload(run);
      state.stages = stages;
      updateRunMetaHeader(run.id, run.latencyMs ?? run.latency_ms ?? 0);

      const targetUrl = run.targetUrl || run.target_url || '';
      if (targetUrl) {
        $('target-url-input').value = targetUrl;
        $('header-active-target').textContent = targetUrl;
      }

      renderAllStages(stages);
      switchTab('workbench');
      showToast(`Loaded workflow run ${String(run.id).slice(0, 8)} into Workbench.`, 'success');
    } catch (_err) {
      // Handled by apiRequest
    }
  }

  async function compareSelectedRuns() {
    hideGlobalAlert();
    const runA = $('compare-run-a-select')?.value;
    const runB = $('compare-run-b-select')?.value;

    if (!runA || !runB) {
      showToast('Select both Run A and Run B to compare.', 'warning');
      return;
    }

    try {
      const data = await apiRequest(
        `/api/reports/compare?runA=${encodeURIComponent(runA)}&runB=${encodeURIComponent(runB)}`,
        { method: 'GET' }
      );
      const cmp = data?.comparison || data;
      renderComparisonResult(cmp);
      showToast('Generated side-by-side run comparison.', 'success');
    } catch (_err) {
      // Handled by apiRequest
    }
  }

  function renderComparisonResult(cmp) {
    if (!cmp) return;
    const panel = $('comparison-results-panel');
    panel.classList.remove('hidden');

    const rA = cmp.runA || {};
    const rB = cmp.runB || {};
    const sDelta = cmp.scoreDelta || {};

    $('cmp-run-a-scores').textContent = `${rA.beforeScore ?? 0} -> ${rA.afterScore ?? 0} (${rA.afterGrade || ' - '})`;
    $('cmp-run-b-scores').textContent = `${rB.beforeScore ?? 0} -> ${rB.afterScore ?? 0} (${rB.afterGrade || ' - '})`;

    const afterDiff = Number(sDelta.afterScoreDiff ?? 0);
    $('cmp-after-diff').textContent = `${afterDiff >= 0 ? '+' : ''}${afterDiff} pts`;
    $('cmp-thresholds').textContent = `${rA.passThreshold ?? 75} / ${rB.passThreshold ?? 75}`;

    $('cmp-run-a-id').textContent = `${String(rA.id || '').slice(0, 8)} (${rA.targetUrl || ''})`;
    $('cmp-run-b-id').textContent = `${String(rB.id || '').slice(0, 8)} (${rB.targetUrl || ''})`;
    $('cmp-csp-a').textContent = cmp.cspDiff?.runACsp || '(No CSP generated)';
    $('cmp-csp-b').textContent = cmp.cspDiff?.runBCsp || '(No CSP generated)';

    const dirChanges = Array.isArray(cmp.cspDiff?.directiveChanges)
      ? cmp.cspDiff.directiveChanges
      : [];
    $('compare-directives-tbody').innerHTML =
      dirChanges.length > 0
        ? dirChanges
            .map((d) => {
              const badgeCls =
                d.status === 'UNCHANGED'
                  ? 'badge-neutral'
                  : d.status === 'ADDED'
                    ? 'badge-success'
                    : d.status === 'REMOVED'
                      ? 'badge-danger'
                      : 'badge-warning';
              return `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(d.directive)}</strong></td>
                  <td class="code-text">${escapeHtml(d.runAString || (d.runAValues || []).join(' '))}</td>
                  <td class="code-text">${escapeHtml(d.runBString || (d.runBValues || []).join(' '))}</td>
                  <td><span class="badge ${badgeCls}">${escapeHtml(d.status)}</span></td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="4" class="empty-cell">No directive differences.</td></tr>';

    const ruleDiffs = Array.isArray(cmp.ruleFindingsDiff) ? cmp.ruleFindingsDiff : [];
    $('compare-rules-tbody').innerHTML =
      ruleDiffs.length > 0
        ? ruleDiffs
            .map((rf) => {
              const aLabel = rf.runAPassed === null ? 'N/A' : rf.runAPassed ? 'PASS' : 'FAIL';
              const bLabel = rf.runBPassed === null ? 'N/A' : rf.runBPassed ? 'PASS' : 'FAIL';
              return `
                <tr>
                  <td class="code-text"><strong>${escapeHtml(rf.ruleId)}</strong></td>
                  <td>${escapeHtml(rf.ruleName)}</td>
                  <td><span class="badge badge-neutral">${escapeHtml(rf.severity)}</span></td>
                  <td class="code-text">${escapeHtml(aLabel)} (${escapeHtml(rf.runAWeight ?? 0)} pts)</td>
                  <td class="code-text">${escapeHtml(bLabel)} (${escapeHtml(rf.runBWeight ?? 0)} pts)</td>
                  <td>
                    <span class="badge ${rf.changed ? 'badge-warning' : 'badge-neutral'}">
                      ${rf.changed ? 'CHANGED' : 'IDENTICAL'}
                    </span>
                  </td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="6" class="empty-cell">No rule differences found.</td></tr>';
  }

  /* ========================================================================
     TAB 4: ADMIN CONFIGURATION & APPEND-ONLY AUDIT LOG CONSOLE
     ======================================================================== */
  async function loadAdminConsoleData() {
    await Promise.all([loadAdminConfig({ silent: true }), loadAuditLogs({ silent: true })]);
  }

  async function loadAdminConfig(opts = {}) {
    try {
      const data = await apiRequest('/api/admin/config', {
        method: 'GET',
        silentAlert: Boolean(opts.silent),
      });
      const cfg = data?.config || data;
      if (cfg) {
        state.adminConfig = cfg;
        renderAdminConfig(cfg);
      }
    } catch (err) {
      const tbody = $('admin-rules-tbody');
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">${escapeHtml(err.code || 'ERR_AUTH_FORBIDDEN')}: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  }

  function renderAdminConfig(cfg) {
    const allowlist = Array.isArray(cfg.allowlist) ? cfg.allowlist.join(', ') : 'localhost, 127.0.0.1';
    $('admin-allowlist-input').value = allowlist;
    $('admin-pass-threshold-input').value = String(cfg.passScoreThreshold ?? 75);
    $('admin-warning-threshold-input').value = String(cfg.criticalWarningThreshold ?? 50);

    const rulesObj = cfg.rules || {};
    const rulesList = Array.isArray(rulesObj) ? rulesObj : Object.values(rulesObj);

    $('admin-rules-tbody').innerHTML =
      rulesList.length > 0
        ? rulesList
            .map((r) => {
              const ruleId = r.id || r.ruleId;
              const enabled = r.enabled !== false;
              return `
                <tr data-rule-row="${escapeHtml(ruleId)}">
                  <td>
                    <input
                      type="checkbox"
                      class="admin-rule-enabled"
                      data-rule-id="${escapeHtml(ruleId)}"
                      ${enabled ? 'checked' : ''}
                    />
                  </td>
                  <td class="code-text"><strong>${escapeHtml(ruleId)}</strong></td>
                  <td>
                    <strong>${escapeHtml(r.name || ruleId)}</strong>
                    <div class="section-Note" style="margin-top:2px;">${escapeHtml(r.description || '')}</div>
                  </td>
                  <td>${escapeHtml(r.category || 'Security')}</td>
                  <td><span class="badge badge-neutral">${escapeHtml(r.severity || 'HIGH')}</span></td>
                  <td>
                    <input
                      type="number"
                      class="weight-input admin-rule-weight"
                      data-rule-id="${escapeHtml(ruleId)}"
                      min="0"
                      max="100"
                      value="${escapeHtml(r.weight ?? 10)}"
                    />
                  </td>
                </tr>
              `;
            })
            .join('')
        : '<tr><td colspan="6" class="empty-cell">No rules found in configuration.</td></tr>';
  }

  function collectDraftAdminConfig() {
    const allowlist = ($('admin-allowlist-input')?.value || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const passScoreThreshold = Number($('admin-pass-threshold-input')?.value ?? 75);
    const criticalWarningThreshold = Number($('admin-warning-threshold-input')?.value ?? 50);

    const baseRules = state.adminConfig?.rules
      ? JSON.parse(JSON.stringify(state.adminConfig.rules))
      : {};

    const checkboxes = document.querySelectorAll('.admin-rule-enabled');
    checkboxes.forEach((cb) => {
      const id = cb.getAttribute('data-rule-id');
      if (id) {
        if (!baseRules[id]) baseRules[id] = { id };
        baseRules[id].enabled = Boolean(cb.checked);
      }
    });

    const weightInputs = document.querySelectorAll('.admin-rule-weight');
    weightInputs.forEach((inp) => {
      const id = inp.getAttribute('data-rule-id');
      if (id) {
        if (!baseRules[id]) baseRules[id] = { id };
        baseRules[id].weight = Number(inp.value ?? 10);
      }
    });

    return {
      allowlist,
      passScoreThreshold,
      criticalWarningThreshold,
      rules: baseRules,
    };
  }

  function openAdminSaveConfirmation() {
    const draft = collectDraftAdminConfig();
    const enabledCount = Object.values(draft.rules).filter((r) => r.enabled !== false).length;

    $('confirm-modal-summary').textContent = JSON.stringify(
      {
        allowlist: draft.allowlist,
        passScoreThreshold: draft.passScoreThreshold,
        criticalWarningThreshold: draft.criticalWarningThreshold,
        enabledRulesCount: `${enabledCount} / ${Object.keys(draft.rules).length}`,
      },
      null,
      2
    );

    state.pendingConfirmAction = async () => {
      const data = await apiRequest('/api/admin/config', {
        method: 'PUT',
        body: draft,
      });
      const updated = data?.config || data;
      state.adminConfig = updated;
      renderAdminConfig(updated);
      showToast('System configuration updated and logged to audit trail.', 'success');
      await loadAuditLogs({ silent: true });
    };

    $('confirm-modal').classList.remove('hidden');
  }

  async function resetAdminConfigToDefaults() {
    hideGlobalAlert();
    try {
      const data = await apiRequest('/api/admin/config/reset', {
        method: 'POST',
        body: {},
      });
      const cfg = data?.config || data;
      state.adminConfig = cfg;
      renderAdminConfig(cfg);
      showToast('System configuration reset to factory defaults.', 'success');
      await loadAuditLogs({ silent: true });
    } catch (_err) {
      // Handled by apiRequest
    }
  }

  async function loadAuditLogs(opts = {}) {
    const outcome = $('audit-outcome-filter')?.value || '';
    const action = $('audit-action-filter')?.value.trim() || '';
    const actor = $('audit-actor-filter')?.value.trim() || '';

    const params = new URLSearchParams();
    params.set('limit', '100');
    if (outcome) params.set('outcome', outcome);
    if (action) params.set('action', action);
    if (actor) params.set('actor', actor);

    try {
      const data = await apiRequest(`/api/audit/logs?${params.toString()}`, {
        method: 'GET',
        silentAlert: Boolean(opts.silent),
      });
      const logs = Array.isArray(data?.logs) ? data.logs : Array.isArray(data) ? data : [];
      renderAuditLogsTable(logs);
    } catch (err) {
      const tbody = $('audit-logs-tbody');
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">${escapeHtml(err.code || 'ERR_AUTH_FORBIDDEN')}: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  }

  function renderAuditLogsTable(logs) {
    const tbody = $('audit-logs-tbody');
    if (!tbody) return;

    if (!logs.length) {
      tbody.innerHTML =
        '<tr><td colspan="8" class="empty-cell">No audit log entries match the selected filters.</td></tr>';
      return;
    }

    tbody.innerHTML = logs
      .map((log) => {
        const outcome = String(log.outcome || 'SUCCESS').toUpperCase();
        const badgeCls =
          outcome === 'SUCCESS'
            ? 'badge-success'
            : outcome === 'DENIED'
              ? 'badge-danger'
              : 'badge-warning';

        let detailsStr = '';
        if (typeof log.details === 'object' && log.details !== null) {
          detailsStr = JSON.stringify(log.details);
        } else if (typeof log.details_json === 'string') {
          detailsStr = log.details_json;
        } else {
          detailsStr = String(log.details || '');
        }

        return `
          <tr>
            <td class="code-text">#${escapeHtml(log.id)}</td>
            <td class="code-text">${escapeHtml(formatTimestamp(log.timestamp))}</td>
            <td>
              <strong>${escapeHtml(log.actor_username || log.actorUsername || 'anonymous')}</strong>
              <span class="badge badge-neutral">${escapeHtml(log.actor_role || log.actorRole || 'none')}</span>
            </td>
            <td class="code-text"><strong>${escapeHtml(log.action)}</strong></td>
            <td class="code-text">${escapeHtml(log.resource)}</td>
            <td><span class="badge ${badgeCls}">${escapeHtml(outcome)}</span></td>
            <td class="code-text">${escapeHtml(log.ip_address || log.ipAddress || '127.0.0.1')}</td>
            <td class="code-text" style="font-size:11px;max-width:340px;word-break:break-all;">${escapeHtml(detailsStr)}</td>
          </tr>
        `;
      })
      .join('');
  }

  /* ========================================================================
     EVENT WIRING
     ======================================================================== */
  function bindEvents() {
    // Login & Logout
    $('login-form')?.addEventListener('submit', handleLoginSubmit);
    $('logout-btn')?.addEventListener('click', handleLogout);
    $('global-alert-close')?.addEventListener('click', hideGlobalAlert);

    // Navigation Tabs
    document.querySelectorAll('.nav-tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        if (tab) switchTab(tab);
      });
    });

    // Target Preset Selector
    $('target-preset-select')?.addEventListener('change', (e) => {
      const fullUrl = resolveTargetUrl(e.target.value);
      $('target-url-input').value = fullUrl;
      $('header-active-target').textContent = fullUrl;
    });

    $('target-url-input')?.addEventListener('input', (e) => {
      $('header-active-target').textContent = e.target.value.trim() || ' - ';
    });

    // Workbench Execution Buttons
    $('run-pipeline-btn')?.addEventListener('click', runFullPipeline);
    $('run-step1-top-btn')?.addEventListener('click', runStage1Only);
    $('run-stage1-btn')?.addEventListener('click', runStage1Only);
    $('run-stage2-btn')?.addEventListener('click', runStage2Only);
    $('run-stage3-btn')?.addEventListener('click', runStage3AndCascade);
    $('run-stage4-btn')?.addEventListener('click', () => runStage4Only());
    $('run-stage5-btn')?.addEventListener('click', () => runStage5Only());
    $('run-stage6-btn')?.addEventListener('click', () => runStage6Only());

    // Live interactive CSP Builder controls
    ['csp-mode-select', 'csp-allow-hashes-toggle', 'csp-allow-framing-toggle', 'csp-include-report-toggle'].forEach(
      (id) => {
        $(id)?.addEventListener('change', () => {
          if (state.stages.crawlResult) {
            runStage3AndCascade();
          }
        });
      }
    );

    // Stage 4 Live Browser CSP Sandbox
    $('launch-sandbox-btn')?.addEventListener('click', launchLiveBrowserSandbox);
    $('close-sandbox-btn')?.addEventListener('click', closeLiveBrowserSandbox);
    $('refresh-violations-btn')?.addEventListener('click', refreshStoredViolationReports);

    // Copy & Download Actions
    $('copy-csp-btn')?.addEventListener('click', () => {
      copyTextToClipboard($('stage3-csp-output')?.textContent || '', 'Content-Security-Policy');
    });
    $('copy-raw-headers-btn')?.addEventListener('click', () => {
      copyTextToClipboard($('stage6-raw-headers-output')?.textContent || '', 'Raw HTTP Header Block');
    });
    $('copy-json-report-btn')?.addEventListener('click', () => {
      copyTextToClipboard($('stage6-json-report-output')?.textContent || '', 'Sanitized JSON Report');
    });
    $('download-headers-btn')?.addEventListener('click', () => downloadRunArtifact(null, 'headers'));
    $('download-json-btn')?.addEventListener('click', () => downloadRunArtifact(null, 'json'));

    // Tab 2: Evaluation Suite
    $('run-eval-suite-btn')?.addEventListener('click', runEvaluationSuite);

    // Tab 3: History & Comparison
    $('refresh-history-btn')?.addEventListener('click', () => loadHistoryRuns());
    $('history-status-filter')?.addEventListener('change', () => loadHistoryRuns());
    $('history-search-input')?.addEventListener('input', () => loadHistoryRuns({ silent: true }));
    $('compare-runs-btn')?.addEventListener('click', compareSelectedRuns);
    $('close-comparison-btn')?.addEventListener('click', () => {
      $('comparison-results-panel')?.classList.add('hidden');
    });

    $('history-runs-tbody')?.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-action');
      const runId = btn.getAttribute('data-run-id');
      if (!runId) return;

      if (action === 'load-run') {
        loadRunIntoWorkbench(runId);
      } else if (action === 'set-run-a') {
        $('compare-run-a-select').value = runId;
        showToast(`Selected Run ${runId.slice(0, 8)} as Run A.`, 'info');
      } else if (action === 'set-run-b') {
        $('compare-run-b-select').value = runId;
        showToast(`Selected Run ${runId.slice(0, 8)} as Run B.`, 'info');
      } else if (action === 'export-txt') {
        downloadRunArtifact(runId, 'headers');
      } else if (action === 'export-json') {
        downloadRunArtifact(runId, 'json');
      }
    });

    // Tab 4: Admin & Audit Console
    $('admin-reload-config-btn')?.addEventListener('click', () => loadAdminConfig());
    $('admin-save-config-btn')?.addEventListener('click', openAdminSaveConfirmation);
    $('admin-reset-config-btn')?.addEventListener('click', resetAdminConfigToDefaults);

    $('confirm-modal-cancel')?.addEventListener('click', () => {
      state.pendingConfirmAction = null;
      $('confirm-modal')?.classList.add('hidden');
    });
    $('confirm-modal-proceed')?.addEventListener('click', async () => {
      const fn = state.pendingConfirmAction;
      state.pendingConfirmAction = null;
      $('confirm-modal')?.classList.add('hidden');
      if (typeof fn === 'function') {
        try {
          await fn();
        } catch (_err) {
          // Handled by apiRequest
        }
      }
    });

    $('refresh-audit-btn')?.addEventListener('click', () => loadAuditLogs());
    $('audit-outcome-filter')?.addEventListener('change', () => loadAuditLogs());
    $('audit-action-filter')?.addEventListener('input', () => loadAuditLogs({ silent: true }));
    $('audit-actor-filter')?.addEventListener('input', () => loadAuditLogs({ silent: true }));
  }

  document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    checkExistingSession();
  });
})();
