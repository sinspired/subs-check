(function () {
  'use strict';

  // ==================== 常量定义 ====================
  const API = {
    status: '/api/status',
    logs: '/api/logs',
    config: '/api/config',
    version: '/api/version',
    trigger: '/api/trigger-check',
    forceClose: '/api/force-close',
    singboxVersions: '/api/singbox-versions',
    publicVersion: '/admin/version'
  };

  // --- 动态轮询配置 ---
  const STATUS_INTERVAL_FAST = 800;  // 检测中：状态刷新 0.8秒
  const STATUS_INTERVAL_SLOW = 3000; // 空闲时：状态刷新 3秒

  const LOG_INTERVAL_FAST = 1000;    // 检测中：日志刷新 1秒
  const LOG_INTERVAL_SLOW = 3000;    // 空闲时：日志刷新 3秒

  const MAX_LOG_LINES = 1000;
  const MAX_FAILURE_DURATION_MS = 10000;
  const ACTION_CONFIRM_TIMEOUT_MS = 600000;
  const THEME_KEY = 'theme';

  // ==================== DOM 元素缓存 ====================
  const $ = s => document.querySelector(s);
  const els = {
    apiKeyInput: $('#apiKeyInput'),
    showApikeyBtn: $('#show-apikey'),
    loginBtn: $('#login-button'),
    rememberKey: $('#rememberKey'),
    loginModal: $('#loginModal'),
    statusEl: $('#status'),
    logContainer: $('#logContainer'),
    versionBadge: $('#version-badge'),
    versionLogin: $(`#version-login`),
    versionInline: $('#versionInline'),
    toggleBtn: $('#btnToggleCheck'),
    refreshLogsBtn: $('#refreshLogs'),
    saveCfgBtn: $('#saveCfg'),
    reloadCfgBtn: $('#reloadCfg'),
    configEditor: $('#configEditor'),
    editorContainer: $('#editorContainer'),
    progressBar: $('#progress'),
    progressText: $('#progressText'),
    progressPercentTitle: $(`#progressPercentTitle`),
    successTitle: $(`#successTitle`),
    successText: $('#successText'),
    progressPercent: $('#progressPercent'),
    downloadLogsBtnSide: $('#downloadLogsBtnSide'),
    searchBtn: $('#searchBtn'),
    logoutBtn: $('#logoutBtn'),
    logoutBtnMobile: $('#logoutBtnMobile'),
    openEditorBtn: $('#openEditor'),
    themeToggleBtn: $('#themeToggle'),
    iconMoon: $('#iconMoon'),
    iconSun: $('#iconSun'),
    projectInfoBtn: document.getElementById('project-info'),
    projectMenu: document.getElementById('projectMenu'),
    lastCheckTime: $('#lastCheckTime'),
    lastCheckDuration: $('#lastCheckDuration'),
    lastCheckTotal: $('#lastCheckTotal'),
    lastCheckAvailable: $('#lastCheckAvailable'),
    historyPlaceholder: document.getElementById('historyPlaceholder'),
    historyLine: $(`#history-line`),
    toastContainer: document.getElementById('toastContainer') || createToastContainer()
  };

  // ==================== 全局状态 ====================
  let sessionKey = null;
  let timers = { logs: null, status: null };

  // 动态间隔控制
  let currentStatusInterval = STATUS_INTERVAL_SLOW;
  let currentLogInterval = LOG_INTERVAL_SLOW;

  let lastLogLines = [];
  let logsPollRunning = false;
  let statusPollRunning = false;

  let apiFailureCount = 0;
  let firstFailureAt = null;

  let actionState = 'unknown';
  let actionInFlight = false;

  let lastCheckInfo = null;
  let checkStartTime = null;
  let codeMirrorView = null;

  // Sub-Store 跳转缓存
  let _cachedSubStoreConfig = null;
  let lastSubStorePath = null;

  // 分享按钮缓存
  let cachedConfigPayload = null;
  let cachedSingboxVersions = null;

  // ==================== 核心工具函数 ====================

  function createToastContainer() {
    const c = document.createElement('div');
    c.id = 'toastContainer';
    document.body.appendChild(c);
    return c;
  }

  function safeLS(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      if (value === null) localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch (e) { return null; }
  }

  function showToast(msg, type = 'info', timeout = 3000) {
    const c = els.toastContainer;
    if (!c) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    const ico = document.createElement('span');
    ico.className = 'icon';
    el.appendChild(ico);
    const t = document.createElement('div');
    t.style.flex = '1';
    t.textContent = msg;
    el.appendChild(t);
    const bar = document.createElement('div');
    bar.className = 'progress-bar';
    bar.style.animationDuration = timeout + 'ms';
    el.appendChild(bar);
    c.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(6px)';
    }, timeout);
    setTimeout(() => {
      try { c.removeChild(el); } catch (e) { }
    }, timeout + 420);
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function sleep(ms) {
    return new Promise(res => setTimeout(res, ms));
  }

  // ==================== API 通信 ====================

  async function sfetch(url, opts = {}) {
    if (!sessionKey) return { ok: false, status: 401, error: '未认证' };
    opts.headers = { ...opts.headers, 'X-API-Key': sessionKey };
    try {
      const r = await fetch(url, opts);
      const ct = r.headers.get('content-type') || '';
      const text = await r.text();
      let payload = ct.includes('application/json') ? JSON.parse(text) : text;

      if (r.status === 401) {
        doLogout('未授权：API Key 无效或已失效');
        return { ok: false, status: 401, payload };
      }
      if (r.ok) {
        resetApiFailures();
        return { ok: true, status: r.status, payload };
      }
      handleApiFailure();
      return { ok: false, status: r.status, payload };
    } catch (e) {
      handleApiFailure();
      return { ok: false, error: e };
    }
  }

  function handleApiFailure() {
    apiFailureCount++;
    if (!firstFailureAt) firstFailureAt = Date.now();
    if (firstFailureAt && (Date.now() - firstFailureAt) >= MAX_FAILURE_DURATION_MS) {
      doLogout('连续无法连接 API 超过 10 秒');
    }
  }

  function resetApiFailures() {
    apiFailureCount = 0;
    firstFailureAt = null;
  }

  // ==================== 轮询控制 (全动态变速) ====================

  function startPollers() {
    if (!sessionKey) return;
    startLogPoller();
    if (!timers.status) {
      const statusLoop = async () => {
        if (!sessionKey) return;
        if (!statusPollRunning) {
          await loadStatus().catch(() => { });
        }
        timers.status = setTimeout(statusLoop, currentStatusInterval);
      };
      statusLoop();
    }
  }

  function stopPollers() {
    if (timers.status) {
      clearTimeout(timers.status);
      timers.status = null;
    }
    if (timers.logs) {
      clearTimeout(timers.logs);
      timers.logs = null;
    }
  }

  function startLogPoller() {
    if (timers.logs) return;
    const logLoop = async () => {
      if (!sessionKey) return;
      if (!logsPollRunning) {
        await loadLogsIncremental(true).catch(() => { });
      }
      timers.logs = setTimeout(logLoop, currentLogInterval);
    };
    logLoop();
  }

  // ==================== 业务逻辑 ====================

  async function loadStatus() {
    if (!sessionKey || statusPollRunning) return;
    statusPollRunning = true;
    try {
      const r = await sfetch(API.status);
      if (!r.ok) {
        if (els.statusEl) {
          els.statusEl.textContent = '获取状态失败';
          els.statusEl.className = 'muted status-label status-error';
        }
        return;
      }

      const d = r.payload || {};
      const checking = !!d.checking;

      // --- 动态调整频率 ---
      if (checking) {
        currentStatusInterval = STATUS_INTERVAL_FAST;
        currentLogInterval = LOG_INTERVAL_FAST;
      } else {
        currentStatusInterval = STATUS_INTERVAL_SLOW;
        currentLogInterval = LOG_INTERVAL_SLOW;
      }

      const lastChecked = d.lastCheck && (typeof d.lastCheck.total === 'number');

      if (checking) {
        updateToggleUI('checking');
        showProgressUI(true);
        updateProgress(d.proxyCount || 0, d.progress || 0, d.available || 0, true, lastChecked);
        hideLastCheckResult();
        if (!checkStartTime) checkStartTime = Date.now();
      } else {
        showProgressUI(false);
        updateToggleUI('idle');
        updateProgress(d.proxyCount || 0, d.progress || 0, d.available || 0, false, lastChecked);

        if (els.progressBar && (d.progress === 0 || d.proxyCount === 0)) {
          els.progressBar.value = 0;
        }

        if (lastChecked) {
          showLastCheckResult({
            lastCheckTime: d.lastCheck.time || d.lastCheck.timestamp,
            duration: d.lastCheck.duration,
            total: d.lastCheck.total || d.proxyCount,
            available: d.lastCheck.available || d.available
          });
          checkStartTime = null;
        } else if (checkStartTime && lastCheckInfo) {
          const duration = Math.round((Date.now() - checkStartTime) / 1000);
          showLastCheckResult({
            lastCheckTime: new Date().toISOString().replace('T', ' ').split('.')[0],
            duration: duration,
            total: d.proxyCount || lastCheckInfo.total,
            available: d.available || lastCheckInfo.available
          });
          checkStartTime = null;
        } else if (lastCheckInfo) {
          showLastCheckResult(lastCheckInfo);
        } else {
          showLastCheckResult(null);
        }
      }
    } finally {
      statusPollRunning = false;
    }
  }

  async function loadLogsIncremental(IntervalRun) {
    if (!sessionKey || logsPollRunning) return;
    logsPollRunning = true;
    try {
      const r = await sfetch(API.logs);
      if (!r.ok) return;

      let lines = [];
      const p = r.payload;
      if (Array.isArray(p?.logs)) lines = p.logs.map(String);
      else if (typeof p?.logs === 'string') lines = p.logs.split('\n');
      else if (typeof p === 'string') lines = p.split('\n');
      else lines = [JSON.stringify(p)];

      const newTail = lines.slice(-MAX_LOG_LINES);

      if (lastLogLines.length === 0) {
        lastLogLines = newTail;
        renderLogLines(lastLogLines, IntervalRun);
        if (!lastCheckInfo) {
          const parsed = parseCheckResultFromLogs(newTail);
          if (parsed) {
            lastCheckInfo = parsed;
            showLastCheckResult(parsed);
          }
        }
        return;
      }

      const oldStr = lastLogLines.join('\n');
      const newStr = newTail.join('\n');

      if (newStr.startsWith(oldStr) && newStr.length > oldStr.length) {
        const addedPart = newStr.substring(oldStr.length + 1);
        const added = addedPart.split('\n').filter(s => s !== '');
        if (added.length > 0) {
          appendLogLines(added);
          if (added.some(line => line.includes('检测完成'))) {
            const parsed = parseCheckResultFromLogs(newTail);
            if (parsed) {
              lastCheckInfo = parsed;
              showLastCheckResult(parsed);
            }
          }
        }
        lastLogLines = newTail;
      } else {
        lastLogLines = newTail;
        renderLogLines(lastLogLines, IntervalRun);
      }
    } finally {
      logsPollRunning = false;
    }
  }

  // ==================== 进度条逻辑 ====================

  function updateProgress(total, processed, available, checking, lastChecked) {
    if (!updateProgress.etaState) {
      updateProgress.etaState = {
        startTime: Date.now(),
        lastUpdateUI: 0,
        cachedEtaText: '',
        lastProcessed: -1,
        lastTotal: 0
      };
    }
    const state = updateProgress.etaState;
    total = Number(total) || 0;
    processed = Number(processed) || 0;
    const now = Date.now();

    if (processed === 0 || (processed < state.lastProcessed && processed < 5)) {
      if (processed === 0) {
        state.startTime = now;
        state.cachedEtaText = '';
      }
    }
    state.lastProcessed = processed;
    state.lastTotal = total;

    const pct = total > 0 ? Math.min(100, (processed / total) * 100) : 0;
    if (els.progressBar) els.progressBar.value = pct;
    if (els.progressText) els.progressText.textContent = `${processed}/${total}`;
    if (els.progressPercentTitle) els.progressPercentTitle.textContent = '进度';
    if (els.successTitle) els.successTitle.textContent = '可用：';
    if (els.successText) {
      els.successText.classList.add("success-highlight");
      els.successText.textContent = available;
    }
    if (els.progressPercent) els.progressPercent.textContent = pct.toFixed(1) + "%";

    let etaText = state.cachedEtaText;
    if (checking && processed < total && total > 0) {
      const timeElapsed = now - state.startTime;
      if (timeElapsed < 30000 && processed < 5000) {
        etaText = '计算中...';
      } else if (now - state.lastUpdateUI > 10000) {
        const safeTime = Math.max(1, timeElapsed / 1000);
        const rate = processed / safeTime;
        const remain = Math.max(0, total - processed);
        if (rate > 0.01) {
          const etaSec = Math.round(remain / rate);
          if (etaSec > 3600) {
            const h = Math.floor(etaSec / 3600);
            const m = Math.round((etaSec % 3600) / 60);
            etaText = `${h}h ${m}m`;
          } else if (etaSec > 60) {
            etaText = Math.round(etaSec / 60) + 'm';
          } else {
            etaText = etaSec + 's';
          }
        } else {
          etaText = '...';
        }
        state.cachedEtaText = etaText;
        state.lastUpdateUI = now;
      }
    } else {
      etaText = '';
    }

    if (els.statusEl) {
      if (processed < total && total > 0 && checking) {
        els.statusEl.textContent = `运行中, 预计剩余: ${etaText}`;
        els.statusEl.title = etaText ? `预计剩余: ${etaText}` : '';
        els.statusEl.className = 'muted status-label status-checking';
      } else if ((processed >= total && total > 0) || lastChecked) {
        els.statusEl.textContent = '检测完成';
        els.statusEl.title = '';
        els.className = 'muted status-label status-logged';
      } else {
        els.statusEl.textContent = '空闲';
        els.statusEl.title = '';
        els.className = 'muted status-label status-idle';
      }
    }
  }

  // ==================== 界面辅助函数 ====================

  function showProgressUI(visible) {
    const v = !!visible;
    try {
      const progWrapper = document.querySelector('#mainContent .progress-wrapper') || document.querySelector('.progress-wrapper');
      const progBarWrap = document.querySelector('#mainContent .progress-bar-wrap') || document.querySelector('.progress-bar-wrap');

      if (progWrapper) progWrapper.style.display = v ? '' : 'none';
      if (progBarWrap) progBarWrap.style.display = v ? '' : 'none';
      if (els.historyPlaceholder) els.historyPlaceholder.style.display = v ? 'none' : '';
      if (els.historyLine) els.historyLine.style.display = v ? 'none' : '';

      if (!v) {
        if (els.progressBar) els.progressBar.value = 0;
        ['progressText', 'progressPercent', 'progressPercentTitle', 'successTitle'].forEach(k => { if (els[k]) els[k].textContent = ''; });
        if (els.successText) {
          els.successText.classList.remove("success-highlight");
          els.successText.textContent = '';
        }
        if (lastCheckInfo) showLastCheckResult(lastCheckInfo);
        else showLastCheckResult(null);
      } else {
        hideLastCheckResult();
      }
    } catch (e) { console.warn(e); }
  }

  function showLastCheckResult(info) {
    if (!els.historyPlaceholder) return;
    let notFoundEl = document.getElementById('historyNotFound');
    if (!notFoundEl) {
      notFoundEl = document.createElement('div');
      notFoundEl.id = 'historyNotFound';
      notFoundEl.className = 'muted';
      notFoundEl.style.fontSize = '12px';
      notFoundEl.style.marginTop = '6px';
      notFoundEl.textContent = '未发现检测记录';
      const summary = els.historyPlaceholder.querySelector('.history-summary');
      if (summary) summary.insertAdjacentElement('afterend', notFoundEl);
      else els.historyPlaceholder.appendChild(notFoundEl);
    }

    try {
      if (!actionInFlight && actionState !== 'checking') {
        els.historyPlaceholder.style.display = '';
        if (!info) {
          if (els.historyLine) els.historyLine.style.display = 'none';
          if (notFoundEl) notFoundEl.style.display = '';
          return;
        }
        if (notFoundEl) notFoundEl.style.display = 'none';
        if (els.historyLine) els.historyLine.style.display = '';

        const prettyTime = info.lastCheckTime ? info.lastCheckTime.replace('T', ' ') : '-';
        const prettyDuration = (typeof info.duration === 'number')
          ? (info.duration >= 60 ? Math.floor(info.duration / 60) + '分' + (info.duration % 60) + '秒' : info.duration + '秒')
          : (info.duration || '0');
        const prettyTotal = info.total >= 10000 ? (info.total / 10000).toFixed(1) + '万' : info.total;

        const histTimeEl = document.getElementById('historyLastTime');
        const histDurationEl = document.getElementById('historyLastDuration');
        const histTotalEl = document.getElementById('historyLastTotal');
        const histAvailableEl = document.getElementById('historyLastAvailable');

        if (histTimeEl) histTimeEl.textContent = prettyTime;
        if (histDurationEl) histDurationEl.textContent = prettyDuration;
        if (histTotalEl) histTotalEl.textContent = prettyTotal;
        if (histAvailableEl) histAvailableEl.textContent = info.available;

        if (els.lastCheckTime) els.lastCheckTime.textContent = prettyTime;
        if (els.lastCheckDuration) els.lastCheckDuration.textContent = prettyDuration;
        if (els.lastCheckTotal) els.lastCheckTotal.textContent = info.total;
        if (els.lastCheckAvailable) els.lastCheckAvailable.textContent = info.available;
      }
    } catch (e) { }
  }

  function hideLastCheckResult() {
    if (els.historyPlaceholder) els.historyPlaceholder.style.display = 'none';
  }

  // ==================== 日志渲染 ====================

  let isMouseInsideLog = false;
  if (els.logContainer) {
    els.logContainer.addEventListener('mouseenter', () => isMouseInsideLog = true);
    els.logContainer.addEventListener('mouseleave', () => isMouseInsideLog = false);
  }

  function renderLogLines(lines, IntervalRun) {
    if (!els.logContainer) return;
    if (isUserSelectingOrHovering() && IntervalRun) {
      els.logContainer.title = "暂停自动刷新";
      return;
    }
    els.logContainer.title = "";
    els.logContainer.innerHTML = lines.map(l => '<div>' + colorize(l) + '</div>').join('');
    scrollToBottomSafe();
  }

  function appendLogLines(linesToAdd) {
    if (!els.logContainer || !linesToAdd?.length) return;
    const frag = document.createDocumentFragment();
    linesToAdd.forEach(l => {
      const d = document.createElement('div');
      d.innerHTML = colorize(l);
      frag.appendChild(d);
    });
    els.logContainer.appendChild(frag);

    while (els.logContainer.children.length > MAX_LOG_LINES) {
      els.logContainer.removeChild(els.logContainer.firstChild);
    }
    scrollToBottomSafe();
  }

  function scrollToBottomSafe() {
    requestAnimationFrame(() => {
      if (!isMouseInsideLog) {
        els.logContainer.scrollTop = els.logContainer.scrollHeight;
      } else {
        const isScrolledToBottom = els.logContainer.scrollHeight - els.logContainer.clientHeight <= els.logContainer.scrollTop + 50;
        if (isScrolledToBottom) els.logContainer.scrollTop = els.logContainer.scrollHeight;
      }
    });
  }

  function isUserSelectingOrHovering() {
    const sel = window.getSelection();
    return (sel && sel.toString().length > 0) || isMouseInsideLog;
  }

  function colorize(line) {
    const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
    let out = escapeHtml(line);
    if (tsMatch) {
      const ts = tsMatch[0];
      out = '<span class="log-time">' + ts + '</span>' + out.slice(ts.length);
    }

    out = out.replace(/\x1b\[([\d;]+)m/g, function (match, innerCode) {
      const codes = innerCode.split(';');
      let html = '';
      codes.forEach(code => {
        switch (code) {
          case '31': html += '<span style="color: #ff4d4f; font-weight: bold;">'; break;
          case '33': html += '<span style="color: #faad14; font-weight: bold;">'; break;
          case '9': html += '<span style="text-decoration: line-through; color: #999; opacity: 0.8;">'; break;
          case '29': html += '</span>'; break;
          case '39': case '0': html += '</span></span></span>'; break;
        }
      });
      return html;
    });

    out = out.replace(/\b(INF|INFO)\b/g, '<span class="log-info">INF</span>')
      .replace(/\b(ERR|ERROR)\b/g, '<span class="log-error">ERR</span>')
      .replace(/\b(WRN|WARN)\b/g, '<span class="log-warn">WRN</span>')
      .replace(/\b(DBG|DEBUG)\b/g, '<span class="log-debug">DBG</span>');

    if (/发现新版本/.test(out)) {
      out = '<div class="log-new-version">' + out.replace(/最新版本=([^\s]+)/, '最新版本=<span class="success-highlight">$1</span>') + '</div>';
    }
    return out;
  }

  function parseCheckResultFromLogs(logs) {
    if (!logs || !Array.isArray(logs)) return null;
    const lines = logs.map(String);
    let startTime, endTime, totalNodes, availableNodes;

    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (!endTime && line.includes('检测完成')) {
        const m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
        if (m) endTime = m[1];
      }
      if (!availableNodes) {
        const m = line.match(/可用节点数量:\s*(\d+)/);
        if (m) availableNodes = parseInt(m[1]);
      }
      if (!totalNodes) {
        const m = line.match(/去重后节点数量:\s*(\d+)/);
        if (m) totalNodes = parseInt(m[1]);
      }
      if (!startTime && (line.includes('手动触发检测') || line.includes('开始准备检测代理'))) {
        const m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
        if (m) startTime = m[1];
        if (startTime && endTime) break;
      }
    }
    if (startTime && endTime && totalNodes > 0) {
      const duration = Math.round((new Date(endTime) - new Date(startTime)) / 1000);
      return { lastCheckTime: endTime, duration, total: totalNodes, available: availableNodes };
    }
    return null;
  }

  // ==================== 认证与交互 ====================

  async function onLoginBtnClick() {
    const k = els.apiKeyInput?.value?.trim();
    if (!k) {
      showToast('请输入 API 密钥', 'warn');
      els.apiKeyInput?.focus();
      return;
    }
    els.loginBtn.disabled = true;
    els.loginBtn.textContent = '验证中…';
    try {
      const resp = await fetch(API.status, { headers: { 'X-API-Key': k } });
      if (resp.status === 401) {
        showToast('API 密钥无效', 'error');
        return;
      }
      if (!resp.ok) {
        showToast('验证失败，HTTP ' + resp.status, 'error');
        return;
      }
      sessionKey = k;
      if (els.rememberKey?.checked) safeLS('subscheck_api_key', k);
      showLogin(false);
      document.activeElement?.blur();
      setAuthUI(true);
      await loadAll();
      startPollers();
      showToast('验证成功，已登录', 'success');
    } catch (e) {
      showToast('网络错误或服务器未响应', 'error');
    } finally {
      els.loginBtn.disabled = false;
      els.loginBtn.textContent = '进入管理界面';
    }
  }

  function doLogout(reason = '已退出登录') {
    stopPollers();
    sessionKey = null;
    safeLS('subscheck_api_key', null);
    setAuthUI(false);
    if (els.logContainer) els.logContainer.innerHTML = '<div class="muted" style="font-family: system-ui;">已退出登录。</div>';
    if (els.configEditor && codeMirrorView) setEditorContent('');
    resetApiFailures();
    showProgressUI(false);
    showLogin(true);
    showToast(reason, 'info');
  }

  function showLogin(show) {
    getPublicVersion();
    if (els.loginModal) els.loginModal.classList.toggle('login-hidden', !show);
    if (show) els.apiKeyInput?.focus();
  }

  function setAuthUI(ok) {
    if (els.statusEl) {
      els.statusEl.textContent = `状态：${ok ? '空闲' : '未登录'}`;
      els.statusEl.className = 'muted status-label ' + (ok ? 'status-logged' : 'status-idle');
    }
    [els.toggleBtn, els.refreshLogsBtn, els.saveCfgBtn, els.reloadCfgBtn].forEach(b => b && (b.disabled = !ok));
    updateToggleUI(ok ? 'idle' : 'disabled');
  }

  function updateToggleUI(state) {
    actionState = state;
    if (!els.toggleBtn) return;
    const config = {
      idle: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>', disabled: false, title: '开始检测', pressed: 'false' },
      starting: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 12h-2.25c0 5.5 4.25 10 9.75 10s9.75-4.5 9.75-10-4.25-10-9.75-10-9.75 4.5-9.75 10zM12 7.5v9"/></svg>', disabled: true, title: '正在开始', pressed: 'true' },
      checking: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h12v12H6z"/></svg>', disabled: false, title: '检测中 - 点击停止', pressed: 'true' },
      stopping: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 12h-2.25c0 5.5 4.25 10 9.75 10s9.75-4.5 9.75-10-4.25-10-9.75-10-9.75 4.5-9.75 10zM12 7.5v9"/></svg>', disabled: true, title: '正在结束', pressed: 'true' },
      disabled: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/></svg>', disabled: true, title: '请先登录', pressed: 'false' }
    };
    const cfg = config[state] || config.disabled;
    els.toggleBtn.disabled = cfg.disabled;
    els.toggleBtn.className = 'toggle-btn state-' + state;
    els.toggleBtn.title = cfg.title;
    els.toggleBtn.setAttribute('aria-pressed', cfg.pressed);
    const iconEl = els.toggleBtn.querySelector('.btn-icon');
    if (iconEl) iconEl.innerHTML = cfg.icon;
  }

  // ==================== Sub-Store & Share ====================

  async function fetchSubStoreConfig() {
    const r = await sfetch(API.config);
    if (!r.ok) throw new Error("读取配置失败");
    const config = YAML.parse(r.payload?.content ?? '');
    return {
      subStorePath: r.payload?.sub_store_path ?? '',
      portStr: config["sub-store-port"]
    };
  }

  function buildSubStoreUrl(config) {
    const { subStorePath, portStr } = config;
    if (!subStorePath) throw new Error("配置中未找到 sub_store_path");

    let path = subStorePath;
    if (path && !path.startsWith('/') && path.length > 1) {
      path = '/' + path;
    }

    const cleanPort = (portStr ?? "").toString().trim().replace(/^:/, "");
    const currentPort = window.location.port;
    const shouldAddPort = currentPort && currentPort !== '';
    const portToAdd = (shouldAddPort && cleanPort) ? ':' + cleanPort : '';

    let hostname = window.location.hostname;
    if (!shouldAddPort) {
      const parts = hostname.split(".");
      if (parts.length > 1) {
        hostname = parts.length === 2 ? "sub_store_for_subs_check." + hostname : "sub_store_for_subs_check." + parts.slice(1).join(".");
      }
    }

    const isFirstTime = lastSubStorePath === null;
    const isPathChanged = lastSubStorePath !== subStorePath;
    const baseUrl = window.location.protocol + '//' + hostname + portToAdd;

    return {
      url: (isFirstTime || isPathChanged) ? `${baseUrl}?api=${path}` : baseUrl,
      subStorePath
    };
  }

  async function handleOpenSubStore(e) {
    e.preventDefault();
    if (!sessionKey) { showLogin(true); return; }

    const newWindow = window.open('', '_blank');
    if (!newWindow) { showToast('窗口弹出被拦截', 'warn'); return; }

    newWindow.document.title = "打开 Sub-Store...";
    newWindow.document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;color:#666;"><h3>正在跳转...</h3></div>';

    try {
      let configData = _cachedSubStoreConfig;
      if (!configData) {
        configData = await fetchSubStoreConfig();
        _cachedSubStoreConfig = configData;
      }
      const result = buildSubStoreUrl(configData);
      lastSubStorePath = result.subStorePath;
      newWindow.location.href = result.url;
    } catch (err) {
      console.error(err);
      newWindow.close();
      showToast(err.message || '打开失败', 'error');
    }
  }

  // 获取分享链接 Base URL
  async function getBaseUrl(path, port) {
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    const baseUrlWithoutPort = `${protocol}//${hostname}`;

    const currentPort = window.location.port;
    const shouldAddPort = !!currentPort;
    const portToAdd = (shouldAddPort && port) ? `:${port}` : '';

    let sub_store_hostname = hostname;
    if (!shouldAddPort) {
      const parts = hostname.split(".");
      if (parts.length === 2) {
        sub_store_hostname = `sub_store_for_subs_check.${hostname}`;
      } else if (parts.length > 2) {
        sub_store_hostname = `sub_store_for_subs_check.${parts.slice(1).join(".")}`;
      }
    }

    const baseUrl = `${baseUrlWithoutPort}${portToAdd}${path}`;
    const fallbackUrl = `${protocol}//${sub_store_hostname}${portToAdd}${path}`;

    try {
      const res = await fetch(baseUrl, { method: "HEAD" }).catch(() => null);
      return res && res.ok ? baseUrl : fallbackUrl;
    } catch {
      return fallbackUrl;
    }
  }

  // ==================== 配置编辑器 ====================

  function initCodeMirror(val = '') {
    const container = els.configEditor;
    if (!container || codeMirrorView) return;
    requestAnimationFrame(() => {
      const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
      codeMirrorView = window.CodeMirror.createEditor(container, val, theme);
    });
  }

  function setEditorContent(txt) {
    if (!codeMirrorView) return;
    codeMirrorView.dispatch({ changes: { from: 0, to: codeMirrorView.state.doc.length, insert: (txt || '').replace(/\r\n/g, '\n') } });
  }

  async function loadConfigValidated() {
    if (!sessionKey) return;
    const r = await sfetch(API.config);
    if (!r.ok) return showToast('读取配置失败', 'warn');
    const raw = (typeof r.payload?.content === 'string') ? r.payload.content : String(r.payload || '');
    codeMirrorView ? setEditorContent(raw) : initCodeMirror(raw);
  }

  async function saveConfigWithValidation() {
    if (!sessionKey || !codeMirrorView) return;
    const rawContent = codeMirrorView.state.doc.toString();
    try {
      const doc = YAML.parseDocument(rawContent);
      if (doc.errors && doc.errors.length > 0) {
        return showToast("YAML 语法错误：" + doc.errors[0].message, "error", 5000);
      }
      const formatted = doc.toString();
      setEditorContent(formatted);
      const r = await sfetch(API.config, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: formatted })
      });
      if (r.ok) {
        showToast(r.payload?.message || '保存成功', 'success');
        _cachedSubStoreConfig = null;
        cachedConfigPayload = null; // 清除分享配置缓存
      } else {
        showToast('保存失败: ' + (r.payload?.error || '未知错误'), 'error');
      }
    } catch (e) {
      showToast("校验失败：" + e.message, "error");
    }
  }

  // ==================== 其他辅助 ====================

  async function waitForBackendChecking(desired) {
    const start = Date.now();
    while (Date.now() - start < ACTION_CONFIRM_TIMEOUT_MS) {
      try {
        const r = await sfetch(API.status);
        if (r.ok && !!r.payload?.checking === desired) return { ok: true };
      } catch (e) { }
      await sleep(600);
    }
    return { ok: false };
  }

  async function getVersion() {
    if (!sessionKey) return;
    try {
      const r = await sfetch(API.version);
      const p = r.payload;
      if (p?.version && els.versionInline) els.versionInline.textContent = p.version;
      if (p?.latest_version && p.version != p.latest_version) {
        els.versionInline.textContent = `有新版本 v${p.latest_version}`;
        els.versionInline.classList.add("new-version");
        els.versionInline.onclick = () => window.open("https://github.com/sinspired/subs-check/releases/latest", "_blank");
      }
    } catch (e) { }
  }

  async function getPublicVersion() {
    try {
      const r = await fetch(API.publicVersion);
      const d = await r.json();
      if (els.versionLogin) els.versionLogin.textContent = d.version;
      if (d?.latest_version && d.version != d.latest_version) {
        els.versionBadge.classList.add("new-version");
        els.versionBadge.title = `有新版本 v${d.latest_version}`;
        els.versionBadge.onclick = () => window.open("https://github.com/sinspired/subs-check/releases/latest", "_blank");
      }
    } catch (e) { }
  }

  // ==================== 初始化 ====================

  function bindControls() {
    els.loginBtn?.addEventListener('click', onLoginBtnClick);
    els.subStoreBtn = document.getElementById('sub-store');
    els.subStoreBtnMobile = document.getElementById('btnSubStore');
    els.subStoreBtn?.addEventListener('click', handleOpenSubStore);
    els.subStoreBtnMobile?.addEventListener('click', handleOpenSubStore);

    els.toggleBtn?.addEventListener('click', async () => {
      if (!sessionKey || actionInFlight) return;
      actionInFlight = true;
      try {
        if (actionState === 'checking') {
          updateToggleUI('stopping');
          showToast('正在停止...', 'info');
          await sfetch(API.forceClose, { method: 'POST' });
          const confirm = await waitForBackendChecking(false);
          if (confirm.ok) showToast('检测已停止', 'success');
        } else {
          updateToggleUI('starting');
          showProgressUI(true);
          checkStartTime = Date.now();
          showToast('启动中...', 'info');
          await sfetch(API.trigger, { method: 'POST' });
          const confirm = await waitForBackendChecking(true);
          if (confirm.ok) {
            updateToggleUI('checking');
          } else {
            showProgressUI(false);
            updateToggleUI('idle');
            showToast('启动超时', 'warn');
          }
        }
      } finally {
        actionInFlight = false;
      }
    });

    els.refreshLogsBtn?.addEventListener('click', () => {
      showToast('正在刷新日志...', 'info');
      loadLogsIncremental(false);
    });
    els.saveCfgBtn?.addEventListener('click', saveConfigWithValidation);
    els.reloadCfgBtn?.addEventListener('click', async () => {
      showToast('正在重载配置...', 'info');
      await loadConfigValidated();
      showToast('配置已重载', 'success');
    });
    els.openEditorBtn?.addEventListener('click', () => els.editorContainer?.scrollIntoView({ behavior: 'smooth' }));

    els.downloadLogsBtnSide?.addEventListener('click', () => {
      const t = els.logContainer?.innerText || '';
      if (!t) return showToast('日志为空', 'warn');
      const blob = new Blob([t], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'subs-check-logs.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('已开始下载日志', 'success');
    });

    const logoutHandler = () => { if (confirm('确定退出？')) doLogout(); };
    els.logoutBtn?.addEventListener('click', logoutHandler);
    els.logoutBtnMobile?.addEventListener('click', logoutHandler);

    els.apiKeyInput?.addEventListener('keydown', e => { if (e.key === 'Enter') onLoginBtnClick(); });

    if (els.showApikeyBtn) {
      els.apiKeyInput.addEventListener('input', () => els.showApikeyBtn.classList.toggle('visible', els.apiKeyInput.value.length > 0));
      els.showApikeyBtn.addEventListener('click', () => {
        const isPwd = els.apiKeyInput.type === 'password';
        els.apiKeyInput.type = isPwd ? 'text' : 'password';
        els.showApikeyBtn.textContent = isPwd ? '隐藏' : '显示';
      });
    }

    const applyTheme = (t) => {
      document.documentElement.setAttribute('data-theme', t);
      if (els.iconMoon) els.iconMoon.style.display = t === 'dark' ? '' : 'none';
      if (els.iconSun) els.iconSun.style.display = t === 'light' ? '' : 'none';
      if (codeMirrorView) {
        const val = codeMirrorView.state.doc.toString();
        codeMirrorView.destroy();
        codeMirrorView = window.CodeMirror.createEditor(els.configEditor, val, t);
      }
    };

    const initTheme = safeLS(THEME_KEY) || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    applyTheme(initTheme);

    els.themeToggleBtn?.addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      safeLS(THEME_KEY, next);
    });

    // 分享菜单逻辑 (修复版)
    const setupShare = (id) => {
      const btn = document.getElementById(id);
      if (!btn) return;
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const menu = document.getElementById('shareMenu');
        if (menu.classList.contains('active')) { menu.classList.remove('active'); return; }

        if (!sessionKey) { showLogin(true); return; }

        try {
          // 1. 检查配置缓存
          if (!cachedConfigPayload) {
            const r = await sfetch(API.config);
            if (!r.ok) return showToast('读取配置失败', 'warn');
            cachedConfigPayload = r.payload;
          }

          // 2. 检查版本缓存
          if (!cachedSingboxVersions) {
            const v = await sfetch(API.singboxVersions);
            if (!v.ok) return showToast('读取singbox版本', 'warn');
            cachedSingboxVersions = v.payload;
          }

          // 3. 数据准备
          const p = cachedConfigPayload;
          const d = cachedSingboxVersions;
          const config = YAML.parse(p?.content ?? "");

          let subStorePath = p?.sub_store_path ?? '';
          const yamlSubStorePath = config["sub-store-path"] ?? "";
          if (!subStorePath) return showToast('请先设置 sub_store_path', 'error');

          const port = (config["sub-store-port"] ?? "").toString().trim().replace(/^:/, "");
          let path = subStorePath.startsWith("/") ? subStorePath : `/${subStorePath}`;

          const latestSingboxName = `singbox-${d.latest}`;
          const oldSingboxName = `singbox-${d.old}`;

          // 4. 使用 getBaseUrl 获取正确地址
          const baseUrl = await getBaseUrl(path, port);

          // 5. 更新 DOM
          const setLink = (eid, suffix) => {
            const el = document.getElementById(eid);
            if (el) el.dataset.link = `${baseUrl}${suffix}`;
          };

          setLink("commonSub-item", "/download/sub");
          setLink("mihomoSub-item", "/api/file/mihomo");

          const oldItem = document.getElementById("singboxOldSub-item");
          oldItem.textContent = `${oldSingboxName} 订阅`;
          oldItem.dataset.link = `${baseUrl}/api/file/${oldSingboxName}`;

          const newItem = document.getElementById("singboxLatestSub-item");
          newItem.textContent = `${latestSingboxName} 订阅`;
          newItem.title = `ios设备当前最高兼容 1.11 版本, 当前为 ${latestSingboxName}`;
          newItem.dataset.link = `${baseUrl}/api/file/${latestSingboxName}`;

          // 6. 显示菜单
          const rect = btn.getBoundingClientRect();
          const isMobile = window.innerWidth < 768;
          menu.style.top = `${rect.top}px`;
          menu.style.left = isMobile ? `${rect.left - 160}px` : `${rect.right * 0.9}px`;
          menu.style.transform ="none";
          menu.classList.add('active');
        } catch (err) {
          console.error(err);
          showToast('获取链接失败', 'error');
          cachedConfigPayload = null;
          cachedSingboxVersions = null;
        }
      });
    };
    setupShare("share");
    setupShare("btnShare");

    document.addEventListener('click', (e) => {
      const sm = document.getElementById('shareMenu');
      const pm = document.getElementById('projectMenu');
      if (sm?.classList.contains('active') && !sm.contains(e.target)) sm.classList.remove('active');
      if (pm?.classList.contains('active') && !els.projectInfoBtn.contains(e.target)) pm.classList.remove('active');
    });

    els.projectInfoBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      const pm = els.projectMenu;
      if (pm.classList.contains('active')) { pm.classList.remove('active'); return; }
      const rect = els.projectInfoBtn.getBoundingClientRect();
      pm.style.top = `${rect.top}px`;
      pm.style.left = (window.innerWidth < 768) ? `${rect.left - 160}px` : `${rect.right * 0.9}px`;
      pm.classList.add('active');
    });

    document.querySelectorAll('[id$="Sub-item"]').forEach(el => {
      el.addEventListener('click', async (e) => {
        const link = el.dataset.link;
        if (!link) return;
        try {
          await navigator.clipboard.writeText(link);
          showToast('已复制链接', 'success');
        } catch (err) {
          const inp = document.createElement('input');
          inp.value = link;
          document.body.appendChild(inp);
          inp.select();
          document.execCommand('copy');
          document.body.removeChild(inp);
          showToast('已复制链接', 'success');
        }
        document.getElementById('shareMenu').classList.remove('active');
      });
    });
  }

  async function loadAll() {
    await Promise.all([
      loadConfigValidated().catch(() => { }),
      loadLogsIncremental().catch(() => { }),
      loadStatus().catch(() => { }),
      getVersion().catch(() => { })
    ]);
  }

  (async function bootstrap() {
    const saved = safeLS('subscheck_api_key');
    if (saved && els.apiKeyInput) els.apiKeyInput.value = saved;

    bindControls();

    try {
      if (saved) {
        sessionKey = saved;
        const r = await sfetch(API.status);
        if (r.ok) {
          showLogin(false);
          setAuthUI(true);
          await loadAll();
          startPollers();
          showToast('自动登录成功', 'success');
        } else {
          throw new Error('auth failed');
        }
      } else {
        throw new Error('no key');
      }
    } catch (e) {
      sessionKey = null;
      safeLS('subscheck_api_key', null);
      showLogin(true);
      setAuthUI(false);
    }

    window.addEventListener('beforeunload', () => {
      stopPollers();
      if (codeMirrorView) codeMirrorView.destroy();
    });
  })();

})();