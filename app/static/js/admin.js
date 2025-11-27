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
    projectInfoBtn: $('#project-info'),
    projectMenu: $('#projectMenu'),
    githubMenuBtn: $('#githubMenuBtn'),
    dockerMenuBtn: $('#dockerMenuBtn'),
    telegramMenuBtn: $('#telegramMenuBtn'),
    githubUrlBtn: $('#githubUrlBtn'),
    dockerUrlBtn: $('#dockerUrlBtn'),
    telegramUrlBtn: $('#telegramUrlBtn'),
    lastCheckTime: $('#lastCheckTime'),
    lastCheckDuration: $('#lastCheckDuration'),
    lastCheckTotal: $('#lastCheckTotal'),
    lastCheckAvailable: $('#lastCheckAvailable'),
    historyPlaceholder: $('#historyPlaceholder'),
    historyTitle: $('#history-title'),
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

  /**
 * 创建并返回 Toast 容器
 * @returns {HTMLDivElement} Toast 容器元素
 */
  function createToastContainer() {
    const c = document.createElement('div');
    c.id = 'toastContainer';
    document.body.appendChild(c);
    return c;
  }

  /**
 * 安全操作 localStorage (读/写/删)
 * @param {string} key 键名
 * @param {string|null|undefined} [value] 值；undefined=读，null=删，其他=写
 * @returns {string|null} 获取的值或 null
 */
  function safeLS(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      if (value === null) localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch (e) { return null; }
  }

  /**
 * 显示 Toast 消息
 * @param {string} msg 提示文本
 * @param {string} [type='info'] 消息类型 (info/success/warn/error)
 * @param {number} [timeout=3000] 显示时长 (毫秒)
 * @returns {void}
 */
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

  /**
 * 转义 HTML 字符串
 * @param {string} s 原始字符串
 * @returns {string} 转义后的安全字符串
 */
  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  /**
 * 延迟执行
 * @param {number} ms 毫秒数
 * @returns {Promise<void>} Promise 延迟
 */
  function sleep(ms) {
    return new Promise(res => setTimeout(res, ms));
  }

  // ==================== 状态栏与历史区渲染 ====================

  // 定义带旋转动画的 SVG 图标 (用于状态栏)
  const STATUS_SPINNER = `
    <style>@keyframes spin-status { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }</style>
    <svg style="animation: spin-status 1s linear infinite; vertical-align: middle; margin-right: 6px; margin-bottom: 2px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>
  `;


  // 定义带旋转动画的 SVG 图标,用于检测任务
  const checking_SPINNER = `
    <style>
      @keyframes spin-status-rotate { 
        100% { transform: rotate(360deg); } 
      }
      @keyframes spin-status-dash {
        0% { stroke-dasharray: 1, 150; stroke-dashoffset: 0; }
        50% { stroke-dasharray: 45, 150; stroke-dashoffset: -15px; }
        100% { stroke-dasharray: 45, 150; stroke-dashoffset: -62px; }
      }
    </style>
    <svg 
      style="
        /* 旋转动画 2秒一圈 */
        animation: spin-status-rotate 2s linear infinite;
        will-change: transform;
        transform-origin: center;
        vertical-align: middle; 
        margin-right: 6px; 
        margin-bottom: 2px;
      " 
      width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
    >
      <!-- 内部线条进行伸缩呼吸动画 -->
      <circle 
        style="animation: spin-status-dash 1.5s ease-in-out infinite;"
        cx="12" cy="12" r="10" 
      ></circle>
    </svg>
  `;

  /**
   * 从日志解析订阅统计数据
   * @param {string[]} logs 日志数组
   * @returns {Object|null} 包含 local/remote/history/total 的统计信息或 null
   */
  function parseSubStats(logs) {
    if (!logs || !logs.length) return null;

    const MAX_DELAY_MS = 5000; // 时间窗口兜底值
    const now = Date.now();

    // 倒序遍历寻找订阅数据
    for (let i = logs.length - 1; i >= 0; i--) {
      const line = logs[i];

      // 1. 查找目标：订阅统计行
      if (line.includes('订阅数量') && line.includes('总计')) {

        let isValid = false;

        // --- [验证逻辑 A]：通过日志上下文验证---
        // 从当前行(i) 往前倒推，寻找“启动任务”的标志
        for (let j = i - 1; j >= 0; j--) {
          const prevLine = logs[j];
          // 如果在订阅数据之前找到了启动标志，说明这条数据属于当前正在运行的任务
          if (prevLine.includes('手动触发检测') || prevLine.includes('启动检测任务') || prevLine.includes('开始检测')) {
            isValid = true;
            break;
          }
          // 如果在找到启动标志前，先遇到了“检测完成”，说明这条订阅数据是上一次任务的遗留
          if (prevLine.includes('检测完成')) {
            isValid = false;
            break;
          }
        }

        // --- [验证逻辑 B]：通过时间验证 (兜底) ---
        // 如果日志被截断找不到启动标志，或者刚刷新页面，则检查时间是否在允许范围内
        if (!isValid) {
          const timeMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
          if (timeMatch) {
            const logTimeStr = timeMatch[1].replace(/-/g, '/');
            const logTime = new Date(logTimeStr).getTime();
            // 只有当数据非常新鲜 (5秒内) 才认为是有效的
            if (now - logTime <= MAX_DELAY_MS) {
              isValid = true;
            }
          }
        }

        // 如果验证未通过，跳过此行，继续往旧日志找（虽然一般情况下一条不对后面的也不对，但逻辑上跳过更严谨）
        // 或者直接 return null 认为无有效数据
        if (!isValid) return null;

        // --- 提取数据 ---
        const getVal = (regex) => {
          const m = line.match(regex);
          return m ? m[1] : null;
        };

        return {
          local: getVal(/本地=(\d+)/),
          remote: getVal(/远程=(\d+)/),
          history: getVal(/历史=(\d+)/),
          total: getVal(/总计.*?=(\d+)/) || getVal(/去重=(\d+)/)
        };
      }

      // 如果在找到数据前就先碰到了启动标志，说明还没运行到数据输出那一步
      if (line.includes('手动触发检测') || line.includes('启动检测任务') || line.includes('开始检测')) {
        return null;
      }
    }
    return null;
  }

  /**
     * 从日志中寻找当前正在进行的任务的开始时间
     * @param {string[]} logs 日志数组
     * @returns {number|null} 时间戳 (ms) 或 null
     */
  function findActiveTaskStartTime(logs) {
    if (!logs || !logs.length) return null;

    // 倒序查找最近的一次启动标志
    for (let i = logs.length - 1; i >= 0; i--) {
      const line = logs[i];
      // 如果先遇到了“检测完成”，说明没有正在运行的任务，或者任务已结束
      if (line.includes('检测完成') || line.includes('启动检测任务')) {
        return null;
      }

      if (line.includes('开始检测')) {
        const timeMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
        if (timeMatch) {
          // 兼容性处理：将 - 替换为 / 以确保 Safari 等浏览器能正确解析
          const timeStr = timeMatch[1].replace(/-/g, '/');
          const ts = new Date(timeStr).getTime();
          if (!isNaN(ts)) return ts;
        }
      }
    }
    return null;
  }

  /**
     * 渲染获取订阅数量
     * 格式示例：本地:66 | 远程:24 | 历史:2 | 总计:90 [已去重]
     */
  function renderPrepareToHistory(stats) {
    if (!els.historyPlaceholder) return;

    // 1. 确保父容器可见
    els.historyPlaceholder.style.display = '';

    // 2. 修改标题
    if (els.historyTitle) {
      // els.historyTitle.innerHTML = `${STATUS_SPINNER} 获取订阅`;
      els.historyTitle.innerHTML = `获取订阅`;
    }

    // 3. 隐藏“未发现记录”
    const notFoundEl = document.getElementById('historyNotFound');
    if (notFoundEl) notFoundEl.style.display = 'none';

    // 4. 隐藏原有的表格行
    if (els.historyLine) {
      els.historyLine.style.display = 'none';
    }

    // 5. 获取或创建临时的显示行
    let prepLine = document.getElementById('prepare-line');
    if (!prepLine) {
      prepLine = document.createElement('div');
      prepLine.id = 'prepare-line';
      // 使用 history-line 原类名
      prepLine.className = "history-line muted";

      if (els.historyLine && els.historyLine.parentNode) {
        els.historyLine.parentNode.insertBefore(prepLine, els.historyLine.nextSibling);
      } else {
        els.historyPlaceholder.appendChild(prepLine);
      }
    }
    prepLine.style.display = 'block';

    // 6. 生成内容
    if (stats) {
      const items = [];

      // 辅助函数: (标签, 值, 后缀)
      const addItem = (label, val, suffix = '') => {
        if (val !== null && val !== undefined) {
          // 在冒号前后加空格，使用 highlight 颜色高亮数值
          items.push(
            `<span class="history-line muted">${label}:</span>` +
            `<span class="available-highlight">${val}</span>` +
            `<span class="history-line muted"> ${suffix}</span>`
          );
        }
      };

      addItem('本地', stats.local);
      addItem('远程', stats.remote);
      addItem('历史', stats.history);

      // 后缀判断
      if (stats.total) {
        const total = Number(stats.total) || 0;
        const sum = ['local', 'remote', 'history']
          .map(key => Number(stats[key]) || 0)
          .reduce((a, b) => a + b, 0);

        const dupCount = sum > total ? sum - total : 0;

        if (dupCount) {
          addItem('总计', stats.total, `[已去重: ${dupCount}]`, dupCount);
        } else {
          addItem('总计', stats.total);
        }
      }

      if (items.length > 0) {
        // 使用 " | " 作为分隔符
        const separator = '<span class="history-line muted">| </span>';
        prepLine.innerHTML = items.join(separator);
      } else {
        prepLine.innerHTML = '<span class="muted">正在分析日志...</span>';
      }
    } else {
      prepLine.innerHTML = '<span class="muted">等待数据...</span>';
    }
  }

  /**
     * 恢复历史区域 UI (当离开 Prepare 阶段时调用)
     * 负责：恢复标题、隐藏准备数据行、显示正常历史数据行
     */
  function restoreHistoryTitle() {
    // 1. 恢复标题
    if (els.historyTitle) {
      els.historyTitle.textContent = '上次检测';
    }

    // 2. 隐藏临时的订阅数据行
    const prepLine = document.getElementById('prepare-line');
    if (prepLine) {
      prepLine.style.display = 'none';
    }

    // 3. 恢复显示正常的历史数据行
    if (els.historyLine) {
      els.historyLine.style.display = 'none';
    }
  }

  // ==================== API 通信 ====================

  /**
  * 安全请求封装
  * @param {string} url   请求地址
  * @param {Object} [opts] fetch 配置项
  * @returns {Promise<Object>} 包含 ok、status、payload、error
  */
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

  /**
   * 加载并更新检测状态。
   *
   * 该函数会轮询后端接口获取当前检测任务的状态，
   * 并根据返回数据动态调整 UI（状态栏、进度条、历史区等）。
   * 包含准备阶段、检测阶段和空闲阶段的不同渲染逻辑。
   *
   * @async
   * @returns {Promise<void>} 异步操作，无返回值
   *
   * @example
   * // 在初始化时调用，开始状态轮询
   * await loadStatus();
   */
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

      let realStartTime = null;
      if (checking && lastLogLines && lastLogLines.length > 0) {
        realStartTime = findActiveTaskStartTime(lastLogLines);
      }
      // 如果日志里没找到（比如日志被截断），但内存里有记录（checkStartTime），则用内存的
      if (!realStartTime && checkStartTime) {
        realStartTime = checkStartTime;
      }

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
        const processed = d.progress || 0;

        // ==================== 阶段 1: 准备阶段 (Progress = 0) ====================
        if (processed === 0) {
          updateToggleUI('preparing');
          showProgressUI(false); // 隐藏进度条，保留 History 面板

          // 1. 更新状态栏 (只显示简略信息)
          if (els.statusEl) {
            els.statusEl.innerHTML = `${STATUS_SPINNER}<span>正在解析订阅...</span>`;
            els.statusEl.className = 'muted status-label status-prepare';
          }

          // 2. 解析日志数据
          const stats = parseSubStats(lastLogLines);

          // 3. 渲染到历史表格 (Local/Remote...)
          renderPrepareToHistory(stats);

        }
        // ==================== 阶段 2: 检测阶段 (Progress > 0) ====================
        else {
          updateToggleUI('checking');
          showProgressUI(true); // 隐藏 History 面板，显示进度条

          // 恢复标题 (为下次显示做准备)
          restoreHistoryTitle();

          // updateProgress 会接管 StatusEl 的倒计时显示
          updateProgress(d.proxyCount || 0, d.progress || 0, d.available || 0, true, lastChecked, lastCheckInfo, realStartTime);

          hideLastCheckResult(); // 确保 History 隐藏

          // 确保内存变量同步，防止下次循环丢失
          if (realStartTime && !checkStartTime) checkStartTime = realStartTime;
        }

        if (!checkStartTime) checkStartTime = Date.now();

      } else {
        // ==================== 空闲状态 ====================
        showProgressUI(false);
        updateToggleUI('idle');

        // 恢复标题
        restoreHistoryTitle();

        updateProgress(d.proxyCount || 0, d.progress || 0, d.available || 0, false, lastChecked, lastCheckInfo);

        // 如果是刚启动尚未有数据，清空进度条
        if (els.progressBar && (d.progress === 0 || d.proxyCount === 0)) {
          els.progressBar.value = 0;
        }

        // 显示真正的历史记录
        if (lastChecked) {
          showLastCheckResult({
            lastCheckTime: d.lastCheck.time || d.lastCheck.timestamp,
            duration: d.lastCheck.duration,
            total: d.lastCheck.total || d.proxyCount,
            available: d.lastCheck.available || d.available
          });
          checkStartTime = null;
        } else if (checkStartTime && lastCheckInfo) {
          // 内存中的最后一次
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

  /**
   *增量载入日志
   *
   * @param {*} IntervalRun
   * @return {*} 
   */
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

  /**
   * 格式化秒数为易读字符串
   */
  function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '...';
    if (seconds > 3600) {
      const h = Math.floor(seconds / 3600);
      const m = Math.round((seconds % 3600) / 60);
      return `${h}小时 ${m}分`;
    } else if (seconds >= 60) {
      return Math.round(seconds / 60) + '分钟';
    } else {
      return Math.floor(seconds) + '秒';
    }
  }


  /**
   *更新进度条
   *
   * @param {*} total
   * @param {*} processed
   * @param {*} available
   * @param {*} checking
   * @param {*} lastChecked
   * @param {*} lastCheckData
   */
  function updateProgress(total, processed, available, checking, lastChecked, lastCheckData, serverStartTime = null) {
    // 初始化状态对象
    if (!updateProgress.etaState) {
      updateProgress.etaState = {
        startTime: 0,
        lastUpdateUI: 0,
        lastRecordHistory: 0,
        history: [],
        cachedEtaText: '',
        isRunning: false,
        historicalRate: 0
      };
    }

    const state = updateProgress.etaState;
    const now = Date.now();

    total = Number(total) || 0;
    processed = Number(processed) || 0;

    // --- 1. 状态管理与重置 ---
    if (checking) {
      // 如果还没标记运行，或者传入了明确的服务器开始时间且与当前记录不符（纠正时间）
      if (!state.isRunning || processed === 0 || (serverStartTime && Math.abs(state.startTime - serverStartTime) > 1000)) {
        state.isRunning = true;

        // 优先使用从日志解析出的真实开始时间，否则使用当前时间
        state.startTime = serverStartTime || now;

        // 重置 UI 更新计时器，确保刷新后立即计算一次，不要等 2秒
        state.lastUpdateUI = 0;

        state.history = [];
        state.cachedEtaText = '计算中...';

        // 记录初始点: 如果是从中途恢复的，起始点就是 {t: start, c: 0}
        state.history.push({ t: state.startTime, c: 0 });

        state.historicalRate = 0;
        if (lastCheckData && lastCheckData.total > 0 && lastCheckData.duration > 0) {
          state.historicalRate = lastCheckData.total / lastCheckData.duration;
        }
      }
    } else if (!checking) {
      state.isRunning = false;
      state.startTime = 0;
      state.history = [];
    }

    // --- 2. 记录历史数据 ---
    if (state.isRunning && checking) {
      if (now - state.lastRecordHistory > 500) {
        state.history.push({ t: now, c: processed });
        state.lastRecordHistory = now;
        // 保留最近 30 秒
        const threshold = now - 60000;
        while (state.history.length > 0 && state.history[0].t < threshold) {
          state.history.shift();
        }
      }
    }

    // --- 3. 基础 UI 更新 ---
    const pct = total > 0 ? Math.min(100, (processed / total) * 100) : 0;
    if (els.progressBar) els.progressBar.value = pct;
    if (els.progressText) els.progressText.textContent = `${processed}/${total}`;
    if (els.progressPercent) els.progressPercent.textContent = pct.toFixed(1) + "%";

    if (els.successTitle) els.successTitle.textContent = '可用：';
    if (els.successText) {
      els.successText.classList.add("success-highlight");
      els.successText.textContent = available;
    }

    // --- 4. 智能 ETA 算法 ---
    let etaText = state.cachedEtaText;

    if (checking && total > 0 && processed < total) {
      const totalTimeElapsed = now - state.startTime;

      // 如果是从日志恢复的时间，totalTimeElapsed 可能已经很大（例如 50000ms）。
      // 此时如果不满 3000ms 的判断会自动跳过，直接进入下方的计算逻辑。
      // 这是符合预期的：中途进来不需要预热。
      // 前 3 秒强制预热，给用户一点反应时间，也避免除0
      if (totalTimeElapsed < 3000) {
        etaText = '计算中...';
        state.cachedEtaText = etaText;
      }
      // 计算期：每 1 秒刷新一次 UI
      // 这里的 2000 是刷新间隔。由于上面重置了 lastUpdateUI = 0，刷新页面后第一次必定进入此分支
      else if (now - state.lastUpdateUI > 1000) {

        // --- A. 计算实时速率 (Real-time Rate) ---
        let realTimeRate = 0;

        // 如果历史队列为空（比如刚刷新页面），或者进度很低
        // 使用 "全局平均速率" = 当前已处理量 / 总耗时
        // 这样即使刷新页面丢失了最近30秒的瞬时速度，也能立刻得到一个准确的平均速度
        if (state.history.length <= 1 || pct < 15) {
          realTimeRate = processed / (totalTimeElapsed / 1000);
        } else {
          // 阶段二：使用滑动窗口 (Last 30s)
          const startPoint = state.history[0];
          const winTime = (now - startPoint.t) / 1000;
          const winCount = processed - startPoint.c;
          if (winTime > 0) realTimeRate = winCount / winTime;
        }

        // --- B. 融合历史数据 ---
        let finalRate = realTimeRate;

        // 只有当存在有效的历史数据时，才启用高级算法
        if (state.historicalRate > 0) {

          // === 策略 1: 冷启动保守阶段 (< 15%) ===
          if (pct < 15) {
            // 如果实时速率 > 历史速率 (看起来比以前快)，我们认为是“假快”或预热假象。
            // 此时强制使用较慢的历史速率，这样算出来的 ETA 会更长（更保守）。
            if (realTimeRate > state.historicalRate) {
              finalRate = state.historicalRate;
            }
            // 如果实时速率 < 历史速率 (真的卡)，那就用实时的，如实反映慢速。
            else {
              finalRate = realTimeRate;
            }
          }

          // === 策略 2: 巡航加权阶段 (>= 15%) ===
          else {
            // 计算权重 w (代表实时速率的权重)
            // 15% 时 w=0.3 (30%信实时, 70%信历史) -> 平滑过渡
            // 100% 时 w=1.0 (100%信实时)
            let w = 0.3 + ((pct - 15) / 85) * 0.7;

            // 限制范围
            w = Math.min(1, Math.max(0, w));

            finalRate = (realTimeRate * w) + (state.historicalRate * (1 - w));
          }
        }

        // --- C. 计算最终时间 ---
        if (finalRate > 0) {
          const remaining = total - processed;
          const etaSeconds = remaining / finalRate;
          etaText = formatDuration(etaSeconds);
        }

        state.cachedEtaText = etaText;
        state.lastUpdateUI = now;
      }
    } else {
      etaText = '';
    }

    // --- 5. 状态栏文字更新 ---
    if (els.statusEl) {
      if (checking) {
        const runSec = Math.floor((now - state.startTime) / 1000);
        els.statusEl.title = `已运行: ${runSec}s`;

        if (processed === 0) {
          // 刚启动，正在下载订阅文件
          els.statusEl.textContent = "正在获取订阅...";
          els.statusEl.className = 'muted status-label status-prepare';

        } else if (etaText === '计算中...') {
          // 已开始处理，但 ETA 未算出
          els.statusEl.innerHTML = `${checking_SPINNER}<span>已启动, 计算剩余时间...</span>`;
          els.statusEl.className = 'muted status-label status-calculating';
        } else if (!etaText) {
          els.statusEl.innerHTML = `<span>正在处理检测结果...</span>`;
          els.statusEl.className = 'muted status-label status-prepare';
        } else {
          // 正常显示倒计时
          els.statusEl.innerHTML = `${checking_SPINNER}<span>运行中, 预计剩余: ${etaText}</span>`;
          els.statusEl.className = 'muted status-label status-checking';
        }

      } else if (lastChecked || (processed >= total && total > 0)) {
        // 检测完成
        els.statusEl.textContent = '检测完成';
        els.statusEl.title = '';
        els.statusEl.className = 'muted status-label status-logged';

      } else {
        // 空闲状态
        els.statusEl.textContent = '空闲';
        els.statusEl.title = '';
        els.statusEl.className = 'muted status-label status-idle';
      }
    }
  }

  // ==================== 界面辅助函数 ====================

  /**
   *显示隐藏进度信息
   *
   * @param {*} visible
   */
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


  /**
   * 根据传入信息，显示历史检测结果
   *
   * @param {*} info 
   */
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

        // 计算友好显示文本（时间格式化、时长格式化等）
        const prettyTime = (() => {
          try {
            const dt = info.lastCheckTime ? new Date(String(info.lastCheckTime).replace(' ', 'T')) : null;
            return dt && !isNaN(dt) ? dt.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : (info.lastCheckTime || '-');
          } catch (e) { return info.lastCheckTime || '未知'; }
        })();
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

  /**
   *隐藏上次检测结果
   *
   */
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


  /**
   * 解析日志并格式化
   * 
   * 支持 Key=Value 高亮，= 号灰色，智能识别数值、布尔值
   * @param {*} line 
   * @returns {string} 
   */
  function colorize(line) {
    // 1. 切分时间戳
    const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
    let timestamp = '';
    let body = line;

    if (tsMatch) {
      timestamp = tsMatch[0];
      body = line.slice(timestamp.length);
    }

    // 2. 基础转义
    let out = escapeHtml(body);

    // 颜色定义
    const colorKey = '#a18248ff'; // Key 金色
    const colorEq = '#666666';    // = 灰色
    const colorNum = '#40a1efff'; // 数字蓝
    const colorCheckNum = '#5cb3d5ff';

    // 生成 URL HTML
    const formatUrl = (url) => {
      // 样式：淡青色 + 下划线
      return `<span style="color: #56b6c2; text-decoration: underline; cursor: pointer;">${url}</span>`;
    };

    // ==================== Step 2.1: 通用 Key=Value 处理 ====================
    // 使用 [^&"\s\\]，排除反斜杠
    // const combinedRegex = /([a-zA-Z0-9\u4e00-\u9fa5\-\._:]+)(=)(&quot;(?:\\&quot;|[^&]|&(?!quot;))*&quot;)|([a-zA-Z0-9\u4e00-\u9fa5\-\._:]+)(=)(?!&quot;)([^\s]+)|(\\?&quot;(https?:\/\/[^&"\s\\]+)\\?&quot;)/g;

    // 使用 [^&"\s\\]，排除反斜杠，支持:总计[去重]=123 \[\]]+
    const combinedRegex = /([a-zA-Z0-9\u4e00-\u9fa5\-\._:\[\]]+)(=)(&quot;(?:\\&quot;|[^&]|&(?!quot;))*&quot;)|([a-zA-Z0-9\u4e00-\u9fa5\-\._:\[\]]+)(=)(?!&quot;)([^\s]+)|(\\?&quot;(https?:\/\/[^&"\s\\]+)\\?&quot;)/g;


    out = out.replace(combinedRegex, (match, k1, eq1, v1, k2, eq2, v2, v3, urlInner) => {

      // --- Case 1: 带引号的键值对 (error="...") ---
      if (k1) {
        let cleanVal = v1;
        // 在长文本内部清洗 URL (同样应用了排除反斜杠的修复)
        cleanVal = cleanVal.replace(/\\?&quot;(https?:\/\/[^&"\s\\]+)\\?&quot;/g, (m, u) => {
          return formatUrl(u);
        });

        // 样式：Key金色，值灰色斜体
        return `<span style="color:${colorKey}">${k1}</span><span style="color:${colorEq}">${eq1}</span><span style="color: #71816eff; font-style: italic;">${cleanVal}</span>`;
      }

      // --- Case 2: 普通键值对 (port=8080) ---
      else if (k2) {
        let colorVal = '#a7c2b2ff'; // 默认绿

        if (v2 === 'true') colorVal = '#00ae60ff';
        else if (v2 === 'false') colorVal = '#ff6c6c';
        else if (/^[\d\.]+$/.test(v2)) colorVal = colorNum; // 复用上方定义的数字蓝
        else if (v2.startsWith('http')) colorVal = '#9476d0cf'; // 链接灰

        return `<span style="color:${colorKey}">${k2}</span><span style="color:${colorEq}">${eq2}</span><span style="color:${colorVal}">${v2}</span>`;
      }

      // --- Case 3: 独立引用 URL (Post "http...") ---
      else if (v3) {
        return formatUrl(urlInner);
      }

      return match;
    });

    // 匹配 "数量: 123" 或 "间距: 123"
    const cnMetricsRegex = /(数量|间距)([:：])\s*(\d+)/g;

    out = out.replace(cnMetricsRegex, (match, label, colon, num) => {
      // 保持 Label 默认颜色 (跟随正文)，仅高亮数字，数字颜色与 Case 2 保持一致
      return `${label}${colon} <span style="color:${colorCheckNum}; font-weight: bold;">${num}</span>`;
    });

    // 3. ANSI 颜色代码处理
    out = out.replace(/\x1b\[([\d;]+)m/g, function (match, innerCode) {
      const codes = innerCode.split(';');
      let html = '';
      codes.forEach(code => {
        switch (code) {
          case '31': html += '<span style="color: #ff4d4f; font-weight: bold;">'; break;
          case '32': html += '<span style="color: #52c41a; font-weight: bold;">'; break;
          case '33': html += '<span style="color: #faad14; font-weight: bold;">'; break;
          case '34': html += '<span style="color: #1890ff; font-weight: bold;">'; break;
          case '36': html += '<span style="color: #13c2c2; font-weight: bold;">'; break;
          case '9': html += '<span style="text-decoration: line-through; color: #999; opacity: 0.8;">'; break;
          case '29': html += '</span>'; break;
          case '39': case '0': html += '</span></span></span>'; break;
        }
      });
      return html;
    });

    // 4. 日志级别处理
    out = out.replace(/\b(INF|INFO)\b/g, '<span class="log-info">INF</span>')
      .replace(/\b(ERR|ERROR)\b/g, '<span class="log-error">ERR</span>')
      .replace(/\b(WRN|WARN)\b/g, '<span class="log-warn">WRN</span>')
      .replace(/\b(DBG|DEBUG)\b/g, '<span class="log-debug">DBG</span>');

    // 5. 特殊日志处理
    if (/发现新版本/.test(out)) {
      out = '<div class="log-new-version">' + out.replace(/最新版本=([^\s]+)/, '最新版本=<span class="success-highlight">$1</span>') + '</div>';
    }

    // 6. 拼回时间戳
    if (timestamp) {
      out = '<span class="log-time">' + timestamp + '</span>' + out;
    }

    return out;
  }

  /**
   *从日志解析上次检测结果
   *
   * @param {*} logs
   * @return {*} 
   */
  function parseCheckResultFromLogs(logs) {
    if (!logs || !Array.isArray(logs)) return null;

    // 为了防止某些特殊对象混入，转为 String
    const lines = logs.map(String);

    let startTime = null;
    let endTime = null;
    let totalNodes = null;
    let availableNodes = null; // 使用 null 区分是“未找到”还是“数量为0”

    // 倒序遍历：从最新的日志开始往前找
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];

      // 第 1 步：首先必须找到“检测完成”的时间，否则视为该次任务未完成，忽略后面的数据
      if (!endTime) {
        if (line.includes('检测完成')) {
          const m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
          if (m) endTime = m[1];
        }
        // 如果还没找到结束时间，跳过当前循环，继续往前找，
        // 这样可以过滤掉那些“有去重数量但异常中断”的脏数据。
        continue;
      }

      // 第 2 步：找到结束时间后，寻找最近的“可用节点数量”
      if (availableNodes === null) {
        const m = line.match(/可用节点数量:\s*(\d+)/);
        if (m) {
          availableNodes = parseInt(m[1], 10);
        }
        // 必须找到可用节点后，才能去找去重节点，所以这里 continue
        continue;
      }

      // 第 3 步：找到可用节点后，寻找紧邻的“去重后节点数量”
      if (totalNodes === null) {
        const m = line.match(/去重后节点数量:\s*(\d+)/);
        if (m) {
          totalNodes = parseInt(m[1], 10);
        }
        // 必须找到去重节点后，才能去找开始时间，所以这里 continue
        continue;
      }

      // 第 4 步：所有数据都齐了，最后寻找“启动时间”
      if (!startTime) {
        if (line.includes('手动触发检测') || line.includes('启动检测任务')) {
          const m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
          if (m) {
            startTime = m[1];
            // 第 5 步：找到了开始时间，说明这一整组数据闭环了，直接退出循环
            break;
          }
        }
      }
    }

    // 校验数据完整性
    if (startTime && endTime && totalNodes !== null && availableNodes !== null) {
      const start = new Date(startTime);
      const end = new Date(endTime);
      // 计算耗时（秒），防止时间倒流出现负数
      const duration = Math.max(0, Math.round((end - start) / 1000));

      return {
        lastCheckTime: endTime,
        duration: duration,
        total: totalNodes,
        available: availableNodes
      };
    }

    return null;
  }

  // ==================== 认证与交互 ====================

  /**
   *登录按钮事件
   *
   * @return {*} 
   */
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
      els.statusEl.textContent = `${ok ? '空闲' : '未登录'}`;
      els.statusEl.className = 'muted status-label ' + (ok ? 'status-logged' : 'status-idle');
    }
    [els.toggleBtn, els.refreshLogsBtn, els.saveCfgBtn, els.searchBtn, els.reloadCfgBtn].forEach(b => b && (b.disabled = !ok));
    updateToggleUI(ok ? 'idle' : 'disabled');
  }

  /**
   *更新开始检测按钮状态，图标
   *
   * @param {*} state
   * @return {*} 
   */
  function updateToggleUI(state) {
    actionState = state;
    if (!els.toggleBtn) return;
    const config = {
      idle: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>', disabled: false, title: '开始检测', pressed: 'false' },
      starting: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 12h-2.25c0 5.5 4.25 10 9.75 10s9.75-4.5 9.75-10-4.25-10-9.75-10-9.75 4.5-9.75 10zM12 7.5v9"/></svg>', disabled: true, title: '正在开始', pressed: 'true' },
      preparing: {
        // 使用云端下载图标
        icon: '<svg class="prefix__prefix__icon" viewBox="0 0 1024 1024" width="200" height="200"><path d="M547.84 515.67a52.907 52.907 0 01-74.837 0L313.6 356.266a52.48 52.48 0 010-75.094 52.907 52.907 0 0174.923 0l68.437 68.694V53.163a52.992 52.992 0 11106.24 0v296.704l69.12-68.694a52.907 52.907 0 0174.837 0 52.48 52.48 0 010 75.094L547.84 515.669zM329.557 531.2H85.077A53.504 53.504 0 0032 584.363v371.882c0 29.27 24.32 53.078 53.163 53.078H935.68a53.504 53.504 0 0053.163-53.078V584.363A53.504 53.504 0 00935.68 531.2H691.883c-26.283 0-46.763 24.49-50.006 50.688-5.717 46.677-32 108.63-131.84 108.63-99.157 0-124.757-61.697-130.56-108.374-3.157-26.368-23.637-50.944-49.92-50.944z" fill="currentColor"/></svg>',
        disabled: false,
        title: '正在获取订阅 - 点击停止',
        pressed: 'true'
      },
      checking: { icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h12v12H6z"/></svg>', disabled: false, title: '检测中 - 点击停止', pressed: 'true' },
      stopping: { icon: '<svg viewBox="0 0 1024 1024" width="200" height="200" fill="currentColor"><path d="M834.4 92H189.6c-13.6 0-24-11.2-24-24 0-13.6 11.2-24 24-24h644.8c13.6 0 24 11.2 24 24 .8 12.8-10.4 24-24 24zm32 900.8h-708c-14.4 0-26.4-12-26.4-26.4 0-14.4 12-26.4 26.4-26.4h708c14.4 0 26.4 12 26.4 26.4 0 14.4-12 26.4-26.4 26.4z"/><path d="M766.4 666.4l-.8-1.6c-40.8-71.2-95.2-117.6-152.8-145.6 57.6-28.8 111.2-74.4 152.8-145.6l.8-1.6c40.8-70.4 68-166.4 72.8-294.4H792C788 196 763.2 284 725.6 348.8l-.8.8C678.4 432 626.4 476 559.2 496.8l-3.2.8h-.8c-1.6.8-2.4 1.6-4 2.4l-.8.8-1.6 1.6-1.6 1.6v.8c-.8.8-1.6 2.4-2.4 4l-.8.8-1.6 5.6v8.8l1.6 5.6.8.8c.8 1.6 1.6 2.4 2.4 4v.8l1.6 1.6v-.8l1.6.8.8.8c.8.8 2.4 1.6 4 2.4h.8l3.2 1.6c68 21.6 119.2 64.8 166.4 146.4l.8 1.6c20 33.6 35.2 74.4 47.2 121.6 2.4 13.6 11.2 43.2 12.8 81.6-37.6-33.6-141.6-57.6-266.4-59.2V464c1.6 0 2.4-.8 4-1.6v-.8l6.4-2.4h1.6c45.6-14.4 81.6-36.8 112-66.4 32-32 56.8-71.2 73.6-115.2 4.8-12-.8-25.6-13.6-30.4-12-4.8-25.6.8-30.4 12.8v.8c-14.4 36.8-35.2 71.2-62.4 98.4-24.8 24-54.4 43.2-92 54.4l-.8.8-2.4.8-4 .8-2.4-.8-1.6-.8-2.4-.8c-36.8-12-68-30.4-92-54.4-28-27.2-48-60.8-62.4-98.4-4.8-12-18.4-18.4-29.6-13.6-12 4.8-17.6 17.6-13.6 30.4 16.8 44 40.8 83.2 73.6 115.2 29.6 29.6 66.4 52 111.2 66.4h.8l6.4 2.4 1.6.8c.8.8 1.6.8 3.2 1.6v369.6c-116.8 0-218.4 20-266.4 48 1.6-19.2 5.6-40 12.8-70.4 12-48 28-88 47.2-121.6l.8-1.6c47.2-81.6 98.4-124.8 167.2-146.4l2.4-1.6h.8c1.6-.8 2.4-1.6 4-2.4l.8-.8 1.6-.8v-.8l1.6-1.6v-.8c.8-.8 1.6-2.4 2.4-4v-.8c.8-1.6 1.6-4 1.6-5.6v-8c0-1.6-.8-4-1.6-5.6v-.8c-.8-1.6-1.6-3.2-2.4-4v-.8l-1.6-1.6-1.6-1.6-2.4.8c-1.6-.8-2.4-1.6-4-2.4h-.8l-2.4-.8c-68-20.8-120-64.8-167.2-147.2l-.8-.8c-36.8-64.8-61.6-152.8-66.4-271.2h-47.2c4.8 128 32 223.2 72.8 294.4l.8 1.6C297.6 445.6 352 491.2 409.6 520c-57.6 28-111.2 74.4-152.8 145.6l-.8 1.6c-38.4 67.2-65.6 156.8-71.2 276h652.8c-5.6-120-32-209.6-71.2-276.8z"/></svg>', disabled: true, title: '正在结束', pressed: 'true' },
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

  /**
   * 获取 sub-store 配置，主要包括 sub-store 路径和端口。
   *
   * @async
   * @returns {Object} 配置对象
   * @returns {string} returns.subStorePath sub-store 的路径
   * @returns {string|number} returns.portStr sub-store 的端口号
   *
   * @throws {Error} 当配置读取失败时抛出异常
   *
   * @example
   * const cfg = await fetchSubStoreConfig();
   * console.log(cfg.subStorePath,cfg.subStorePathYaml, cfg.portStr);
   */
  async function fetchSubStoreConfig() {
    const r = await sfetch(API.config);
    if (!r.ok) throw new Error("读取配置失败");
    const config = YAML.parse(r.payload?.content ?? '');
    return {
      subStorePath: r.payload?.sub_store_path ?? '',
      subStorePathYaml: config["sub-store-path"],
      portStr: config["sub-store-port"]
    };
  }

  /**
   * 构建 Sub-Store 访问 URL
   * @param {Object} config 配置对象
   * @param {string} config.subStorePath sub-store 路径
   * @param {string|number} config.portStr sub-store 端口
   * @returns {Object} 包含完整 URL 和 subStorePath
   */
  function buildSubStoreUrl(config) {
    const { subStorePath, subStorePathYaml, portStr } = config;
    if (!subStorePath) throw new Error("配置中未找到 sub_store_path");
    if (!subStorePathYaml || subStorePathYaml == '') showToast("您未设置sub-store-path，当前使用随机值。请尽快设置！", "warn")

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
      // 防止 IP 地址访问时生成错误的域名 (如: sub_store.104.56.43.43)
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
      if (parts.length > 1 && !isIp) {
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

  /**
   * 打开并处理 Sub-Store 管理窗口
   * @param {Event} e 点击事件对象
   * @returns {Promise<void>} 异步操作，无返回值
   */
  async function handleOpenSubStore(e) {
    e.preventDefault();
    if (!sessionKey) { showLogin(true); return; }

    const newWindow = window.open('', '_blank');
    if (!newWindow) { showToast('窗口弹出被拦截', 'warn'); return; }

    // 1. 设置初始 Loading 界面
    newWindow.document.title = "正在连接 Sub-Store...";
    newWindow.document.body.style.margin = "0";
    newWindow.document.body.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9f9f9;color:#333;">
        <div style="margin-bottom:15px;">
           <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#0ea5a0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>
           <style>.spin{animation:spin 1s linear infinite}@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>
        </div>
        <h3 id="status-text" style="font-weight:600;">正在跳转...</h3>
        <p style="color:#666;font-size:13px;margin-top:5px;">正在解析 sub-store 配置并构建连接，请稍候。</p>
      </div>
    `;

    // 2. 启动超时控制 (10秒)
    let isFinished = false;
    const timeoutTimer = setTimeout(() => {
      if (isFinished) return;
      isFinished = true; // 标记超时
      console.warn("SubStore跳转超时");
      if (newWindow && !newWindow.closed) {
        newWindow.document.body.innerHTML = `
          <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;">
            <h3 style="color:#ff4d4f;">连接超时</h3>
            <p style="color:#666;margin-bottom:20px;">获取 sub-store 配置耗时过长，请关闭重试。</p>
            <button onclick="window.close()" style="padding:8px 20px;cursor:pointer;background:#fff;border:1px solid #ccc;border-radius:4px;">关闭窗口</button>
          </div>
        `;
      }
    }, 10000);

    try {
      let configData = _cachedSubStoreConfig;
      if (!configData) {
        // 如果超时了，就不要再更新文字了
        if (!isFinished && newWindow && !newWindow.closed) {
          const statusEl = newWindow.document.getElementById('status-text');
          els.statusEl.innerHTML = `${STATUS_SPINNER}<span>正在获取 sub-store 配置...</span>`;
        }

        configData = await fetchSubStoreConfig();

        // 获取数据后，必须再次检查是否已超时
        if (isFinished) return;

        _cachedSubStoreConfig = configData;
      }

      const result = buildSubStoreUrl(configData);
      lastSubStorePath = result.subStorePath;

      // 先清理定时器并标记结束，再执行跳转
      if (isFinished) return;
      isFinished = true;
      clearTimeout(timeoutTimer);

      newWindow.location.href = result.url;

    } catch (err) {
      console.error(err);

      // 如果已经超时处理过了，就不再处理错误
      if (isFinished) return;
      isFinished = true;
      clearTimeout(timeoutTimer);

      // 优先在窗口内显示错误，不要急着 close()
      if (newWindow && !newWindow.closed) {
        newWindow.document.title = "错误";
        newWindow.document.body.innerHTML = `
          <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;padding:20px;text-align:center;">
            <h3 style="color:#ff4d4f;margin-bottom:10px;">发生错误</h3>
            <p style="color:#333;background:#ffebeb;padding:10px;border-radius:5px;font-family:monospace;">${err.message || '未知错误'}</p>
            <p style="color:#999;font-size:12px;margin-top:10px;">请检查网络或后端日志</p>
            <button onclick="window.close()" style="margin-top:20px;padding:8px 20px;cursor:pointer;border:1px solid #d9d9d9;background:#fff;border-radius:4px;">关闭</button>
          </div>
        `;
      } else {
        // 只有窗口意外关闭了，才用 Toast
        showToast(err.message || '打开失败', 'error');
      }
    }
  }

  /**
   * 获取分享链接的 Base URL
   * @param {string} path 路径
   * @param {string|number} port 端口号
   * @returns {Promise<string>} 可用的 Base URL
   */
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

    const normalizedTxt = (txt || '').replace(/\r\n/g, '\n');
    const currentContent = codeMirrorView.state.doc.toString();

    // 内容相同直接返回
    if (currentContent === normalizedTxt) {
      return;
    }

    codeMirrorView.dispatch({
      changes: {
        from: 0,
        to: codeMirrorView.state.doc.length,
        insert: normalizedTxt
      },
      scrollIntoView: false
    });

    showToast(
      txt === '' ? '配置已清除' : '配置已加载',
      txt === '' ? 'warn' : 'success'
    );
  }

  async function loadConfigValidated() {
    if (!sessionKey) return;
    const r = await sfetch(API.config);
    if (!r.ok) return showToast('读取配置失败', 'warn');
    const raw = (typeof r.payload?.content === 'string') ? r.payload.content : String(r.payload || '');
    codeMirrorView ? setEditorContent(raw) : initCodeMirror(raw);
    if (codeMirrorView?.scrollDOM) {
      codeMirrorView.scrollDOM.scrollTop = 0;
    }
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
          // ==================== 停止逻辑 ====================
          updateToggleUI('stopping');
          showToast('正在停止...', 'info');
          await sfetch(API.forceClose, { method: 'POST' });
          const confirm = await waitForBackendChecking(false);
          if (confirm.ok) showToast('检测已停止', 'success');
        } else {
          // ==================== 启动逻辑 ====================
          updateToggleUI('starting');

          // 点击启动时，强制隐藏进度条，保持显示历史记录
          showProgressUI(false);

          // 立即更新状态栏，给用户“已响应”的反馈 (利用之前定义的 STATUS_SPINNER)
          if (els.statusEl) {
            // 如果 STATUS_SPINNER 变量在作用域内可用
            if (typeof STATUS_SPINNER !== 'undefined') {
              els.statusEl.innerHTML = `<span>正在启动任务...</span>`;
            } else {
              els.statusEl.textContent = "正在启动任务...";
            }
            els.statusEl.className = 'muted status-label status-prepare';
          }

          checkStartTime = Date.now();
          showToast('启动中...', 'info');

          await sfetch(API.trigger, { method: 'POST' });
          const confirm = await waitForBackendChecking(true);

          if (confirm.ok) {
            // 后端确认启动后，转为 preparing 状态
            // 具体的 UI (显示历史还是进度条) 交给 loadStatus 的轮询去自动修正
            updateToggleUI('preparing');
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

    // 绑定编辑器搜索按钮事件
    searchBtn?.addEventListener('click', () => {
      if (window.searchView && searchPanelOpen(window.searchView.state)) {
        closeSearchPanel(window.searchView);
      } else if (window.searchView) {
        openSearchPanel(window.searchView);
      }
    });
    els.saveCfgBtn?.addEventListener('click', saveConfigWithValidation);
    els.reloadCfgBtn?.addEventListener('click', async () => {
      await loadConfigValidated();
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
        els.showApikeyBtn.classList.toggle('active', isPwd);
      });
    }

    const applyTheme = (t) => {
      document.documentElement.setAttribute('data-theme', t);
      if (els.iconMoon) els.iconMoon.style.display = t === 'dark' ? '' : 'none';
      if (els.iconSun) els.iconSun.style.display = t === 'light' ? '' : 'none';

      // 根据当前主题设置按钮提示
      if (els.themeToggleBtn) {
        els.themeToggleBtn.title = t === 'dark' ? '切换到浅色模式' : '切换到深色模式';
      }

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

    els.themeToggleBtn?.addEventListener('dblclick', () => {
      safeLS('theme', null);
      const sys = window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      applyTheme(sys);
      showToast('主题已重置为系统默认', 'info');
    });

    // 分享菜单逻辑
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
          const SubStorePathYaml = config["sub-store-path"] ?? "";
          if (!subStorePath) return showToast('请先设置 sub_store_path', 'error');
          if (!SubStorePathYaml || SubStorePathYaml == '') showToast("您未设置sub-store-path，当前使用随机值。请尽快设置！", "warn");

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
          menu.style.transform = "none";
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

    els.githubMenuBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const GITHUB_REPO_URL = 'https://github.com/sinspired/subs-check';
      window.open(GITHUB_REPO_URL, '_blank', 'noopener,noreferrer');
    });

    els.dockerMenuBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const DOCKER_URL = 'https://hub.docker.com/r/sinspired/subs-check';
      window.open(DOCKER_URL, '_blank', 'noopener,noreferrer');
    });

    els.telegramMenuBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const TELEGRAM_URL = 'https://t.me/subs_check_pro';
      window.open(TELEGRAM_URL, '_blank', 'noopener,noreferrer');
    });

    // footer 项目地址
    els.githubUrlBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const GITHUB_REPO_URL = 'https://github.com/sinspired/subs-check';
      window.open(GITHUB_REPO_URL, '_blank', 'noopener,noreferrer');
    });

    els.dockerUrlBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const DOCKER_URL = 'https://hub.docker.com/r/sinspired/subs-check';
      window.open(DOCKER_URL, '_blank', 'noopener,noreferrer');
    });

    els.telegramUrlBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const TELEGRAM_URL = 'https://t.me/subs_check_pro';
      window.open(TELEGRAM_URL, '_blank', 'noopener,noreferrer');
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