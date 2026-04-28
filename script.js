/**
 * VulnScanner — Security Operations Dashboard  |  script.js v3
 * Handles: clock, API health, scan lifecycle, overlay,
 *          KPI cards, activity feed, result display, log table
 */

// ── Config ─────────────────────────────────────────────────────
const API_BASE = 'http://localhost:3000';

const SQL_PAYLOADS = ["' OR '1'='1","admin' --","' OR 1=1 --","1; DROP TABLE users--","' UNION SELECT null--"];
const XSS_PAYLOADS = ["<script>alert('xss')</script>","<img src=x onerror=alert(1)>","'\"><svg onload=alert(1)>","<body onload=alert('XSS')>"];

// ── DOM ─────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const targetUrl      = $('targetUrl');
const protocolSelect = $('protocolSelect');
const clearBtn       = $('clearBtn');
const btnSQL         = $('btnSQL');
const btnXSS         = $('btnXSS');
const resultZone     = $('resultZone');
const resultEmpty    = $('resultEmpty');
const logPanel       = $('logPanel');
const logTableBody   = $('logTableBody');
const logTotalBadge  = $('logTotalBadge');
const logClearBtn    = $('logClearBtn');
const logExportBtn   = $('logExportBtn');
const activityFeed   = $('activityFeed');
const scanOverlay    = $('scanOverlay');

// KPIs
const kpiTotalScans = $('kpiTotalScans');
const kpiVulns      = $('kpiVulns');
const kpiClean      = $('kpiClean');
const kpiAvgTime    = $('kpiAvgTime');
const tbScans       = $('tbScans');
const tbVulns       = $('tbVulns');

// Overlay
const overlayBadge        = $('overlayBadge');
const overlayTarget       = $('overlayTarget');
const overlayStatus       = $('overlayStatus');
const overlayProgressFill = $('overlayProgressFill');
const overlayProgressText = $('overlayProgressText');
const overlayPct          = $('overlayPct');
const stText              = $('stText');

// ── State ───────────────────────────────────────────────────────
let isScanning    = false;
let sessionStart  = Date.now();
let stats = { scans: 0, vulns: 0, clean: 0, totalMs: 0, logRows: 0 };
let scanTimes     = [];
let progressTimer = null;
let typeTimer     = null;

// ── Clock ───────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  const pad = n => String(n).padStart(2,'0');
  $('topbarClock').textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

  // Session duration
  const elapsed = Math.floor((Date.now() - sessionStart) / 1000);
  const mm = Math.floor(elapsed / 60), ss = elapsed % 60;
  $('sessionDur').textContent = `${pad(mm)}:${pad(ss)}`;
}
updateClock();
setInterval(updateClock, 1000);

// ── API Health ──────────────────────────────────────────────────
async function checkHealth() {
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    setApiOnline(r.ok);
  } catch { setApiOnline(false); }
}

function setApiOnline(online) {
  const dot   = $('apiDot');
  const label = $('apiLabel');
  const eng   = $('statusApiEngine');

  dot.className = 'api-dot ' + (online ? 'online' : 'offline');
  label.textContent = online ? 'API Online' : 'API Offline';
  label.style.color = online ? 'var(--green)' : 'var(--red)';

  eng.innerHTML = online
    ? '<span class="sr-dot sr-dot--ok"></span>Connected'
    : '<span class="sr-dot sr-dot--warn"></span>Offline';
}

checkHealth();
setInterval(checkHealth, 30000);

// ── URL Validation ──────────────────────────────────────────────
function getFullUrl() {
  const proto = protocolSelect.value;
  const host  = targetUrl.value.trim();
  if (!host) return null;
  if (host.startsWith('http://') || host.startsWith('https://')) return host;
  return proto + host;
}

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

function syncButtons() {
  const ok = isValidUrl(getFullUrl() || '');
  btnSQL.disabled = !ok || isScanning;
  btnXSS.disabled = !ok || isScanning;
}

targetUrl.addEventListener('input', syncButtons);
protocolSelect.addEventListener('change', syncButtons);
clearBtn.addEventListener('click', () => {
  targetUrl.value = '';
  syncButtons();
  showEmpty();
});

// ── KPI updater ─────────────────────────────────────────────────
function updateKPIs() {
  const avg = scanTimes.length ? Math.round(scanTimes.reduce((a,b)=>a+b,0) / scanTimes.length) : null;

  // Animate count-up
  countUp(kpiTotalScans, stats.scans);
  countUp(kpiVulns,  stats.vulns);
  countUp(kpiClean,  stats.clean);
  kpiAvgTime.textContent = avg ? avg + 'ms' : '—';
  tbScans.textContent    = stats.scans;
  tbVulns.textContent    = stats.vulns;

  // Threat level
  updateThreatLevel();
}

function countUp(el, target) {
  const current = parseInt(el.textContent, 10) || 0;
  if (current === target) return;
  let frame = 0;
  const steps = 12;
  const inc = (target - current) / steps;
  const iv = setInterval(() => {
    frame++;
    el.textContent = Math.round(current + inc * frame);
    if (frame >= steps) { el.textContent = target; clearInterval(iv); }
  }, 30);
}

function updateThreatLevel() {
  const ratio = stats.scans ? stats.vulns / stats.scans : 0;
  const segs  = document.querySelectorAll('.tg-segment');
  const txt   = $('threatLevelText');
  segs.forEach(s => s.classList.remove('active-seg'));

  if (ratio === 0 && stats.scans === 0) {
    txt.textContent = 'LOW'; txt.style.color = 'var(--green)';
  } else if (ratio < 0.25) {
    segs[0].classList.add('active-seg');
    txt.textContent = 'LOW'; txt.style.color = 'var(--green)';
  } else if (ratio < 0.5) {
    segs[0].classList.add('active-seg'); segs[1].classList.add('active-seg');
    txt.textContent = 'MEDIUM'; txt.style.color = 'var(--amber)';
  } else if (ratio < 0.75) {
    segs[0].classList.add('active-seg'); segs[1].classList.add('active-seg'); segs[2].classList.add('active-seg');
    txt.textContent = 'HIGH'; txt.style.color = 'var(--red)';
  } else {
    segs.forEach(s => s.classList.add('active-seg'));
    txt.textContent = 'CRITICAL'; txt.style.color = '#ff0033';
  }
}

// ── Activity Feed ───────────────────────────────────────────────
function addActivity(type, msg) {
  // Remove empty placeholder
  const empty = activityFeed.querySelector('.af-empty');
  if (empty) empty.remove();

  const dotClass = { vuln:'af-dot--vuln', clean:'af-dot--clean', err:'af-dot--err', info:'af-dot--info' }[type] || 'af-dot--info';
  const item = document.createElement('div');
  item.className = 'af-item';
  item.innerHTML = `
    <div class="af-dot ${dotClass}"></div>
    <div class="af-body">
      <div class="af-msg">${esc(msg)}</div>
      <div class="af-time">${new Date().toLocaleTimeString()}</div>
    </div>
  `;
  activityFeed.prepend(item);

  // Cap feed at 30 items
  while (activityFeed.children.length > 30) activityFeed.lastChild.remove();
}

// ── Scan Overlay ────────────────────────────────────────────────
function showOverlay(type, url, payloads) {
  overlayBadge.textContent  = type === 'sql' ? 'SQL INJECTION' : 'XSS INJECTION';
  overlayTarget.textContent = url;
  overlayStatus.textContent = 'Establishing connection…';
  overlayProgressFill.style.width = '0%';
  overlayProgressText.textContent = `0 / ${payloads.length} payloads`;
  overlayPct.textContent = '0%';
  stText.textContent = '';
  scanOverlay.classList.add('active');

  runSimulatedProgress(payloads);
}

function hideOverlay() {
  scanOverlay.classList.remove('active');
  clearInterval(progressTimer);
  clearInterval(typeTimer);
}

function runSimulatedProgress(payloads) {
  clearInterval(progressTimer);
  let idx = 0;
  const total = payloads.length;
  tick(0, total, payloads[0]);

  progressTimer = setInterval(() => {
    idx++;
    if (idx >= total) { clearInterval(progressTimer); overlayStatus.textContent = 'Analysing responses…'; return; }
    tick(idx, total, payloads[idx]);
  }, 950);
}

function tick(idx, total, payload) {
  const pct = Math.round(((idx + 1) / total) * 88);
  overlayProgressFill.style.width = pct + '%';
  overlayProgressText.textContent = `${idx + 1} / ${total} payloads`;
  overlayPct.textContent = pct + '%';
  overlayStatus.textContent = `Injecting payload ${idx + 1} of ${total}…`;
  typewrite(payload);
}

function typewrite(text) {
  clearInterval(typeTimer);
  stText.textContent = '';
  let i = 0;
  typeTimer = setInterval(() => {
    if (i < text.length) { stText.textContent += text[i++]; }
    else { clearInterval(typeTimer); }
  }, 24);
}

// ── Core Scan ───────────────────────────────────────────────────
async function runScan(type) {
  if (isScanning) return;
  const url = getFullUrl();
  if (!url || !isValidUrl(url)) { renderError('Please enter a valid URL before scanning.'); return; }

  const endpoint = type === 'sql' ? '/scan/sql' : '/scan/xss';
  const btn      = type === 'sql' ? btnSQL : btnXSS;
  const payloads = type === 'sql' ? SQL_PAYLOADS : XSS_PAYLOADS;

  isScanning = true;
  btn.classList.add('loading');
  btnSQL.disabled = btnXSS.disabled = true;
  clearResult();
  showOverlay(type, url, payloads);
  addActivity('info', `Scan initiated — ${type.toUpperCase()} against ${trunc(url, 48)}`);

  const t0 = Date.now();

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(60000),
    });

    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.message || `HTTP ${res.status}`);
    }

    const data = await res.json();
    const elapsed = Date.now() - t0;
    scanTimes.push(elapsed);

    // Complete the bar
    overlayProgressFill.style.width = '100%';
    overlayPct.textContent = '100%';
    overlayStatus.textContent = 'Scan complete.';
    await pause(350);
    hideOverlay();

    // Stats
    stats.scans++;
    if (data.result === 'vulnerable') { stats.vulns++; updateThreatLevel(); }
    else if (data.result === 'not_vulnerable') stats.clean++;
    updateKPIs();

    // Render
    renderResult(data, elapsed);

    // Activity
    const verb = data.result === 'vulnerable' ? '⚠ VULNERABLE' : data.result === 'not_vulnerable' ? '✓ SECURE' : 'ERROR';
    const actType = data.result === 'vulnerable' ? 'vuln' : data.result === 'not_vulnerable' ? 'clean' : 'err';
    addActivity(actType, `${type.toUpperCase()} scan — ${verb} — ${trunc(url, 38)} (${elapsed}ms)`);

    // Log
    if (data.findings?.length) appendLog(data.findings, data.scanType, url);

  } catch (err) {
    await pause(200);
    hideOverlay();
    const msg = err.name === 'TimeoutError' ? 'Request timed out — check backend connection.' : (err.message || 'Unknown error');
    renderError(msg);
    addActivity('err', `Scan failed — ${msg}`);
  } finally {
    isScanning = false;
    btn.classList.remove('loading');
    syncButtons();
  }
}

btnSQL.addEventListener('click', () => runScan('sql'));
btnXSS.addEventListener('click', () => runScan('xss'));
targetUrl.addEventListener('keydown', e => { if (e.key === 'Enter' && !btnSQL.disabled) runScan('sql'); });

// ── Result rendering ────────────────────────────────────────────
function clearResult() {
  resultZone.querySelectorAll('.result-card').forEach(el => el.remove());
  if (resultEmpty) resultEmpty.style.display = 'none';
}

function showEmpty() {
  clearResult();
  if (resultEmpty) resultEmpty.style.display = '';
}

function renderResult(data, elapsed) {
  const { result, scanType, target, payloadsTested, timestamp } = data;
  const map = {
    vulnerable:     { verdict: '⚠ VULNERABLE',    badge: 'HIGH RISK', icon: '⚠' },
    not_vulnerable: { verdict: '✓ NOT VULNERABLE', badge: 'SECURE',    icon: '✓' },
  };
  const m    = map[result] || { verdict: '✕ ERROR', badge: 'FAILED', icon: '✕' };
  const time = new Date(timestamp).toLocaleTimeString();

  const card = document.createElement('div');
  card.className = `result-card ${result}`;
  card.innerHTML = `
    <div class="rc-strip"></div>
    <div class="rc-body">
      <div class="rc-header">
        <div class="rc-verdict-row">
          <div class="rc-icon">${m.icon}</div>
          <span class="rc-verdict">${m.verdict}</span>
        </div>
        <span class="rc-badge">${m.badge}</span>
      </div>
      <div class="rc-meta">
        <div class="rc-meta-item">
          <span class="rc-meta-lbl">ATTACK TYPE</span>
          <span class="rc-meta-val">${esc(scanType)}</span>
        </div>
        <div class="rc-meta-item">
          <span class="rc-meta-lbl">TARGET</span>
          <span class="rc-meta-val">${esc(trunc(target, 36))}</span>
        </div>
        <div class="rc-meta-item">
          <span class="rc-meta-lbl">PAYLOADS</span>
          <span class="rc-meta-val">${payloadsTested} tested</span>
        </div>
        <div class="rc-meta-item">
          <span class="rc-meta-lbl">ELAPSED</span>
          <span class="rc-meta-val">${elapsed ? elapsed + 'ms' : time}</span>
        </div>
      </div>
    </div>`;
  resultZone.appendChild(card);
}

function renderError(msg) {
  clearResult();
  const card = document.createElement('div');
  card.className = 'result-card error';
  card.innerHTML = `
    <div class="rc-strip"></div>
    <div class="rc-body">
      <div class="rc-header">
        <div class="rc-verdict-row">
          <div class="rc-icon">✕</div>
          <span class="rc-verdict">ERROR</span>
        </div>
        <span class="rc-badge">FAILED</span>
      </div>
      <div class="rc-meta" style="grid-template-columns:1fr">
        <div class="rc-meta-item">
          <span class="rc-meta-lbl">REASON</span>
          <span class="rc-meta-val">${esc(msg)}</span>
        </div>
      </div>
    </div>`;
  resultZone.appendChild(card);
}

// ── Log Table ───────────────────────────────────────────────────
function appendLog(findings, scanType, url) {
  logPanel.style.display = '';

  findings.forEach(f => {
    stats.logRows++;
    const cls  = f.verdict === 'vulnerable' ? 'verdict-chip--vuln' : f.verdict === 'safe' ? 'verdict-chip--clean' : 'verdict-chip--err';
    const text = f.verdict === 'vulnerable' ? 'VULN' : f.verdict === 'safe' ? 'CLEAN' : 'ERROR';
    const row  = document.createElement('tr');
    row.innerHTML = `
      <td><span class="verdict-chip ${cls}">${text}</span></td>
      <td>${esc(scanType)}</td>
      <td title="${esc(f.payload || '')}">${esc(f.payload || '—')}</td>
      <td>${esc(f.finding || '—')}</td>
      <td>${f.status ? 'HTTP ' + f.status : '—'}</td>
      <td>${new Date().toLocaleTimeString()}</td>`;
    logTableBody.prepend(row);
  });

  logTotalBadge.textContent = `${stats.logRows} entr${stats.logRows === 1 ? 'y' : 'ies'}`;
}

logClearBtn.addEventListener('click', () => {
  logTableBody.innerHTML = '';
  logPanel.style.display = 'none';
  stats.logRows = 0;
  logTotalBadge.textContent = '0 entries';
});

logExportBtn.addEventListener('click', () => {
  const rows = [...logTableBody.querySelectorAll('tr')];
  const csv  = ['VERDICT,SCAN TYPE,PAYLOAD,FINDING,HTTP,TIMESTAMP'];
  rows.forEach(r => {
    const cells = [...r.querySelectorAll('td')].map(td => `"${td.textContent.trim().replace(/"/g, '""')}"`);
    csv.push(cells.join(','));
  });
  const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `vulnscan-log-${Date.now()}.csv`;
  a.click();
});

// ── Helpers ─────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function trunc(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }
function pause(ms)   { return new Promise(r => setTimeout(r, ms)); }

// ── Init ─────────────────────────────────────────────────────────
addActivity('info', 'Dashboard initialised — session started');
updateKPIs();
