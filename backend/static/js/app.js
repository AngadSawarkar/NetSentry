/**
 * NetSentry – app.js
 * Shared utilities: sidebar, topbar, search, toast, formatters.
 */

// ============================================================
// SIDEBAR TOGGLE
// ============================================================
const sidebar     = document.getElementById('sidebar');
const mainContent = document.getElementById('main-content');
const toggleBtn   = document.getElementById('sidebar-toggle');
const mobileOverlay = document.getElementById('mobile-overlay');

function isMobile() { return window.innerWidth <= 1024; }

function openSidebar() {
  if (isMobile()) {
    sidebar.classList.add('mobile-open');
    mobileOverlay.classList.add('show');
  } else {
    sidebar.classList.remove('collapsed');
    mainContent.classList.remove('expanded');
    localStorage.setItem('ns_sidebar_collapsed', '0');
  }
}

function closeSidebar() {
  if (isMobile()) {
    sidebar.classList.remove('mobile-open');
    mobileOverlay.classList.remove('show');
  } else {
    sidebar.classList.add('collapsed');
    mainContent.classList.add('expanded');
    localStorage.setItem('ns_sidebar_collapsed', '1');
  }
}

toggleBtn.addEventListener('click', () => {
  if (isMobile()) {
    sidebar.classList.contains('mobile-open') ? closeSidebar() : openSidebar();
  } else {
    sidebar.classList.contains('collapsed') ? openSidebar() : closeSidebar();
  }
});

mobileOverlay.addEventListener('click', closeSidebar);

// Restore collapsed state on desktop
if (!isMobile() && localStorage.getItem('ns_sidebar_collapsed') === '1') {
  sidebar.classList.add('collapsed');
  mainContent.classList.add('expanded');
}

window.addEventListener('resize', () => {
  if (!isMobile()) {
    sidebar.classList.remove('mobile-open');
    mobileOverlay.classList.remove('show');
  }
});

// ============================================================
// GLOBAL STATUS UPDATER
// ============================================================
const backendDot   = document.getElementById('backend-dot');
const sensorDot    = document.getElementById('sensor-dot');
const backendLabel = document.getElementById('backend-label');
const sensorLabel  = document.getElementById('sensor-label');
const lastUpdated  = document.getElementById('last-updated');
const topbarIface  = document.getElementById('topbar-iface');

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) throw new Error('API error');
    const data = await res.json();

    const backOnline  = data.backend === 'ONLINE';
    const sensOnline  = data.sensor  === 'ONLINE';

    if (backendDot)   { backendDot.className   = 'status-dot ' + (backOnline  ? 'online' : 'offline'); }
    if (sensorDot)    { sensorDot.className    = 'status-dot ' + (sensOnline  ? 'online' : 'offline'); }
    if (backendLabel) { backendLabel.textContent = backOnline  ? 'Backend Online'  : 'Backend Offline'; }
    if (sensorLabel)  { sensorLabel.textContent  = sensOnline  ? 'Sensor Online'   : 'Sensor Offline'; }
    if (topbarIface && data.interface) { topbarIface.textContent = data.interface; }

  } catch (e) {
    if (backendDot)   { backendDot.className   = 'status-dot offline'; }
    if (backendLabel) { backendLabel.textContent = 'Backend Offline'; }
  }
  if (lastUpdated) { lastUpdated.textContent = 'Updated ' + new Date().toLocaleTimeString(); }
}

// Refresh button
const refreshBtn = document.getElementById('refresh-btn');
if (refreshBtn) {
  refreshBtn.addEventListener('click', () => {
    refreshBtn.classList.add('spinning');
    Promise.all([
      refreshStatus(),
      typeof refreshPageData === 'function' ? refreshPageData() : Promise.resolve()
    ]).finally(() => {
      setTimeout(() => refreshBtn.classList.remove('spinning'), 600);
    });
  });
}

// Auto-refresh status every 10 s
refreshStatus();
setInterval(refreshStatus, 10000);

// ============================================================
// GLOBAL IP / DOMAIN SEARCH
// ============================================================
const globalSearchInput = document.getElementById('global-search');
const globalSearchBtn   = document.getElementById('global-search-btn');

function runGlobalSearch() {
  const q = globalSearchInput ? globalSearchInput.value.trim() : '';
  if (!q) return;
  window.location.href = '/investigation?q=' + encodeURIComponent(q);
}

if (globalSearchBtn) globalSearchBtn.addEventListener('click', runGlobalSearch);
if (globalSearchInput) {
  globalSearchInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') runGlobalSearch();
  });
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = { success: 'bi-check-circle-fill', error: 'bi-x-circle-fill',
                  warning: 'bi-exclamation-triangle-fill', info: 'bi-info-circle-fill' };
  const colors = { success: 'var(--accent-green)', error: 'var(--accent-red)',
                   warning: 'var(--accent-orange)', info: 'var(--accent-blue)' };

  const toast = document.createElement('div');
  toast.className = `ns-toast ${type}`;
  toast.innerHTML = `<i class="bi ${icons[type] || icons.info}" style="color:${colors[type] || colors.info};font-size:1rem;flex-shrink:0"></i>
                     <span style="flex:1">${escHtml(message)}</span>
                     <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:0 2px;font-size:0.9rem">×</button>`;

  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; setTimeout(() => toast.remove(), 300); }, duration);
}

// ============================================================
// FORMATTERS
// ============================================================
function formatBytes(bytes) {
  if (bytes == null || isNaN(bytes)) return '—';
  const b = Number(bytes);
  if (b < 1024)        return b + ' B';
  if (b < 1048576)     return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824)  return (b/1048576).toFixed(2) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}

function formatNum(n) {
  if (n == null || isNaN(n)) return '—';
  return Number(n).toLocaleString();
}

function parseDate(ts) {
  if (!ts || ts === 'None' || ts === 'null' || ts === '—') return null;
  if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
  if (typeof ts === 'number') {
    const d = new Date(ts > 1e11 ? ts : ts * 1000);
    return isNaN(d.getTime()) ? null : d;
  }
  let s = String(ts).trim();
  if (!s || s === 'None' || s === 'null' || s === '—') return null;

  // Normalize "YYYY-MM-DD HH:MM:SS" space to 'T'
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(s)) {
    s = s.replace(' ', 'T');
  }

  // If ISO without timezone offset (e.g. '2026-11-11T18:47:06'), explicitly treat as UTC by appending 'Z'
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) {
    s += 'Z';
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function formatTs(ts) {
  if (!ts || ts === 'None' || ts === 'null') return '—';
  try {
    const d = parseDate(ts);
    if (!d) return '—';
    return d.toLocaleString();
  } catch { return String(ts); }
}

function relativeTime(ts) {
  if (!ts || ts === 'None' || ts === 'null') return '—';
  try {
    const d = parseDate(ts);
    if (!d) return '—';
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60)    return 'just now';
    if (diff < 3600)  return Math.floor(diff/60)   + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600)  + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  } catch { return String(ts); }
}

function escHtml(s) {
  if (typeof s !== 'string') s = String(s ?? '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
           .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function protoBadge(proto) {
  const p = (proto || 'OTHER').toUpperCase();
  const cls = ['TCP','UDP','ICMP','DNS'].includes(p) ? p : 'OTHER';
  return `<span class="proto-badge ${cls}">${escHtml(p)}</span>`;
}

function severityBadge(sev) {
  const s = (sev || 'INFO').toUpperCase();
  return `<span class="severity-badge ${s}">${escHtml(s)}</span>`;
}

function statusPill(online) {
  return online
    ? `<span class="status-pill online"><span class="status-dot online"></span>Online</span>`
    : `<span class="status-pill offline"><span class="status-dot offline"></span>Offline</span>`;
}

// Is device "recently seen" = within last 15 minutes
function isRecentlySeen(lastSeen, minuteThreshold = 15) {
  if (!lastSeen || lastSeen === 'None' || lastSeen === 'null') return false;
  try {
    const d = parseDate(lastSeen);
    if (!d) return false;
    const diff = Date.now() - d.getTime();
    return diff >= -30000 && diff < minuteThreshold * 60 * 1000;
  } catch { return false; }
}

// Click IP → investigation
function investigateIp(ip) {
  window.location.href = '/investigation?q=' + encodeURIComponent(ip);
}

// ============================================================
// DETAIL PANEL HELPERS
// ============================================================
function openDetailPanel(titleHtml, bodyHtml) {
  const panel   = document.getElementById('detail-panel');
  const overlay = document.getElementById('detail-overlay');
  const title   = document.getElementById('detail-panel-title');
  const body    = document.getElementById('detail-panel-body');
  if (!panel) return;
  title.innerHTML = titleHtml;
  body.innerHTML  = bodyHtml;
  panel.classList.add('open');
  if (overlay) overlay.classList.add('show');
}

function closeDetailPanel() {
  const panel   = document.getElementById('detail-panel');
  const overlay = document.getElementById('detail-overlay');
  if (panel) panel.classList.remove('open');
  if (overlay) overlay.classList.remove('show');
}

document.addEventListener('DOMContentLoaded', () => {
  const closeBtn  = document.getElementById('detail-panel-close');
  const overlay   = document.getElementById('detail-overlay');
  if (closeBtn) closeBtn.addEventListener('click', closeDetailPanel);
  if (overlay)  overlay.addEventListener('click', closeDetailPanel);
});

// ============================================================
// PAGINATION HELPER
// ============================================================
class NSPaginator {
  constructor(containerId, infoId, pageSize = 25) {
    this.container = document.getElementById(containerId);
    this.info      = document.getElementById(infoId);
    this.pageSize  = pageSize;
    this.page      = 1;
    this.total     = 0;
    this.onPage    = null; // callback(page)
  }

  render(total, currentPage) {
    this.total = total;
    this.page  = currentPage;
    const totalPages = Math.max(1, Math.ceil(total / this.pageSize));
    const start = Math.min((currentPage-1)*this.pageSize + 1, total);
    const end   = Math.min(currentPage * this.pageSize, total);

    if (this.info) {
      this.info.textContent = total === 0 ? 'No results' : `Showing ${start}–${end} of ${total}`;
    }

    if (!this.container) return;
    let html = '';
    html += `<button class="page-btn" ${currentPage===1?'disabled':''} onclick="ns_paginator_go(${currentPage-1})"><i class="bi bi-chevron-left"></i></button>`;

    // window of pages
    let startP = Math.max(1, currentPage-2);
    let endP   = Math.min(totalPages, startP+4);
    startP = Math.max(1, endP-4);

    for (let p = startP; p <= endP; p++) {
      html += `<button class="page-btn ${p===currentPage?'active':''}" onclick="ns_paginator_go(${p})">${p}</button>`;
    }

    html += `<button class="page-btn" ${currentPage===totalPages?'disabled':''} onclick="ns_paginator_go(${currentPage+1})"><i class="bi bi-chevron-right"></i></button>`;
    this.container.innerHTML = html;
  }
}

// Global go-to-page dispatcher (called from inline onclick)
let _activePaginator = null;
function ns_paginator_go(page) {
  if (_activePaginator && _activePaginator.onPage) _activePaginator.onPage(page);
}

// ============================================================
// CHART.JS DEFAULT DEFAULTS
// ============================================================
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';
  Chart.defaults.font.family = "Inter, -apple-system, sans-serif";
  Chart.defaults.font.size = 12;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  Chart.defaults.plugins.tooltip.backgroundColor = '#1c2130';
  Chart.defaults.plugins.tooltip.borderColor = '#30363d';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.titleColor = '#e6edf3';
  Chart.defaults.plugins.tooltip.bodyColor  = '#8b949e';
}
