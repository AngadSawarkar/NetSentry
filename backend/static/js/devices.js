/**
 * NetSentry – devices.js
 */
let allDevices  = [];
let filteredDev = [];
let devPage     = 1;
const DEV_PAGE  = 25;
let allConns    = [];
let allAlerts   = [];

async function loadDevices() {
  const [devRes, connRes, alertRes] = await Promise.allSettled([
    fetch('/api/devices'),
    fetch('/api/connections'),
    fetch('/api/alerts')
  ]);

  if (devRes.status === 'fulfilled' && devRes.value.ok) {
    const d = await devRes.value.json();
    allDevices = d.devices || [];
    document.getElementById('dev-count').textContent = allDevices.length;
    applyDevFilters();
  }

  if (connRes.status === 'fulfilled' && connRes.value.ok) {
    const d = await connRes.value.json();
    allConns = d.connections || [];
  }

  if (alertRes.status === 'fulfilled' && alertRes.value.ok) {
    const d = await alertRes.value.json();
    allAlerts = d.alerts || [];
  }
}

function applyDevFilters() {
  const search     = (document.getElementById('dev-search').value || '').toLowerCase().trim();
  const recentOnly = document.getElementById('filter-recent-only')?.checked;
  const sort       = document.getElementById('dev-sort').value || 'last_seen_desc';

  let list = allDevices.filter(d => {
    if (recentOnly && !isRecentlySeen(d.last_seen)) return false;
    if (search) {
      const ip  = (d.ip_address  || '').toLowerCase();
      const mac = (d.mac_address || '').toLowerCase();
      if (!ip.includes(search) && !mac.includes(search)) return false;
    }
    return true;
  });

  list.sort((a,b) => {
    if (sort === 'packets_desc')   return (b.packet_count||0) - (a.packet_count||0);
    if (sort === 'bytes_desc')     return (b.total_bytes||0)  - (a.total_bytes||0);
    if (sort === 'first_seen_asc') return (parseDate(a.first_seen)?.getTime() || 0) - (parseDate(b.first_seen)?.getTime() || 0);
    return (parseDate(b.last_seen)?.getTime() || 0) - (parseDate(a.last_seen)?.getTime() || 0);
  });

  filteredDev = list;
  devPage = 1;
  renderDevTable();
}

function renderDevTable() {
  const tbody = document.getElementById('dev-table-body');
  const start = (devPage-1)*DEV_PAGE;
  const slice = filteredDev.slice(start, start+DEV_PAGE);

  if (!filteredDev.length) {
    tbody.innerHTML = `<tr><td colspan="8">
      <div class="empty-state">
        <i class="bi bi-hdd-network"></i>
        <h3>No Devices Found</h3>
        <p>No devices match your search criteria.</p>
      </div>
    </td></tr>`;
  } else {
    tbody.innerHTML = slice.map(d => {
      const online = isRecentlySeen(d.last_seen);
      return `<tr>
        <td>${online
          ? `<span class="status-pill online"><span class="status-dot online"></span>Online</span>`
          : `<span class="status-pill offline"><span class="status-dot offline"></span>Offline</span>`}</td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(d.ip_address||'')}')">${escHtml(d.ip_address||'—')}</span></td>
        <td><code class="text-muted text-xs">${escHtml(d.mac_address||'—')}</code></td>
        <td class="text-muted text-xs">${formatTs(d.first_seen)}</td>
        <td class="text-muted text-xs">${relativeTime(d.last_seen)}</td>
        <td class="num-cell">${formatNum(d.packet_count)}</td>
        <td class="bytes-cell">${formatBytes(d.total_bytes)}</td>
        <td><button class="btn-ns btn-ns-outline btn-ns-sm" onclick="showDeviceDetail(${d.id})"><i class="bi bi-info-circle"></i> Detail</button></td>
      </tr>`;
    }).join('');
  }

  renderDevPagination();
}

function renderDevPagination() {
  const total = filteredDev.length;
  const totalPages = Math.max(1, Math.ceil(total / DEV_PAGE));
  const start = Math.min((devPage-1)*DEV_PAGE+1, total);
  const end   = Math.min(devPage*DEV_PAGE, total);

  const info = document.getElementById('dev-page-info');
  const ctrl = document.getElementById('dev-page-controls');
  if (info) info.textContent = total === 0 ? 'No results' : `${start}–${end} of ${total}`;
  if (!ctrl) return;
  let html = `<button class="page-btn" ${devPage===1?'disabled':''} onclick="goDevPage(${devPage-1})"><i class="bi bi-chevron-left"></i></button>`;
  const sp = Math.max(1, devPage-2), ep = Math.min(totalPages, sp+4);
  for (let p = Math.max(1, ep-4); p <= ep; p++) {
    html += `<button class="page-btn ${p===devPage?'active':''}" onclick="goDevPage(${p})">${p}</button>`;
  }
  html += `<button class="page-btn" ${devPage===totalPages?'disabled':''} onclick="goDevPage(${devPage+1})"><i class="bi bi-chevron-right"></i></button>`;
  ctrl.innerHTML = html;
}

function goDevPage(page) { devPage = page; renderDevTable(); }

function showDeviceDetail(id) {
  const dev = allDevices.find(d => d.id === id);
  if (!dev) return;

  const online = isRecentlySeen(dev.last_seen);
  const conns  = allConns.filter(c => c.source_ip === dev.ip_address || c.destination_ip === dev.ip_address);
  const alerts = allAlerts.filter(a => a.source_ip === dev.ip_address || a.destination_ip === dev.ip_address);

  let connHtml = '';
  if (conns.length) {
    connHtml = `<div class="detail-item-label">Related Connections (${conns.length})</div>`;
    connHtml += conns.slice(0,5).map(c => `
      <div style="font-size:0.8rem;padding:6px 8px;background:var(--bg-primary);border-radius:4px;margin-bottom:4px;font-family:monospace">
        ${escHtml(c.source_ip)}:${c.source_port} → ${escHtml(c.destination_ip)}:${c.destination_port}
        <span class="proto-badge ${(c.protocol||'').toUpperCase()}" style="margin-left:4px">${escHtml(c.protocol||'')}</span>
      </div>
    `).join('');
    if (conns.length > 5) connHtml += `<div class="text-muted text-xs">…and ${conns.length-5} more</div>`;
  } else {
    connHtml = '<div class="detail-item-label">Related Connections</div><div class="text-muted text-sm">None recorded</div>';
  }

  let alertHtml = '';
  if (alerts.length) {
    alertHtml = `<div class="detail-item-label">Related Alerts (${alerts.length})</div>`;
    alertHtml += alerts.slice(0,3).map(a => `
      <div style="font-size:0.8rem;padding:6px 8px;background:var(--bg-primary);border-radius:4px;margin-bottom:4px;">
        ${severityBadge(a.severity)} <strong>${escHtml(a.alert_type||'')}</strong><br>
        <span class="text-muted">${escHtml(a.description||'')}</span>
      </div>
    `).join('');
  } else {
    alertHtml = '<div class="detail-item-label">Related Alerts</div><div class="text-muted text-sm">None recorded</div>';
  }

  openDetailPanel(
    `<i class="bi bi-hdd-network-fill text-blue"></i> ${escHtml(dev.ip_address||'Device')}`,
    `<div class="detail-item">
      <div class="detail-item-label">Status</div>
      <div class="detail-item-value">${online
        ? `<span class="status-pill online"><span class="status-dot online"></span>Online (seen recently)</span>`
        : `<span class="status-pill offline"><span class="status-dot offline"></span>Offline (not seen in 15+ min)</span>`}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">IP Address</div>
      <div class="detail-item-value font-mono">${escHtml(dev.ip_address||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">MAC Address</div>
      <div class="detail-item-value font-mono">${escHtml(dev.mac_address||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">First Seen</div>
      <div class="detail-item-value">${formatTs(dev.first_seen)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Last Seen</div>
      <div class="detail-item-value">${formatTs(dev.last_seen)} <span class="text-muted text-xs">(${relativeTime(dev.last_seen)})</span></div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Packet Count</div>
      <div class="detail-item-value font-mono">${formatNum(dev.packet_count)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Total Bytes</div>
      <div class="detail-item-value font-mono">${formatBytes(dev.total_bytes)}</div>
    </div>
    <hr class="detail-divider">
    ${connHtml}
    <hr class="detail-divider">
    ${alertHtml}
    <hr class="detail-divider">
    <button class="btn-ns btn-ns-primary w-100" onclick="investigateIp('${escHtml(dev.ip_address||'')}')">
      <i class="bi bi-search"></i> Investigate this IP
    </button>`
  );
}

async function refreshPageData() { await loadDevices(); }
document.addEventListener('DOMContentLoaded', () => {
  loadDevices();
  const inp  = document.getElementById('dev-search');
  const chk  = document.getElementById('filter-recent-only');
  if (inp) inp.addEventListener('keydown', e => { if(e.key==='Enter') applyDevFilters(); });
  if (chk) chk.addEventListener('change', applyDevFilters);
});
