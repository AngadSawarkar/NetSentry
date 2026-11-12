/**
 * NetSentry – connections.js
 */
let allConnsPage = [];
let filteredConnsPage = [];
let connPage2 = 1;
const CONN2_PAGE = 25;

async function loadConnections() {
  const res = await fetch('/api/connections').catch(() => null);
  if (!res || !res.ok) {
    document.getElementById('conn-table-body2').innerHTML = `<tr><td colspan="10">
      <div class="empty-state"><i class="bi bi-exclamation-triangle"></i><h3>Load Error</h3><p>Could not reach the backend API.</p></div>
    </td></tr>`;
    return;
  }
  const d = await res.json();
  allConnsPage = d.connections || [];
  document.getElementById('total-conn-count').textContent = allConnsPage.length;
  applyConnFilters2();
}

function applyConnFilters2() {
  const search = (document.getElementById('conn-ip-search').value || '').toLowerCase().trim();
  const port   = (document.getElementById('conn-port-search').value || '').trim();
  const proto  = (document.getElementById('conn-proto-filter2').value || '').toUpperCase();
  const sort   = document.getElementById('conn-sort2').value || 'last_seen_desc';

  let list = allConnsPage.filter(c => {
    if (proto && (c.protocol||'').toUpperCase() !== proto) return false;
    if (port) {
      const portNum = parseInt(port);
      if (c.source_port !== portNum && c.destination_port !== portNum) return false;
    }
    if (search) {
      const src = (c.source_ip||'').toLowerCase();
      const dst = (c.destination_ip||'').toLowerCase();
      if (!src.includes(search) && !dst.includes(search)) return false;
    }
    return true;
  });

  list.sort((a,b) => {
    if (sort==='packets_desc') return (b.packet_count||0)-(a.packet_count||0);
    if (sort==='bytes_desc')   return (b.total_bytes||0)-(a.total_bytes||0);
    return (parseDate(b.last_seen)?.getTime() || 0) - (parseDate(a.last_seen)?.getTime() || 0);
  });

  filteredConnsPage = list;
  connPage2 = 1;
  renderConnTable2();
}

function renderConnTable2() {
  const tbody = document.getElementById('conn-table-body2');
  const start = (connPage2-1)*CONN2_PAGE;
  const slice = filteredConnsPage.slice(start, start+CONN2_PAGE);

  if (!filteredConnsPage.length) {
    tbody.innerHTML = `<tr><td colspan="10"><div class="empty-state">
      <i class="bi bi-diagram-3"></i><h3>No Connections</h3><p>No matching connection records found.</p>
    </div></td></tr>`;
  } else {
    tbody.innerHTML = slice.map(c => `
      <tr>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.source_ip||'')}')">${escHtml(c.source_ip||'—')}</span></td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.destination_ip||'')}')">${escHtml(c.destination_ip||'—')}</span></td>
        <td>${protoBadge(c.protocol)}</td>
        <td class="port-cell">${c.source_port||'—'}</td>
        <td class="port-cell">${c.destination_port||'—'}</td>
        <td class="num-cell">${formatNum(c.packet_count)}</td>
        <td class="bytes-cell">${formatBytes(c.total_bytes)}</td>
        <td class="text-muted text-xs">${formatTs(c.first_seen)}</td>
        <td class="text-muted text-xs">${relativeTime(c.last_seen)}</td>
        <td><button class="btn-ns btn-ns-outline btn-ns-sm" onclick="showConnDetail(${c.id})"><i class="bi bi-info-circle"></i></button></td>
      </tr>
    `).join('');
  }

  // Pagination
  const total = filteredConnsPage.length;
  const totalPages = Math.max(1, Math.ceil(total/CONN2_PAGE));
  const start2 = Math.min((connPage2-1)*CONN2_PAGE+1, total);
  const end2   = Math.min(connPage2*CONN2_PAGE, total);

  const info = document.getElementById('conn2-page-info');
  const ctrl = document.getElementById('conn2-page-controls');
  if (info) info.textContent = total===0 ? 'No results' : `${start2}–${end2} of ${total}`;
  if (ctrl) {
    let html = `<button class="page-btn" ${connPage2===1?'disabled':''} onclick="goConnPage2(${connPage2-1})"><i class="bi bi-chevron-left"></i></button>`;
    const sp=Math.max(1,connPage2-2), ep=Math.min(totalPages,sp+4);
    for (let p=Math.max(1,ep-4);p<=ep;p++) html+=`<button class="page-btn ${p===connPage2?'active':''}" onclick="goConnPage2(${p})">${p}</button>`;
    html += `<button class="page-btn" ${connPage2===totalPages?'disabled':''} onclick="goConnPage2(${connPage2+1})"><i class="bi bi-chevron-right"></i></button>`;
    ctrl.innerHTML = html;
  }
}

function goConnPage2(page) { connPage2=page; renderConnTable2(); }

function showConnDetail(id) {
  const c = allConnsPage.find(x => x.id===id);
  if (!c) return;
  openDetailPanel(
    `<i class="bi bi-diagram-3-fill text-blue"></i> Connection Detail`,
    `<div class="detail-item">
      <div class="detail-item-label">Source</div>
      <div class="detail-item-value font-mono">${escHtml(c.source_ip||'—')}:${c.source_port||'—'}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Destination</div>
      <div class="detail-item-value font-mono">${escHtml(c.destination_ip||'—')}:${c.destination_port||'—'}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Protocol</div>
      <div class="detail-item-value">${protoBadge(c.protocol)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">First Seen</div>
      <div class="detail-item-value">${formatTs(c.first_seen)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Last Seen</div>
      <div class="detail-item-value">${formatTs(c.last_seen)} <span class="text-muted text-xs">(${relativeTime(c.last_seen)})</span></div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Packet Count</div>
      <div class="detail-item-value font-mono">${formatNum(c.packet_count)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Total Bytes</div>
      <div class="detail-item-value font-mono">${formatBytes(c.total_bytes)}</div>
    </div>
    <hr class="detail-divider">
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-ns btn-ns-outline" style="flex:1" onclick="investigateIp('${escHtml(c.source_ip||'')}')">
        <i class="bi bi-search"></i> Investigate ${escHtml(c.source_ip||'')}
      </button>
      <button class="btn-ns btn-ns-outline" style="flex:1" onclick="investigateIp('${escHtml(c.destination_ip||'')}')">
        <i class="bi bi-search"></i> Investigate ${escHtml(c.destination_ip||'')}
      </button>
    </div>`
  );
}

async function refreshPageData() { await loadConnections(); }
document.addEventListener('DOMContentLoaded', () => {
  loadConnections();
  ['conn-ip-search','conn-port-search'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => { if(e.key==='Enter') applyConnFilters2(); });
  });
});
