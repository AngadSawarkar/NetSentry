/**
 * NetSentry – alerts.js
 */
let allAlerts2   = [];
let filteredAlerts = [];
let alertPage    = 1;
const ALERT_PAGE = 25;

async function loadAlerts() {
  const res = await fetch('/api/alerts').catch(() => null);
  if (!res || !res.ok) {
    document.getElementById('alert-table-body').innerHTML = `<tr><td colspan="8">
      <div class="empty-state"><i class="bi bi-exclamation-triangle"></i><h3>Load Error</h3><p>Could not load alerts.</p></div>
    </td></tr>`;
    return;
  }
  const d = await res.json();
  allAlerts2 = d.alerts || [];

  // Update stat cards
  const critical = allAlerts2.filter(a => a.severity === 'CRITICAL').length;
  const high     = allAlerts2.filter(a => a.severity === 'HIGH').length;
  const medium   = allAlerts2.filter(a => a.severity === 'MEDIUM').length;
  const lowInfo  = allAlerts2.filter(a => a.severity === 'LOW' || a.severity === 'INFO' || !a.severity).length;

  document.getElementById('alert-total').textContent    = formatNum(allAlerts2.length);
  document.getElementById('alert-critical').textContent = formatNum(critical);
  document.getElementById('alert-high').textContent     = formatNum(high);
  document.getElementById('alert-medium').textContent   = formatNum(medium);
  document.getElementById('alert-low').textContent      = formatNum(lowInfo);

  // Populate type filter with actual types seen
  const types = [...new Set(allAlerts2.map(a => a.alert_type).filter(Boolean))];
  const sel = document.getElementById('alert-type-filter');
  if (sel) {
    // Keep static options, add any extra types
    const existing = [...sel.options].map(o => o.value);
    for (const t of types) {
      if (!existing.includes(t)) {
        const opt = document.createElement('option');
        opt.value = t; opt.textContent = t;
        sel.appendChild(opt);
      }
    }
  }

  applyAlertFilters();
}

function applyAlertFilters() {
  const search = (document.getElementById('alert-search').value || '').toLowerCase().trim();
  const sev    = (document.getElementById('alert-sev-filter').value || '').toUpperCase();
  const type   = (document.getElementById('alert-type-filter').value || '').toUpperCase();

  let list = allAlerts2.filter(a => {
    if (sev  && (a.severity   || '').toUpperCase() !== sev)  return false;
    if (type && (a.alert_type || '').toUpperCase() !== type) return false;
    if (search) {
      const src   = (a.source_ip   || '').toLowerCase();
      const dst   = (a.destination_ip || '').toLowerCase();
      const desc  = (a.description  || '').toLowerCase();
      const atype = (a.alert_type   || '').toLowerCase();
      if (!src.includes(search) && !dst.includes(search) && !desc.includes(search) && !atype.includes(search)) return false;
    }
    return true;
  });

  // Sort by time DESC
  list.sort((a,b) => (parseDate(b.timestamp)?.getTime() || 0) - (parseDate(a.timestamp)?.getTime() || 0));

  filteredAlerts = list;
  alertPage = 1;
  renderAlertTable();
}

function renderAlertTable() {
  const tbody = document.getElementById('alert-table-body');
  const start = (alertPage-1)*ALERT_PAGE;
  const slice = filteredAlerts.slice(start, start+ALERT_PAGE);

  if (!filteredAlerts.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state">
      <i class="bi bi-shield-check"></i><h3>No Alerts</h3><p>No alerts match your current filters.</p>
    </div></td></tr>`;
  } else {
    tbody.innerHTML = slice.map(a => `
      <tr>
        <td class="text-muted text-xs">#${a.id||'—'}</td>
        <td><span class="text-xs fw-600">${escHtml(a.alert_type||'—')}</span></td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(a.source_ip||'')}')">${escHtml(a.source_ip||'—')}</span></td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(a.destination_ip||'')}')">${escHtml(a.destination_ip||'—')}</span></td>
        <td>${severityBadge(a.severity)}</td>
        <td class="text-secondary text-sm">${escHtml((a.description||'').substring(0,70))}${(a.description||'').length>70?'…':''}</td>
        <td class="text-muted text-xs">${formatTs(a.timestamp)}</td>
        <td><button class="btn-ns btn-ns-outline btn-ns-sm" onclick="showAlertDetail(${a.id})"><i class="bi bi-info-circle"></i></button></td>
      </tr>
    `).join('');
  }

  // Pagination
  const total = filteredAlerts.length;
  const totalPages = Math.max(1, Math.ceil(total/ALERT_PAGE));
  const start2 = Math.min((alertPage-1)*ALERT_PAGE+1, total);
  const end2   = Math.min(alertPage*ALERT_PAGE, total);

  const info = document.getElementById('alert-page-info');
  const ctrl = document.getElementById('alert-page-controls');
  if (info) info.textContent = total===0 ? 'No results' : `${start2}–${end2} of ${total}`;
  if (ctrl) {
    let html = `<button class="page-btn" ${alertPage===1?'disabled':''} onclick="goAlertPage(${alertPage-1})"><i class="bi bi-chevron-left"></i></button>`;
    const sp=Math.max(1,alertPage-2), ep=Math.min(totalPages,sp+4);
    for (let p=Math.max(1,ep-4);p<=ep;p++) html+=`<button class="page-btn ${p===alertPage?'active':''}" onclick="goAlertPage(${p})">${p}</button>`;
    html+=`<button class="page-btn" ${alertPage===totalPages?'disabled':''} onclick="goAlertPage(${alertPage+1})"><i class="bi bi-chevron-right"></i></button>`;
    ctrl.innerHTML = html;
  }
}

function goAlertPage(page) { alertPage=page; renderAlertTable(); }

function showAlertDetail(id) {
  const a = allAlerts2.find(x => x.id===id);
  if (!a) return;

  const alertLabels = {
    PORT_SCAN:'TCP port scan detected – source IP probed multiple destination ports in a short window.',
    SYN_FLOOD:'SYN flood detected – high volume of TCP SYN packets with no corresponding ACK.',
    ICMP_FLOOD:'ICMP flood detected – excessive ICMP echo requests from source IP.',
    REPEATED_CONNECTIONS:'Repeated connection attempts to same destination port detected.',
    DNS_FLOOD:'Excessive DNS queries detected from source IP.',
    REPEATED_DNS:'Repeated DNS queries for the same domain detected.',
  };

  const context = alertLabels[a.alert_type] || '';

  openDetailPanel(
    `<i class="bi bi-shield-exclamation text-orange"></i> Alert #${a.id}`,
    `<div class="detail-item">
      <div class="detail-item-label">Alert Type</div>
      <div class="detail-item-value fw-600">${escHtml(a.alert_type||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Severity</div>
      <div class="detail-item-value">${severityBadge(a.severity)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Source IP</div>
      <div class="detail-item-value font-mono">${escHtml(a.source_ip||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Destination IP</div>
      <div class="detail-item-value font-mono">${escHtml(a.destination_ip||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Timestamp</div>
      <div class="detail-item-value">${formatTs(a.timestamp)} <span class="text-muted text-xs">(${relativeTime(a.timestamp)})</span></div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Description</div>
      <div class="detail-item-value text-sm">${escHtml(a.description||'—')}</div>
    </div>
    ${context ? `<div style="background:rgba(47,129,247,0.08);border:1px solid rgba(47,129,247,0.2);border-radius:6px;padding:10px 12px;margin:8px 0;font-size:.8rem;color:var(--text-secondary)">
      <i class="bi bi-info-circle text-blue"></i> ${escHtml(context)}
    </div>` : ''}
    <hr class="detail-divider">
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${a.source_ip ? `<button class="btn-ns btn-ns-outline" style="flex:1" onclick="investigateIp('${escHtml(a.source_ip)}')">
        <i class="bi bi-search"></i> Investigate ${escHtml(a.source_ip)}
      </button>` : ''}
      ${a.destination_ip ? `<button class="btn-ns btn-ns-outline" style="flex:1" onclick="investigateIp('${escHtml(a.destination_ip)}')">
        <i class="bi bi-search"></i> Investigate ${escHtml(a.destination_ip)}
      </button>` : ''}
    </div>`
  );
}

async function refreshPageData() { await loadAlerts(); }
document.addEventListener('DOMContentLoaded', () => {
  loadAlerts();
  const inp = document.getElementById('alert-search');
  if (inp) inp.addEventListener('keydown', e => { if(e.key==='Enter') applyAlertFilters(); });
});
