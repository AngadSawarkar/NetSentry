/**
 * NetSentry – incidents.js
 * Incident status stored in localStorage.
 */
let allIncidents = [];
let filteredInc  = [];
let incPage = 1;
const INC_PAGE = 25;
const STATUS_KEY = 'ns_incident_statuses';

function getStatuses() {
  try { return JSON.parse(localStorage.getItem(STATUS_KEY)) || {}; }
  catch { return {}; }
}
function setStatus(id, status) {
  const s = getStatuses();
  s[id] = status;
  localStorage.setItem(STATUS_KEY, JSON.stringify(s));
}

function getIncidentStatus(id, serverStatus) {
  const local = getStatuses()[id];
  if (local) return local;
  return serverStatus || 'NEW';
}

async function loadIncidents() {
  const res = await fetch('/api/alerts').catch(() => null);
  if (!res || !res.ok) {
    document.getElementById('incident-table-body').innerHTML = `<tr><td colspan="7">
      <div class="empty-state"><i class="bi bi-exclamation-triangle"></i><h3>Load Error</h3><p>Could not load alerts.</p></div>
    </td></tr>`;
    return;
  }
  const d = await res.json();
  allIncidents = (d.alerts || []).map(a => ({
    ...a,
    status: getIncidentStatus(a.id, a.status)
  }));
  document.getElementById('incident-count').textContent = allIncidents.length;
  applyIncFilters();
}

function applyIncFilters() {
  const search    = (document.getElementById('inc-search').value || '').toLowerCase().trim();
  const sev       = (document.getElementById('inc-sev-filter').value || '').toUpperCase();
  const statusF   = (document.getElementById('inc-status-filter').value || '').toUpperCase();
  const dateFrom  = document.getElementById('inc-date-from').value;
  const dateTo    = document.getElementById('inc-date-to').value;

  let list = allIncidents.filter(a => {
    if (sev && (a.severity||'').toUpperCase() !== sev) return false;
    const incStatus = getIncidentStatus(a.id);
    if (statusF && incStatus !== statusF) return false;
    if (search) {
      const src = (a.source_ip||'').toLowerCase();
      const t   = (a.alert_type||'').toLowerCase();
      if (!src.includes(search) && !t.includes(search)) return false;
    }
    if (dateFrom) {
      const ts = parseDate(a.timestamp);
      if (ts && ts < new Date(dateFrom)) return false;
    }
    if (dateTo) {
      const ts = parseDate(a.timestamp);
      if (ts && ts > new Date(dateTo + 'T23:59:59')) return false;
    }
    return true;
  });

  list.sort((a,b) => (parseDate(b.timestamp)?.getTime() || 0) - (parseDate(a.timestamp)?.getTime() || 0));
  filteredInc = list;
  incPage = 1;
  renderIncTable();
}

const STATUS_COLORS = {
  NEW:'new', INVESTIGATING:'investigating', RESOLVED:'resolved', FALSE_POSITIVE:'fp'
};
const STATUS_LABELS = {
  NEW:'New', INVESTIGATING:'Investigating', RESOLVED:'Resolved', FALSE_POSITIVE:'False Positive'
};

function renderIncTable() {
  const tbody = document.getElementById('incident-table-body');
  const start = (incPage-1)*INC_PAGE;
  const slice = filteredInc.slice(start, start+INC_PAGE);

  if (!filteredInc.length) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">
      <i class="bi bi-clock-history"></i><h3>No Incidents</h3><p>No matching incident records.</p>
    </div></td></tr>`;
  } else {
    tbody.innerHTML = slice.map(a => {
      const st = getIncidentStatus(a.id);
      const stLabel = STATUS_LABELS[st] || st;
      const stClass = STATUS_COLORS[st] || '';
      return `<tr>
        <td class="text-muted text-xs">#${a.id}</td>
        <td class="text-xs fw-600">${escHtml(a.alert_type||'—')}</td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(a.source_ip||'')}')">${escHtml(a.source_ip||'—')}</span></td>
        <td>${severityBadge(a.severity)}</td>
        <td>
          <select class="incident-status-select" onchange="updateIncidentStatus(${a.id}, this.value)">
            ${['NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE'].map(s =>
              `<option value="${s}" ${st===s?'selected':''}>${STATUS_LABELS[s]}</option>`
            ).join('')}
          </select>
        </td>
        <td class="text-muted text-xs">${formatTs(a.timestamp)}</td>
        <td><button class="btn-ns btn-ns-outline btn-ns-sm" onclick="showIncDetail(${a.id})"><i class="bi bi-info-circle"></i> View</button></td>
      </tr>`;
    }).join('');
  }

  // Pagination
  const total = filteredInc.length;
  const totalPages = Math.max(1, Math.ceil(total/INC_PAGE));
  const s2 = Math.min((incPage-1)*INC_PAGE+1, total);
  const e2 = Math.min(incPage*INC_PAGE, total);
  const info = document.getElementById('inc-page-info');
  const ctrl = document.getElementById('inc-page-controls');
  if (info) info.textContent = total===0?'No results':`${s2}–${e2} of ${total}`;
  if (ctrl) {
    let html = `<button class="page-btn" ${incPage===1?'disabled':''} onclick="goIncPage(${incPage-1})"><i class="bi bi-chevron-left"></i></button>`;
    const sp=Math.max(1,incPage-2), ep=Math.min(totalPages,sp+4);
    for(let p=Math.max(1,ep-4);p<=ep;p++) html+=`<button class="page-btn ${p===incPage?'active':''}" onclick="goIncPage(${p})">${p}</button>`;
    html+=`<button class="page-btn" ${incPage===totalPages?'disabled':''} onclick="goIncPage(${incPage+1})"><i class="bi bi-chevron-right"></i></button>`;
    ctrl.innerHTML=html;
  }
}

function goIncPage(page) { incPage=page; renderIncTable(); }

function updateIncidentStatus(id, status) {
  setStatus(id, status);
  // Update in-memory record
  const inc = allIncidents.find(x => x.id === id);
  if (inc) inc.status = status;

  fetch(`/api/incidents/${id}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  }).then(r => {
    if (r.ok) showToast(`Incident #${id} saved as ${STATUS_LABELS[status]||status}`, 'success', 2500);
    else showToast(`Incident #${id} set to ${STATUS_LABELS[status]||status} (local only)`, 'warning', 2500);
  }).catch(() => {
    showToast(`Incident #${id} set to ${STATUS_LABELS[status]||status} (local only)`, 'warning', 2500);
  });
}

function showIncDetail(id) {
  const a = allIncidents.find(x=>x.id===id);
  if (!a) return;
  const st = getIncidentStatus(a.id);
  openDetailPanel(
    `<i class="bi bi-clock-history text-blue"></i> Incident #${a.id}`,
    `<div class="detail-item">
      <div class="detail-item-label">Alert Type</div>
      <div class="detail-item-value fw-600">${escHtml(a.alert_type||'—')}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Severity</div>
      <div class="detail-item-value">${severityBadge(a.severity)}</div>
    </div>
    <div class="detail-item">
      <div class="detail-item-label">Status</div>
      <div class="detail-item-value">
        <select class="incident-status-select" onchange="updateIncidentStatus(${a.id}, this.value)">
          ${['NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE'].map(s=>
            `<option value="${s}" ${st===s?'selected':''}>${STATUS_LABELS[s]}</option>`).join('')}
        </select>
      </div>
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
    </div>`
  );
}

async function refreshPageData() { await loadIncidents(); }
document.addEventListener('DOMContentLoaded', () => {
  loadIncidents();
  const inp = document.getElementById('inc-search');
  if (inp) inp.addEventListener('keydown', e => { if(e.key==='Enter') applyIncFilters(); });
});
