/**
 * NetSentry – investigation.js
 */

function runInvestigation() {
  const q = document.getElementById('inv-query').value.trim();
  if (!q) { showToast('Please enter an IP address or domain name.', 'warning'); return; }
  window.location.href = '/investigation?q=' + encodeURIComponent(q);
}

document.addEventListener('DOMContentLoaded', () => {
  const inp = document.getElementById('inv-query');
  if (inp) inp.addEventListener('keydown', e => { if (e.key==='Enter') runInvestigation(); });

  // Auto-run if query param present
  const params = new URLSearchParams(window.location.search);
  const q = params.get('q');
  if (q) fetchInvestigation(q);
});

function isIPv4(str) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
}

function isDomain(str) {
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(str);
}

async function fetchInvestigation(q) {
  document.getElementById('inv-results').style.display = 'none';
  document.getElementById('inv-loading').style.display = 'block';
  document.getElementById('inv-empty').style.display   = 'none';

  try {
    let endpoint, type;
    if (isIPv4(q)) {
      endpoint = '/api/investigation/ip/' + encodeURIComponent(q);
      type = 'ip';
    } else if (isDomain(q)) {
      endpoint = '/api/investigation/domain/' + encodeURIComponent(q);
      type = 'domain';
    } else {
      showToast('Please enter a valid IP address or domain name.', 'warning');
      document.getElementById('inv-loading').style.display = 'none';
      return;
    }

    const res = await fetch(endpoint);
    document.getElementById('inv-loading').style.display = 'none';

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showEmpty(err.error || 'No data found for this query.');
      return;
    }

    const data = await res.json();
    if (type === 'ip') renderIPResult(q, data);
    else               renderDomainResult(q, data);

  } catch (e) {
    document.getElementById('inv-loading').style.display = 'none';
    showEmpty('Could not reach the backend. Please check that NetSentry is running.');
  }
}

function showEmpty(msg) {
  document.getElementById('inv-results').style.display = 'none';
  document.getElementById('inv-empty').style.display   = '';
  document.getElementById('inv-empty-msg').textContent = msg;
}

// ============================================================
// IP RESULT
// ============================================================
function renderIPResult(ip, d) {
  document.getElementById('inv-summary-title').textContent = ip;
  document.getElementById('inv-type-badge').innerHTML = '<span class="proto-badge TCP">IPv4 Address</span>';

  const device = d.device || null;

  let summaryHtml = `
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">First Observed</div><div class="detail-item-value">${formatTs(d.first_seen)}</div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">Last Observed</div><div class="detail-item-value">${formatTs(d.last_seen)} <span class="text-muted text-xs">(${relativeTime(d.last_seen)})</span></div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">Total Packets</div><div class="detail-item-value font-mono">${formatNum(d.packet_count)}</div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">Total Bytes</div><div class="detail-item-value font-mono">${formatBytes(d.total_bytes)}</div></div>
    </div>`;

  if (device) {
    summaryHtml += `
      <div class="col-12 mt-2">
        <div style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;padding:12px 14px;">
          <div class="text-xs text-muted mb-0" style="margin-bottom:6px;text-transform:uppercase;letter-spacing:.8px">Device Record Found in Inventory</div>
          <div style="display:flex;gap:24px;flex-wrap:wrap;font-size:.85rem">
            <div><span class="text-muted">MAC: </span><code>${escHtml(device.mac_address||'—')}</code></div>
            <div><span class="text-muted">Status: </span>${isRecentlySeen(device.last_seen)?'<span class="status-pill online">Online</span>':'<span class="status-pill offline">Offline</span>'}</div>
          </div>
        </div>
      </div>`;
  } else {
    summaryHtml += `<div class="col-12 mt-2"><span class="text-muted text-sm"><i class="bi bi-info-circle"></i> This IP is not in the device inventory (observed only as source/destination in traffic).</span></div>`;
  }

  document.getElementById('inv-summary-row').innerHTML = summaryHtml;

  // Connections
  renderInvConnections(d.connections || []);
  renderInvAlerts(d.alerts || []);

  document.getElementById('inv-results').style.display = '';
}

// ============================================================
// DOMAIN RESULT
// ============================================================
function renderDomainResult(domain, d) {
  document.getElementById('inv-summary-title').textContent = domain;
  document.getElementById('inv-type-badge').innerHTML = '<span class="proto-badge DNS">Domain</span>';

  let summaryHtml = `
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">First Observed</div><div class="detail-item-value">${formatTs(d.first_seen)}</div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">Last Observed</div><div class="detail-item-value">${formatTs(d.last_seen)} <span class="text-muted text-xs">(${relativeTime(d.last_seen)})</span></div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">DNS Query Count</div><div class="detail-item-value font-mono">${formatNum(d.query_count)}</div></div>
    </div>
    <div class="col-6 col-md-3">
      <div class="detail-item"><div class="detail-item-label">Querying Devices</div><div class="detail-item-value font-mono">${(d.querying_ips||[]).length}</div></div>
    </div>`;

  if (d.querying_ips && d.querying_ips.length) {
    summaryHtml += `
      <div class="col-12 mt-2">
        <div class="detail-item-label">Devices that queried this domain</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
          ${d.querying_ips.map(ip => `<span class="ip-cell" onclick="investigateIp('${escHtml(ip)}')" style="background:var(--bg-secondary);padding:3px 10px;border-radius:4px;border:1px solid var(--border-color)">${escHtml(ip)}</span>`).join('')}
        </div>
      </div>`;
  }

  if (!d.query_count || d.query_count === 0) {
    summaryHtml = `<div class="col-12"><div class="empty-state" style="padding:20px"><i class="bi bi-search"></i><h3>No DNS Observations</h3><p>No DNS queries for "${escHtml(domain)}" have been recorded by NetSentry.</p></div></div>`;
  }

  document.getElementById('inv-summary-row').innerHTML = summaryHtml;

  // Alerts relating to domain queries
  renderInvConnections(d.connections || []);
  renderInvAlerts(d.alerts || []);

  document.getElementById('inv-results').style.display = '';
}

// ============================================================
// SHARED TABLE RENDERS
// ============================================================
function renderInvConnections(conns) {
  const tbody = document.getElementById('inv-conn-body');
  if (!conns.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state" style="padding:20px"><i class="bi bi-diagram-3"></i><p>No related connections.</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = conns.slice(0,20).map(c => `
    <tr>
      <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.source_ip||'')}')">${escHtml(c.source_ip||'—')}</span></td>
      <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.destination_ip||'')}')">${escHtml(c.destination_ip||'—')}</span></td>
      <td>${protoBadge(c.protocol)}</td>
      <td class="port-cell text-xs">${c.source_port||'—'} → ${c.destination_port||'—'}</td>
      <td class="num-cell">${formatNum(c.packet_count)}</td>
      <td class="text-muted text-xs">${relativeTime(c.last_seen)}</td>
    </tr>
  `).join('');
}

function renderInvAlerts(alerts) {
  const tbody = document.getElementById('inv-alert-body');
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="padding:20px"><i class="bi bi-shield-check"></i><p>No related security alerts.</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.slice(0,10).map(a => `
    <tr>
      <td class="text-xs fw-600">${escHtml(a.alert_type||'—')}</td>
      <td>${severityBadge(a.severity)}</td>
      <td class="text-secondary text-xs">${escHtml((a.description||'').substring(0,60))}${(a.description||'').length>60?'…':''}</td>
      <td class="text-muted text-xs">${relativeTime(a.timestamp)}</td>
    </tr>
  `).join('');
}
