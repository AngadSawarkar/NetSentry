/**
 * NetSentry – dashboard.js
 * Overview page data loading and charts.
 */

let trafficChart = null;
let protoChart   = null;

// ============================================================
// LOAD SUMMARY STATS
// ============================================================
async function loadSummaryCards() {
  const [devRes, connRes, alertRes, trafficRes] = await Promise.allSettled([
    fetch('/api/devices'),
    fetch('/api/connections'),
    fetch('/api/alerts'),
    fetch('/api/traffic')
  ]);

  // Devices
  if (devRes.status === 'fulfilled' && devRes.value.ok) {
    const d = await devRes.value.json();
    document.getElementById('card-devices').textContent = formatNum(d.total_devices);
    renderRecentDevices(d.devices || []);
  }

  // Connections
  if (connRes.status === 'fulfilled' && connRes.value.ok) {
    const d = await connRes.value.json();
    document.getElementById('card-connections').textContent = formatNum(d.total_connections);
  }

  // Alerts
  if (alertRes.status === 'fulfilled' && alertRes.value.ok) {
    const d = await alertRes.value.json();
    const alerts = d.alerts || [];
    const critical = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
    document.getElementById('card-alerts').textContent   = formatNum(d.total_alerts);
    document.getElementById('card-critical').textContent = formatNum(critical);
    renderRecentAlerts(alerts.slice(0, 8));
  }

  // Traffic
  if (trafficRes.status === 'fulfilled' && trafficRes.value.ok) {
    const d = await trafficRes.value.json();
    const stats = d.traffic_statistics || [];

    if (stats.length > 0) {
      const latest = stats[0];
      document.getElementById('card-packets').textContent = formatNum(latest.total_packets);
      document.getElementById('card-bytes').textContent   = formatBytes(latest.total_bytes);
    } else {
      document.getElementById('card-packets').textContent = '0';
      document.getElementById('card-bytes').textContent   = '0 B';
    }

    renderTrafficChart(stats);
    renderProtoChart(stats);
  }
}

// ============================================================
// RECENT ALERTS TABLE
// ============================================================
function renderRecentAlerts(alerts) {
  const tbody = document.getElementById('recent-alerts-body');
  if (!tbody) return;
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="5">
      <div class="empty-state">
        <i class="bi bi-shield-check"></i>
        <h3>No Alerts</h3>
        <p>No security alerts have been recorded.</p>
      </div>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="text-xs fw-600">${escHtml(a.alert_type || '—')}</span></td>
      <td><span class="ip-cell" onclick="investigateIp('${escHtml(a.source_ip || '')}')">${escHtml(a.source_ip || '—')}</span></td>
      <td><span class="ip-cell" onclick="investigateIp('${escHtml(a.destination_ip || '')}')">${escHtml(a.destination_ip || '—')}</span></td>
      <td>${severityBadge(a.severity)}</td>
      <td class="text-muted text-xs">${relativeTime(a.timestamp)}</td>
    </tr>
  `).join('');
}

// ============================================================
// RECENT DEVICES TABLE
// ============================================================
function renderRecentDevices(devices) {
  const tbody = document.getElementById('recent-devices-body');
  if (!tbody) return;
  if (!devices.length) {
    tbody.innerHTML = `<tr><td colspan="4">
      <div class="empty-state">
        <i class="bi bi-hdd-network"></i>
        <h3>No Devices</h3>
        <p>No devices have been discovered yet.</p>
      </div>
    </td></tr>`;
    return;
  }

  // Show top 6 by last_seen
  const sorted = [...devices].sort((a,b) => (parseDate(b.last_seen)?.getTime() || 0) - (parseDate(a.last_seen)?.getTime() || 0)).slice(0,6);
  tbody.innerHTML = sorted.map(d => `
    <tr>
      <td><span class="ip-cell" onclick="investigateIp('${escHtml(d.ip_address || '')}')">${escHtml(d.ip_address || '—')}</span></td>
      <td><code class="text-muted text-xs">${escHtml(d.mac_address || '—')}</code></td>
      <td class="num-cell">${formatNum(d.packet_count)}</td>
      <td class="text-muted text-xs">${relativeTime(d.last_seen)}</td>
    </tr>
  `).join('');
}

// ============================================================
// TRAFFIC CHART
// ============================================================
function renderTrafficChart(stats) {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;

  // stats is ordered DESC by id; take last 20 and reverse for time order
  const slice = stats.slice(0, 20).reverse();
  const labels  = slice.map(s => {
    if (!s.timestamp) return '';
    const d = parseDate(s.timestamp);
    if (!d) return '';
    return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  });
  const packets = slice.map(s => s.total_packets || 0);
  const bytes   = slice.map(s => (s.total_bytes || 0) / 1024); // KB

  if (trafficChart) trafficChart.destroy();

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Packets',
          data: packets,
          borderColor: '#2f81f7',
          backgroundColor: 'rgba(47,129,247,0.1)',
          borderWidth: 2,
          pointRadius: 3,
          fill: true,
          tension: 0.4,
          yAxisID: 'y'
        },
        {
          label: 'Traffic (KB)',
          data: bytes,
          borderColor: '#3fb950',
          backgroundColor: 'rgba(63,185,80,0.07)',
          borderWidth: 2,
          pointRadius: 3,
          fill: true,
          tension: 0.4,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { position: 'top' } },
      scales: {
        x: { grid: { color: '#21262d' } },
        y: {
          type: 'linear', position: 'left',
          title: { display: true, text: 'Packets', color: '#8b949e' },
          grid: { color: '#21262d' }
        },
        y1: {
          type: 'linear', position: 'right',
          title: { display: true, text: 'Traffic (KB)', color: '#8b949e' },
          grid: { drawOnChartArea: false }
        }
      }
    }
  });
}

function extractPackets(val) {
  if (val == null) return 0;
  if (typeof val === 'number') return val;
  if (typeof val === 'object' && val.packets != null) return Number(val.packets) || 0;
  return 0;
}

// ============================================================
// PROTOCOL CHART
// ============================================================
function renderProtoChart(stats) {
  const ctx = document.getElementById('protoChart');
  if (!ctx) return;

  const agg = { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, Other: 0 };
  for (const s of stats) {
    const p = s.protocol_statistics || {};
    agg.TCP   += extractPackets(p.TCP);
    agg.UDP   += extractPackets(p.UDP);
    agg.ICMP  += extractPackets(p.ICMP);
    agg.DNS   += extractPackets(p.DNS);
    agg.Other += extractPackets(p.Other || p.OTHER);
  }

  const total = Object.values(agg).reduce((a,b) => a+b, 0);
  const labels = Object.keys(agg).filter(k => agg[k] > 0);
  const data   = labels.map(k => agg[k]);

  if (protoChart) protoChart.destroy();

  if (total === 0) {
    document.getElementById('protoChart').closest('.chart-container').innerHTML =
      '<div class="empty-state"><i class="bi bi-pie-chart"></i><p>No protocol data yet</p></div>';
    return;
  }

  protoChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: ['#2f81f7','#39c5cf','#d29922','#3fb950','#bc8cff'],
        borderColor: '#1c2130',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: { legend: { position: 'bottom' } }
    }
  });
}

// ============================================================
// HEALTH STATUS
// ============================================================
async function loadHealth() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const d = await res.json();

    const bOnline = d.backend === 'ONLINE';
    const sOnline = d.sensor  === 'ONLINE';

    document.getElementById('health-backend').innerHTML   = statusPill(bOnline);
    document.getElementById('health-sensor').innerHTML    = statusPill(sOnline);
    document.getElementById('health-iface').textContent   = d.interface || '—';
    document.getElementById('health-heartbeat').textContent = formatTs(d.last_heartbeat);
  } catch {}
}

// ============================================================
// REFRESH ENTRY POINT
// ============================================================
async function refreshPageData() {
  await Promise.allSettled([loadSummaryCards(), loadHealth()]);
}

document.addEventListener('DOMContentLoaded', refreshPageData);
// Auto-refresh every 30 s
setInterval(refreshPageData, 30000);
