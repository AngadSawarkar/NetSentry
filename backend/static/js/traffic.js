/**
 * NetSentry – traffic.js
 */

let allConnections   = [];
let filteredConns    = [];
let connPage         = 1;
const CONN_PAGE_SIZE = 25;
let trafficLineChart = null;
let trafficProtoChart = null;

// ============================================================
// LOAD DATA
// ============================================================
async function loadTrafficData() {
  const [connRes, trafficRes] = await Promise.allSettled([
    fetch('/api/connections'),
    fetch('/api/traffic')
  ]);

  if (connRes.status === 'fulfilled' && connRes.value.ok) {
    const d = await connRes.value.json();
    allConnections = d.connections || [];
    applyConnFilters();
  }

  if (trafficRes.status === 'fulfilled' && trafficRes.value.ok) {
    const d = await trafficRes.value.json();
    renderTrafficLineChart(d.traffic_statistics || []);
    renderTrafficProtoChart(d.traffic_statistics || []);
  }
}

// ============================================================
// FILTERS
// ============================================================
function applyConnFilters() {
  const search = (document.getElementById('conn-search').value || '').toLowerCase().trim();
  const proto  = (document.getElementById('conn-proto-filter').value || '').toUpperCase();
  const sort   = document.getElementById('conn-sort').value || 'last_seen_desc';

  let list = allConnections.filter(c => {
    if (proto && (c.protocol || '').toUpperCase() !== proto) return false;
    if (search) {
      const src = (c.source_ip || '').toLowerCase();
      const dst = (c.destination_ip || '').toLowerCase();
      if (!src.includes(search) && !dst.includes(search)) return false;
    }
    return true;
  });

  // Sort
  list.sort((a,b) => {
    if (sort === 'packets_desc') return (b.packet_count||0) - (a.packet_count||0);
    if (sort === 'bytes_desc')   return (b.total_bytes||0)  - (a.total_bytes||0);
    // last_seen_desc (default)
    return (parseDate(b.last_seen)?.getTime() || 0) - (parseDate(a.last_seen)?.getTime() || 0);
  });

  filteredConns = list;
  connPage = 1;
  renderConnTable();
}

// ============================================================
// TABLE RENDER
// ============================================================
function renderConnTable() {
  const tbody = document.getElementById('traffic-table-body');
  const start = (connPage-1)*CONN_PAGE_SIZE;
  const slice = filteredConns.slice(start, start+CONN_PAGE_SIZE);

  if (!filteredConns.length) {
    tbody.innerHTML = `<tr><td colspan="9">
      <div class="empty-state">
        <i class="bi bi-diagram-3"></i>
        <h3>No Traffic Records</h3>
        <p>No network flow records match your filters. Try adjusting the search.</p>
      </div>
    </td></tr>`;
  } else {
    tbody.innerHTML = slice.map(c => `
      <tr>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.source_ip||'')}')">${escHtml(c.source_ip||'—')}</span></td>
        <td><span class="ip-cell" onclick="investigateIp('${escHtml(c.destination_ip||'')}')">${escHtml(c.destination_ip||'—')}</span></td>
        <td>${protoBadge(c.protocol)}</td>
        <td class="port-cell">${escHtml(String(c.source_port||'—'))}</td>
        <td class="port-cell">${escHtml(String(c.destination_port||'—'))}</td>
        <td class="num-cell">${formatNum(c.packet_count)}</td>
        <td class="bytes-cell">${formatBytes(c.total_bytes)}</td>
        <td class="text-muted text-xs">${formatTs(c.first_seen)}</td>
        <td class="text-muted text-xs">${relativeTime(c.last_seen)}</td>
      </tr>
    `).join('');
  }

  // Update pagination
  const totalPages = Math.max(1, Math.ceil(filteredConns.length / CONN_PAGE_SIZE));
  const start2 = Math.min((connPage-1)*CONN_PAGE_SIZE+1, filteredConns.length);
  const end2   = Math.min(connPage*CONN_PAGE_SIZE, filteredConns.length);

  const info     = document.getElementById('traffic-page-info');
  const controls = document.getElementById('traffic-page-controls');
  if (info) info.textContent = filteredConns.length === 0 ? 'No results' : `${start2}–${end2} of ${filteredConns.length}`;

  if (controls) {
    let html = `<button class="page-btn" ${connPage===1?'disabled':''} onclick="goConnPage(${connPage-1})"><i class="bi bi-chevron-left"></i></button>`;
    const sp = Math.max(1, connPage-2), ep = Math.min(totalPages, sp+4);
    for (let p = Math.max(1, ep-4); p <= ep; p++) {
      html += `<button class="page-btn ${p===connPage?'active':''}" onclick="goConnPage(${p})">${p}</button>`;
    }
    html += `<button class="page-btn" ${connPage===totalPages?'disabled':''} onclick="goConnPage(${connPage+1})"><i class="bi bi-chevron-right"></i></button>`;
    controls.innerHTML = html;
  }

  const countLabel = document.getElementById('conn-count-label');
  if (countLabel) countLabel.textContent = filteredConns.length + ' record(s)';
}

function goConnPage(page) {
  connPage = page;
  renderConnTable();
}

// ============================================================
// CHARTS
// ============================================================
function renderTrafficLineChart(stats) {
  const ctx = document.getElementById('trafficLineChart');
  if (!ctx) return;
  const slice = stats.slice(0, 25).reverse();
  const labels  = slice.map(s => {
    if (!s.timestamp) return '';
    const d = parseDate(s.timestamp);
    if (!d) return '';
    return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  });
  const packets = slice.map(s => s.total_packets||0);
  const bytes   = slice.map(s => (s.total_bytes||0)/1024);

  if (trafficLineChart) trafficLineChart.destroy();
  trafficLineChart = new Chart(ctx, {
    type:'line',
    data:{
      labels,
      datasets:[
        {label:'Packets',data:packets,borderColor:'#2f81f7',backgroundColor:'rgba(47,129,247,0.1)',fill:true,tension:0.4,borderWidth:2,pointRadius:2,yAxisID:'y'},
        {label:'KB',    data:bytes,  borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,0.07)', fill:true,tension:0.4,borderWidth:2,pointRadius:2,yAxisID:'y1'}
      ]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      interaction:{mode:'index',intersect:false},
      plugins:{legend:{position:'top'}},
      scales:{
        x:{grid:{color:'#21262d'}},
        y:{grid:{color:'#21262d'},title:{display:true,text:'Packets',color:'#8b949e'}},
        y1:{position:'right',grid:{drawOnChartArea:false},title:{display:true,text:'KB',color:'#8b949e'}}
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

function renderTrafficProtoChart(stats) {
  const ctx = document.getElementById('trafficProtoChart');
  if (!ctx) return;
  const agg = {TCP:0,UDP:0,ICMP:0,DNS:0,Other:0};
  for (const s of stats) {
    const p = s.protocol_statistics||{};
    agg.TCP   += extractPackets(p.TCP);
    agg.UDP   += extractPackets(p.UDP);
    agg.ICMP  += extractPackets(p.ICMP);
    agg.DNS   += extractPackets(p.DNS);
    agg.Other += extractPackets(p.Other || p.OTHER);
  }
  const labels = Object.keys(agg).filter(k=>agg[k]>0);
  const data   = labels.map(k=>agg[k]);
  if (!data.length) {
    ctx.closest('.chart-container').innerHTML = '<div class="empty-state"><i class="bi bi-pie-chart"></i><p>No data yet</p></div>';
    return;
  }
  if (trafficProtoChart) trafficProtoChart.destroy();
  trafficProtoChart = new Chart(ctx,{
    type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:['#2f81f7','#39c5cf','#d29922','#3fb950','#bc8cff'],borderColor:'#1c2130',borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',plugins:{legend:{position:'bottom'}}}
  });
}

// ============================================================
// ENTRY POINT
// ============================================================
async function refreshPageData() { await loadTrafficData(); }
document.addEventListener('DOMContentLoaded', loadTrafficData);

// Enter key on search
document.addEventListener('DOMContentLoaded', () => {
  const inp = document.getElementById('conn-search');
  if (inp) inp.addEventListener('keydown', e => { if (e.key==='Enter') applyConnFilters(); });
});

// Auto-refresh every 20 s
setInterval(loadTrafficData, 20000);
