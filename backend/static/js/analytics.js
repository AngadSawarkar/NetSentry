/**
 * NetSentry – analytics.js
 */
let analyticsHours = 1;
let aTrafficChart, aProtoChart, aAlertChart, aAlertTypeChart;

function setTimeRange(btn, hours) {
  document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  analyticsHours = hours;
  loadAnalytics();
}

function filterByHours(list, tsField, hours) {
  if (!hours) return list;
  const cutoff = Date.now() - hours*3600*1000;
  return list.filter(r => {
    const ts = r[tsField];
    if (!ts) return false;
    const d = parseDate(ts);
    return d ? d.getTime() >= cutoff : false;
  });
}

async function loadAnalytics() {
  const label = document.getElementById('analytics-range-label');
  if (label) label.textContent = analyticsHours ? `Showing last ${analyticsHours < 24 ? analyticsHours+'h' : (analyticsHours/24)+'d'}` : 'All time';

  const [trafficRes, connRes, alertRes, devRes] = await Promise.allSettled([
    fetch('/api/traffic'),
    fetch('/api/connections'),
    fetch('/api/alerts'),
    fetch('/api/devices')
  ]);

  let trafficData = [], connData = [], alertData = [], devData = [];

  if (trafficRes.status==='fulfilled' && trafficRes.value.ok) {
    const d = await trafficRes.value.json();
    trafficData = filterByHours(d.traffic_statistics||[], 'timestamp', analyticsHours);
  }
  if (connRes.status==='fulfilled' && connRes.value.ok) {
    const d = await connRes.value.json();
    connData = filterByHours(d.connections||[], 'last_seen', analyticsHours);
  }
  if (alertRes.status==='fulfilled' && alertRes.value.ok) {
    const d = await alertRes.value.json();
    alertData = filterByHours(d.alerts||[], 'timestamp', analyticsHours);
  }
  if (devRes.status==='fulfilled' && devRes.value.ok) {
    const d = await devRes.value.json();
    devData = d.devices||[];
  }

  renderAnalyticsTraffic(trafficData);
  renderAnalyticsProto(trafficData, connData);
  renderAnalyticsAlerts(alertData);
  renderAlertTypes(alertData);
  renderTopDevices(devData);
  renderTopSrc(connData);
  renderTopPorts(connData);
}

// ============================================================
function renderAnalyticsTraffic(stats) {
  const ctx = document.getElementById('analyticsTrafficChart');
  if (!ctx) return;
  const slice = stats.slice().reverse();
  const labels  = slice.map(s=>{
    if (!s.timestamp) return '';
    const d = parseDate(s.timestamp);
    if (!d) return '';
    if (analyticsHours<=24) return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    return d.toLocaleDateString([],{month:'short',day:'numeric'});
  });
  const packets = slice.map(s=>s.total_packets||0);
  const bytes   = slice.map(s=>(s.total_bytes||0)/1024);

  if (aTrafficChart) aTrafficChart.destroy();
  aTrafficChart = new Chart(ctx,{
    type:'line',
    data:{labels,datasets:[
      {label:'Packets',data:packets,borderColor:'#2f81f7',backgroundColor:'rgba(47,129,247,0.1)',fill:true,tension:0.4,borderWidth:2,pointRadius:2,yAxisID:'y'},
      {label:'KB',    data:bytes,  borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,0.07)', fill:true,tension:0.4,borderWidth:2,pointRadius:2,yAxisID:'y1'}
    ]},
    options:{responsive:true,maintainAspectRatio:false,
      interaction:{mode:'index',intersect:false},plugins:{legend:{position:'top'}},
      scales:{x:{grid:{color:'#21262d'}},
        y:{grid:{color:'#21262d'},title:{display:true,text:'Packets',color:'#8b949e'}},
        y1:{position:'right',grid:{drawOnChartArea:false},title:{display:true,text:'KB',color:'#8b949e'}}
      }}
  });
}

function extractPackets(val) {
  if (val == null) return 0;
  if (typeof val === 'number') return val;
  if (typeof val === 'object' && val.packets != null) return Number(val.packets) || 0;
  return 0;
}

function renderAnalyticsProto(stats, conns) {
  const ctx = document.getElementById('analyticsProtoChart');
  if (!ctx) return;
  const agg = {TCP:0,UDP:0,ICMP:0,DNS:0,Other:0};
  for (const s of stats) {
    const p=s.protocol_statistics||{};
    agg.TCP   += extractPackets(p.TCP);
    agg.UDP   += extractPackets(p.UDP);
    agg.ICMP  += extractPackets(p.ICMP);
    agg.DNS   += extractPackets(p.DNS);
    agg.Other += extractPackets(p.Other || p.OTHER);
  }
  // Fallback to connections if traffic has no proto data
  if (!Object.values(agg).some(v=>v>0)) {
    for (const c of conns) {
      const p=(c.protocol||'').toUpperCase();
      if (agg[p]!==undefined) agg[p]++;
      else agg.Other++;
    }
  }
  const labels=Object.keys(agg).filter(k=>agg[k]>0);
  const data=labels.map(k=>agg[k]);
  if (!data.length) {
    ctx.closest('.chart-container').innerHTML='<div class="empty-state"><i class="bi bi-pie-chart"></i><p>No data for selected range</p></div>';
    return;
  }
  if (aProtoChart) aProtoChart.destroy();
  aProtoChart=new Chart(ctx,{type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:['#2f81f7','#39c5cf','#d29922','#3fb950','#bc8cff'],borderColor:'#1c2130',borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',plugins:{legend:{position:'bottom'}}}
  });
}

function renderAnalyticsAlerts(alerts) {
  const ctx = document.getElementById('analyticsAlertChart');
  if (!ctx) return;
  // Group by day
  const counts = {};
  for (const a of alerts) {
    if (!a.timestamp) continue;
    const d = parseDate(a.timestamp);
    if (!d) continue;
    const key = d.toLocaleDateString([],{month:'short',day:'numeric'});
    counts[key] = (counts[key]||0)+1;
  }
  const labels = Object.keys(counts);
  const data   = labels.map(k=>counts[k]);
  if (!data.length) {
    ctx.closest('.chart-container').innerHTML='<div class="empty-state"><i class="bi bi-bar-chart"></i><p>No alerts in selected range</p></div>';
    return;
  }
  if (aAlertChart) aAlertChart.destroy();
  aAlertChart=new Chart(ctx,{type:'bar',
    data:{labels,datasets:[{label:'Alerts',data,backgroundColor:'rgba(248,81,73,0.4)',borderColor:'#f85149',borderWidth:1,borderRadius:3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{color:'#21262d'}},y:{grid:{color:'#21262d'},beginAtZero:true}}}
  });
}

function renderAlertTypes(alerts) {
  const ctx = document.getElementById('analyticsAlertTypeChart');
  if (!ctx) return;
  const counts = {};
  for (const a of alerts) { const t=a.alert_type||'Unknown'; counts[t]=(counts[t]||0)+1; }
  const labels=Object.keys(counts);
  const data=labels.map(k=>counts[k]);
  if (!data.length) {
    ctx.closest('.chart-container').innerHTML='<div class="empty-state"><i class="bi bi-pie-chart"></i><p>No alerts in selected range</p></div>';
    return;
  }
  if (aAlertTypeChart) aAlertTypeChart.destroy();
  aAlertTypeChart=new Chart(ctx,{type:'bar',
    data:{labels,datasets:[{label:'Count',data,backgroundColor:['rgba(248,81,73,0.5)','rgba(210,153,34,0.5)','rgba(47,129,247,0.5)','rgba(63,185,80,0.5)','rgba(188,140,255,0.5)','rgba(57,197,207,0.5)'],borderColor:['#f85149','#d29922','#2f81f7','#3fb950','#bc8cff','#39c5cf'],borderWidth:1,borderRadius:3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{color:'#21262d'},ticks:{maxRotation:20}},y:{grid:{color:'#21262d'},beginAtZero:true}}}
  });
}

function renderTopDevices(devs) {
  const tbody=document.getElementById('top-devices-body');
  const top=devs.slice().sort((a,b)=>(b.packet_count||0)-(a.packet_count||0)).slice(0,10);
  if (!top.length){tbody.innerHTML='<tr><td colspan="3"><div class="empty-state" style="padding:16px"><p>No data</p></div></td></tr>';return;}
  tbody.innerHTML=top.map(d=>`<tr>
    <td><span class="ip-cell" onclick="investigateIp('${escHtml(d.ip_address||'')}')">${escHtml(d.ip_address||'—')}</span></td>
    <td class="num-cell">${formatNum(d.packet_count)}</td>
    <td class="bytes-cell">${formatBytes(d.total_bytes)}</td>
  </tr>`).join('');
}

function renderTopSrc(conns) {
  const tbody=document.getElementById('top-src-body');
  const agg={};
  for (const c of conns) {
    const ip=c.source_ip||'—';
    if (!agg[ip]) agg[ip]={packets:0,conns:0};
    agg[ip].packets+=(c.packet_count||0);
    agg[ip].conns++;
  }
  const top=Object.entries(agg).sort((a,b)=>b[1].packets-a[1].packets).slice(0,10);
  if (!top.length){tbody.innerHTML='<tr><td colspan="3"><div class="empty-state" style="padding:16px"><p>No data</p></div></td></tr>';return;}
  tbody.innerHTML=top.map(([ip,v]) => `<tr>
    <td><span class="ip-cell" onclick="investigateIp('${escHtml(ip)}')">${escHtml(ip)}</span></td>
    <td class="num-cell">${formatNum(v.packets)}</td>
    <td class="num-cell">${v.conns}</td>
  </tr>`).join('');
}

function renderTopPorts(conns) {
  const tbody=document.getElementById('top-ports-body');
  const agg={};
  for (const c of conns) {
    const key=`${c.destination_port||0}|${(c.protocol||'').toUpperCase()}`;
    agg[key]=(agg[key]||0)+1;
  }
  const top=Object.entries(agg).sort((a,b)=>b[1]-a[1]).slice(0,10);
  if (!top.length){tbody.innerHTML='<tr><td colspan="3"><div class="empty-state" style="padding:16px"><p>No data</p></div></td></tr>';return;}
  tbody.innerHTML=top.map(([key,cnt])=>{
    const [port,proto]=key.split('|');
    return `<tr>
      <td class="port-cell">${escHtml(port)}</td>
      <td>${protoBadge(proto)}</td>
      <td class="num-cell">${cnt}</td>
    </tr>`;
  }).join('');
}

async function refreshPageData() { await loadAnalytics(); }
document.addEventListener('DOMContentLoaded', loadAnalytics);
