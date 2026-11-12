/**
 * NetSentry – reports.js
 */

async function generateReport() {
  const btn    = document.getElementById('generate-report-btn');
  const status = document.getElementById('report-status');
  const title  = document.getElementById('report-title').value.trim() || 'NetSentry Security Report';
  const from   = document.getElementById('report-from').value;
  const to     = document.getElementById('report-to').value;
  const sections = {
    devices:     document.getElementById('sec-devices').checked,
    traffic:     document.getElementById('sec-traffic').checked,
    connections: document.getElementById('sec-connections').checked,
    alerts:      document.getElementById('sec-alerts').checked
  };

  btn.disabled = true;
  btn.innerHTML = '<div class="spinner" style="display:inline-block;margin-right:8px"></div> Generating…';
  status.textContent = 'Fetching data from NetSentry…';

  try {
    const params = new URLSearchParams({ title, from, to, ...Object.fromEntries(Object.entries(sections).map(([k,v])=>[k,v?'1':'0'])) });
    const res = await fetch('/api/reports/generate?' + params.toString());

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Report generation failed');
    }

    // Download the PDF blob
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `netsentry_report_${new Date().toISOString().slice(0,10)}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    status.innerHTML = '<span class="text-green"><i class="bi bi-check-circle-fill"></i> Report downloaded successfully.</span>';
    showToast('PDF report generated and downloaded.', 'success');

  } catch (e) {
    status.innerHTML = `<span class="text-red"><i class="bi bi-x-circle-fill"></i> ${escHtml(e.message)}</span>`;
    showToast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-download"></i> Generate &amp; Download PDF';
  }
}
