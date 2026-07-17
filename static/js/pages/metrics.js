/* Metrics page.
 *
 * Data: GET /metrics/current (tiles + container table), GET /metrics/history
 * (charts), and the `metrics` WS topic, which pushes the same shape as
 * /current. The socket is the live path; the 15s poll below is the fallback for
 * when it is down — the old page polled every 5s unconditionally, which meant
 * the WS updates and the poll fought over the same DOM.
 *
 * Counter semantics matter here: net_*_bytes and disk_*_bytes are cumulative
 * since boot, so a rate is a delta between samples. The tiles show a real rate
 * by differencing consecutive samples; the charts do the same across history.
 */

import { get } from '../core/api.js';
import { h, icon, render, emptyRow, skeletonRows, reportError, wireSegmented } from '../core/ui.js';
import { bytes, rate, percent, num } from '../core/format.js';
import { createChart, destroyChart } from '../core/chart.js';
import * as live from '../core/live.js';

const tilesEl = document.getElementById('tiles');
const bodyEl = document.getElementById('container-body');
const countEl = document.getElementById('container-count');

let charts = {};
let range = '1h';
let prev = null; // previous host sample, for rate calculation

const RANGE_LABEL = { '1h': 'last hour', '6h': 'last 6 hours', '24h': 'last 24 hours', '7d': 'last 7 days', '30d': 'last 30 days' };

/* =======================================================================
   Tiles
   ======================================================================= */

function tile({ key, label, iconName, value, unit, sub, status }) {
  return h(
    'div',
    { class: `stat${status ? ` ${status}` : ''}`, dataset: { key } },
    h('span', { class: 'stat-key' }, icon(iconName), label),
    h('span', { class: 'stat-value' }, value, unit ? h('span', { class: 'unit' }, unit) : null),
    h('span', { class: 'stat-sub' }, sub)
  );
}

const level = (pct, warn, down) => (pct >= down ? 'down' : pct >= warn ? 'warn' : null);

function renderTiles(host) {
  if (!host) {
    render(
      tilesEl,
      h(
        'div',
        { class: 'stat', style: { gridColumn: '1 / -1' } },
        h('span', { class: 'stat-key' }, icon('clock'), 'Waiting'),
        h('span', { class: 'stat-sub' }, 'No sample has completed yet. The collector scrapes this host every few seconds.')
      )
    );
    return;
  }

  // Rates need two samples. Until we have a previous one, say so rather than
  // render a fabricated zero.
  let netRx = null;
  let netTx = null;
  let dRead = null;
  let dWrite = null;
  if (prev && host.ts > prev.ts) {
    const dt = host.ts - prev.ts;
    netRx = Math.max(0, host.net_rx_bytes - prev.net_rx_bytes) / dt;
    netTx = Math.max(0, host.net_tx_bytes - prev.net_tx_bytes) / dt;
    dRead = Math.max(0, host.disk_read_bytes - prev.disk_read_bytes) / dt;
    dWrite = Math.max(0, host.disk_write_bytes - prev.disk_write_bytes) / dt;
  }

  render(
    tilesEl,
    tile({
      key: 'cpu',
      label: 'CPU',
      iconName: 'cpu',
      value: host.cpu_total.toFixed(1),
      unit: '%',
      sub: `load ${host.load_1.toFixed(2)} · ${host.load_5.toFixed(2)} · ${host.load_15.toFixed(2)}`,
      status: level(host.cpu_total, 70, 90),
    }),
    tile({
      key: 'mem',
      label: 'Memory',
      iconName: 'memory-stick',
      value: host.mem_used_pct.toFixed(1),
      unit: '%',
      sub: `${bytes(host.mem_used)} of ${bytes(host.mem_total)}`,
      status: level(host.mem_used_pct, 80, 92),
    }),
    tile({
      key: 'disk',
      label: 'Disk',
      iconName: 'hard-drive',
      value: host.disk_used_pct.toFixed(1),
      unit: '%',
      sub: `${bytes(host.disk_total - host.disk_used)} free of ${bytes(host.disk_total)}`,
      status: level(host.disk_used_pct, 80, 90),
    }),
    tile({
      key: 'net',
      label: 'Network',
      iconName: 'network',
      value: netRx == null ? '—' : rate(netRx),
      sub: netRx == null ? 'waiting for a second sample' : `${rate(netTx)} out`,
    }),
    tile({
      key: 'disk-io',
      label: 'Disk I/O',
      iconName: 'gauge',
      value: dRead == null ? '—' : rate(dRead),
      sub: dRead == null ? 'waiting for a second sample' : `${rate(dWrite)} written`,
    })
  );
}

/* =======================================================================
   Container table
   ======================================================================= */

function renderContainers(containers) {
  countEl.textContent = num(containers.length);

  if (!containers.length) {
    render(bodyEl, emptyRow(5, 'No container stats are being reported.'));
    return;
  }

  render(
    bodyEl,
    ...containers.map((c) => {
      const pct = c.mem_limit ? (c.mem_used / c.mem_limit) * 100 : 0;
      return h(
        'tr',
        {},
        h('td', { class: 'mono' }, c.name),
        h(
          'td',
          {},
          h(
            'div',
            { class: 'usage' },
            h('div', { class: `progress${pct >= 90 ? ' down' : pct >= 75 ? ' warn' : ''}` }, h('div', { class: 'progress-bar', style: { width: `${Math.min(100, c.cpu_pct)}%` } })),
            h('span', { class: 'usage-val' }, percent(c.cpu_pct))
          )
        ),
        h(
          'td',
          {},
          h(
            'div',
            { class: 'usage' },
            h('div', { class: `progress${pct >= 90 ? ' down' : pct >= 75 ? ' warn' : ''}` }, h('div', { class: 'progress-bar', style: { width: `${Math.min(100, pct)}%` } })),
            h('span', { class: 'usage-val' }, bytes(c.mem_used))
          )
        ),
        h('td', { class: 'num' }, bytes(c.net_rx_bytes)),
        h('td', { class: 'num' }, bytes(c.net_tx_bytes))
      );
    })
  );
}

/* =======================================================================
   Charts
   ======================================================================= */

/** Cumulative counter → per-second rate series, aligned to the point after it. */
function toRates(points, field) {
  const out = [];
  for (let i = 0; i < points.length; i++) {
    if (i === 0) {
      out.push(null); // no previous sample; a gap is honest, a 0 is a lie
      continue;
    }
    const dt = points[i].ts - points[i - 1].ts;
    const d = points[i][field] - points[i - 1][field];
    // A counter that went backwards means a reboot or a collector restart —
    // don't draw a negative spike, drop the point.
    out.push(dt > 0 && d >= 0 ? d / dt : null);
  }
  return out;
}

function renderCharts(points) {
  for (const c of Object.values(charts)) destroyChart(c);
  charts = {};

  const hosts = ['chart-cpu', 'chart-mem', 'chart-net', 'chart-disk'].map((id) => document.getElementById(id));
  for (const el of hosts) {
    render(el);
    el.parentElement.querySelector('.chart-legend')?.remove();
  }

  document.getElementById('chart-range-label').textContent = RANGE_LABEL[range];

  if (points.length < 2) {
    for (const el of hosts) {
      render(el, h('p', { class: 'chart-empty' }, 'Not enough samples in this range yet.'));
    }
    document.getElementById('cpu-summary').textContent = '';
    document.getElementById('mem-summary').textContent = '';
    return;
  }

  const xs = points.map((p) => p.ts);

  charts.cpu = createChart(hosts[0], {
    labels: ['CPU'],
    data: [xs, points.map((p) => p.cpu_total)],
    format: (v) => `${v.toFixed(0)}%`,
    yRange: [0, 100],
  });

  charts.mem = createChart(hosts[1], {
    labels: ['Memory'],
    data: [xs, points.map((p) => p.mem_used_pct)],
    format: (v) => `${v.toFixed(0)}%`,
    yRange: [0, 100],
  });

  charts.net = createChart(hosts[2], {
    labels: ['In', 'Out'],
    data: [xs, toRates(points, 'net_rx_bytes'), toRates(points, 'net_tx_bytes')],
    format: (v) => rate(v, 0),
  });

  charts.disk = createChart(hosts[3], {
    labels: ['Read', 'Write'],
    data: [xs, toRates(points, 'disk_read_bytes'), toRates(points, 'disk_write_bytes')],
    format: (v) => rate(v, 0),
  });

  const peak = Math.max(...points.map((p) => p.cpu_total));
  const avg = points.reduce((a, p) => a + p.cpu_total, 0) / points.length;
  document.getElementById('cpu-summary').textContent = `avg ${avg.toFixed(1)}% · peak ${peak.toFixed(1)}%`;
  document.getElementById('mem-summary').textContent = `peak ${Math.max(...points.map((p) => p.mem_used_pct)).toFixed(1)}%`;
}

/* =======================================================================
   Loading
   ======================================================================= */

async function loadCurrent() {
  try {
    const data = await get('/metrics/current');
    if (data.host && prev && data.host.ts === prev.ts) return; // same sample, nothing moved
    renderTiles(data.host);
    if (data.host) prev = data.host;
    renderContainers(data.containers || []);
  } catch (e) {
    reportError(e, "Couldn't load metrics");
  }
}

async function loadHistory() {
  try {
    const data = await get(`/metrics/history?range=${encodeURIComponent(range)}`);
    renderCharts(data.points || []);
  } catch (e) {
    reportError(e, "Couldn't load history");
  }
}

/* =======================================================================
   Boot
   ======================================================================= */

render(tilesEl, ...Array.from({ length: 5 }, () => h('div', { class: 'stat' }, h('div', { class: 'skel skel-line', style: { width: '40%' } }), h('div', { class: 'skel skel-line', style: { width: '65%', height: '20px' } }))));
render(bodyEl, ...skeletonRows(5, 3));

wireSegmented(document.getElementById('range-picker'), (v) => {
  range = v;
  loadHistory();
});

loadCurrent();
loadHistory();

// Live tiles. The payload matches /metrics/current, so both paths render
// through the same functions.
live.subscribe('metrics', (data) => {
  const host = data?.host ?? data;
  if (host?.ts) {
    renderTiles(host);
    prev = host;
  }
  if (data?.containers) renderContainers(data.containers);
});

// Fallback poll — only meaningful while the socket is down. Checking the state
// rather than polling unconditionally is what keeps the two paths from fighting.
setInterval(() => {
  if (live.getState() !== 'live') loadCurrent();
}, 15_000);

// History doesn't stream; refresh it occasionally so a long-open page keeps up.
setInterval(loadHistory, 120_000);
