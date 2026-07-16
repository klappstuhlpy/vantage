/* ── Live metrics dashboard ──────────────────────────────────────
   - polls /metrics/current every 5s for the tile row + container table
   - refetches /metrics/history when the range picker changes (and on load)
   - renders four uPlot charts (CPU+Load, Memory, Network, Temperature)
   ──────────────────────────────────────────────────────────────── */

const LIVE_POLL_MS = 5_000;
let currentRange = "1h";

const charts = {};          // chart-id → uPlot instance
let lastNetRx = null;       // for live throughput calculation in tiles
let lastNetTs = null;
let lastDiskRead = null;    // for live disk-I/O calculation in tiles
let lastDiskWrite = null;
let lastDiskOps = null;     // {read, write}
let lastDiskTs = null;

/* ── helpers ─────────────────────────────────────────────────── */

function fmtBytes(n) {
  if (n == null || !isFinite(n)) return "—";
  if (n === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i = Math.floor(Math.log(Math.abs(n)) / Math.log(k));
  return (n / Math.pow(k, i)).toFixed(i ? 1 : 0) + " " + sizes[i];
}

function fmtRate(bytesPerSec) {
  if (bytesPerSec == null || !isFinite(bytesPerSec)) return "—";
  return fmtBytes(bytesPerSec) + "/s";
}

function statusClassFor(pct, warn = 70, alert = 90) {
  if (pct == null) return "";
  if (pct >= alert) return "alert";
  if (pct >= warn)  return "warn";
  return "";
}

/* ── live tiles ──────────────────────────────────────────────── */

async function pollCurrent() {
  try {
    const res = await fetch("/metrics/current");
    if (!res.ok) return;
    const data = await res.json();

    const host = data.host;
    if (host) {
      // CPU
      document.getElementById("tile-cpu-pct").textContent = host.cpu_total.toFixed(1);
      document.getElementById("tile-cpu-load").textContent =
        `load ${host.load_1.toFixed(2)} · ${host.load_5.toFixed(2)} · ${host.load_15.toFixed(2)}`;
      document.getElementById("tile-cpu-status").className = "tile-status " + statusClassFor(host.cpu_total);

      // Memory
      document.getElementById("tile-mem-pct").textContent = host.mem_used_pct.toFixed(1);
      document.getElementById("tile-mem-detail").textContent =
        `${fmtBytes(host.mem_used)} / ${fmtBytes(host.mem_total)}`;
      document.getElementById("tile-mem-status").className = "tile-status " + statusClassFor(host.mem_used_pct);

      // Disk
      document.getElementById("tile-disk-pct").textContent = host.disk_used_pct.toFixed(1);
      document.getElementById("tile-disk-detail").textContent =
        `${fmtBytes(host.disk_used)} / ${fmtBytes(host.disk_total)}`;
      document.getElementById("tile-disk-status").className = "tile-status " + statusClassFor(host.disk_used_pct, 80, 90);

      // Disk I/O throughput: delta vs previous poll
      if (lastDiskRead != null && lastDiskTs != null && host.ts > lastDiskTs) {
        const dt = host.ts - lastDiskTs;
        const rRate = (host.disk_read_bytes - lastDiskRead) / dt;
        const wRate = (host.disk_write_bytes - lastDiskWrite) / dt;
        const rOps  = (host.disk_read_ops  - lastDiskOps.read)  / dt;
        const wOps  = (host.disk_write_ops - lastDiskOps.write) / dt;
        document.getElementById("tile-disk-read").textContent  = fmtRate(Math.max(0, rRate));
        document.getElementById("tile-disk-write").textContent = fmtRate(Math.max(0, wRate));
        document.getElementById("tile-disk-iops").textContent  =
          `${(Math.max(0, rOps) + Math.max(0, wOps)).toFixed(0)} IOPS`;
      }
      lastDiskRead  = host.disk_read_bytes;
      lastDiskWrite = host.disk_write_bytes;
      lastDiskOps   = { read: host.disk_read_ops, write: host.disk_write_ops };
      lastDiskTs    = host.ts;

      // Network throughput: delta vs previous poll
      if (lastNetRx != null && lastNetTs != null && host.ts > lastNetTs) {
        const dt = host.ts - lastNetTs;
        const rxRate = (host.net_rx_bytes - lastNetRx.rx) / dt;
        const txRate = (host.net_tx_bytes - lastNetRx.tx) / dt;
        document.getElementById("tile-net-rx").textContent = fmtRate(Math.max(0, rxRate));
        document.getElementById("tile-net-tx").textContent = fmtRate(Math.max(0, txRate));
      }
      lastNetRx = { rx: host.net_rx_bytes, tx: host.net_tx_bytes };
      lastNetTs = host.ts;
    }

    // Container table
    const tbody = document.querySelector("#container-table tbody");
    document.getElementById("container-count").textContent = data.containers.length;
    if (data.containers.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No running containers</td></tr>';
    } else {
      tbody.innerHTML = data.containers.map(c => {
        const memPct = c.mem_limit > 0 ? (c.mem_used / c.mem_limit * 100) : 0;
        return `<tr>
          <td>${escapeHtml(c.name)}</td>
          <td><div class="bar-cell"><span>${c.cpu_pct.toFixed(1)}%</span>
              <div class="bar ${statusClassFor(c.cpu_pct)}"><span style="width:${Math.min(c.cpu_pct, 100)}%"></span></div></div></td>
          <td><div class="bar-cell"><span>${fmtBytes(c.mem_used)} / ${fmtBytes(c.mem_limit)}</span>
              <div class="bar ${statusClassFor(memPct)}"><span style="width:${Math.min(memPct, 100)}%"></span></div></div></td>
          <td class="numeric">↓ ${fmtBytes(c.net_rx_bytes)} · ↑ ${fmtBytes(c.net_tx_bytes)}</td>
        </tr>`;
      }).join("");
    }
  } catch (e) {
    console.error("current poll failed:", e);
  }
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ── chart setup ─────────────────────────────────────────────── */

function chartSize(el) {
  const w = el.parentElement.clientWidth - 32;   // subtract panel padding
  return { width: Math.max(200, w), height: 220 };
}

function commonOpts(title, scales, series, el) {
  return {
    ...chartSize(el),
    cursor: { drag: { setScale: false } },
    legend: { live: true },
    scales,
    series,
    axes: [
      { stroke: "#71717a" },
      { stroke: "#71717a", grid: { stroke: "rgba(127,127,127,0.15)" } },
    ],
  };
}

function buildChart(id, opts) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  const size = chartSize(el);
  charts[id] = new uPlot({ ...opts, ...size }, opts.data, el);
}

/* ── load history + render charts ─────────────────────────────── */

function showChartMessage(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = `<div class="chart-message">${escapeHtml(msg)}</div>`;
}

const CHART_IDS = ["chart-cpu", "chart-mem", "chart-net", "chart-disk-io"];

async function loadHistory() {
  try {
    const res = await fetch(`/metrics/history?range=${encodeURIComponent(currentRange)}`);
    if (!res.ok) {
      CHART_IDS.forEach(id => showChartMessage(id, `History endpoint returned HTTP ${res.status}`));
      return;
    }
    const data = await res.json();
    const points = data.points || [];
    if (points.length < 2) {
      CHART_IDS.forEach(id =>
        showChartMessage(id, points.length === 0
          ? "No samples yet — first scrape lands ~30s after startup."
          : "Only one sample so far — charts appear after the next scrape."));
      return;
    }
    renderCharts(points);
  } catch (e) {
    console.error("history load failed:", e);
    CHART_IDS.forEach(id => showChartMessage(id, "Failed to load history: " + (e && e.message || e)));
  }
}

function renderCharts(points) {
  if (!window.uPlot) {
    CHART_IDS.forEach(id => showChartMessage(id, "uPlot library failed to load (CDN blocked?)."));
    return;
  }

  const xs = points.map(p => p.ts);
  const cpu = points.map(p => p.cpu_total);
  const load = points.map(p => p.load_1);
  const mem = points.map(p => p.mem_used_pct);
  const disk = points.map(p => p.disk_used_pct);

  // Network: convert cumulative byte counters into rate (bytes/s) using deltas
  const netRx = [];
  const netTx = [];
  const diskR = [];
  const diskW = [];
  for (let i = 0; i < points.length; i++) {
    if (i === 0) {
      netRx.push(null); netTx.push(null);
      diskR.push(null); diskW.push(null);
      continue;
    }
    const dt = points[i].ts - points[i-1].ts;
    if (dt <= 0) {
      netRx.push(null); netTx.push(null);
      diskR.push(null); diskW.push(null);
      continue;
    }
    netRx.push(Math.max(0, points[i].net_rx_bytes - points[i-1].net_rx_bytes) / dt);
    netTx.push(Math.max(0, points[i].net_tx_bytes - points[i-1].net_tx_bytes) / dt);
    diskR.push(Math.max(0, points[i].disk_read_bytes  - points[i-1].disk_read_bytes)  / dt);
    diskW.push(Math.max(0, points[i].disk_write_bytes - points[i-1].disk_write_bytes) / dt);
  }

  rebuildChart("chart-cpu", {
    data: [xs, cpu, load],
    series: [
      {},
      { label: "CPU %",   stroke: "#7c3aed", width: 1.5 },
      { label: "Load 1m", stroke: "#fbbf24", width: 1.5, scale: "load" },
    ],
    scales: { x: { time: true }, y: { range: [0, 100] }, load: { auto: true } },
    axes: [
      { stroke: "#71717a" },
      { stroke: "#71717a", grid: { stroke: "rgba(127,127,127,0.15)" }, values: (u, v) => v.map(x => x + "%") },
      { stroke: "#fbbf24", side: 1, scale: "load", grid: { show: false } },
    ],
  });

  rebuildChart("chart-mem", {
    data: [xs, mem, disk],
    series: [
      {},
      { label: "RAM %",  stroke: "#60a5fa", width: 1.5 },
      { label: "Disk %", stroke: "#a78bfa", width: 1.5 },
    ],
    scales: { x: { time: true }, y: { range: [0, 100] } },
    axes: [
      { stroke: "#71717a" },
      { stroke: "#71717a", grid: { stroke: "rgba(127,127,127,0.15)" }, values: (u, v) => v.map(x => x + "%") },
    ],
  });

  rebuildChart("chart-net", {
    data: [xs, netRx, netTx],
    series: [
      {},
      { label: "↓ Recv", stroke: "#86efac", width: 1.5, value: (u, v) => fmtRate(v) },
      { label: "↑ Send", stroke: "#f87171", width: 1.5, value: (u, v) => fmtRate(v) },
    ],
    scales: { x: { time: true } },
    axes: [
      { stroke: "#71717a" },
      { stroke: "#71717a", grid: { stroke: "rgba(127,127,127,0.15)" }, values: (u, v) => v.map(fmtRate) },
    ],
  });

  rebuildChart("chart-disk-io", {
    data: [xs, diskR, diskW],
    series: [
      {},
      { label: "↓ Read",  stroke: "#67e8f9", width: 1.5, value: (u, v) => fmtRate(v) },
      { label: "↑ Write", stroke: "#fb923c", width: 1.5, value: (u, v) => fmtRate(v) },
    ],
    scales: { x: { time: true } },
    axes: [
      { stroke: "#71717a" },
      { stroke: "#71717a", grid: { stroke: "rgba(127,127,127,0.15)" }, values: (u, v) => v.map(fmtRate) },
    ],
  });
}

function rebuildChart(id, cfg) {
  const el = document.getElementById(id);
  if (!el) {
    console.error("missing chart container:", id);
    return;
  }
  el.innerHTML = "";
  try {
    const { width, height } = chartSize(el);
    if (charts[id]) {
      charts[id].destroy();
    }
    charts[id] = new uPlot({ width, height, ...cfg }, cfg.data, el);
  } catch (e) {
    console.error("chart render failed:", id, e);
    showChartMessage(id, `Render error: ${e && e.message || e}`);
  }
}

/* ── range picker ────────────────────────────────────────────── */

document.querySelectorAll("#range-picker .button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#range-picker .button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    currentRange = btn.dataset.range;
    loadHistory();
  });
});

/* ── resize handler ──────────────────────────────────────────── */

let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => loadHistory(), 200);
});

/* ── boot ────────────────────────────────────────────────────── */

pollCurrent();
loadHistory();
let pollTimer = setInterval(pollCurrent, LIVE_POLL_MS);

/* ── WebSocket: push-based tile updates ──────────────────────
   When the server pushes a "metrics" event we apply it directly
   instead of polling on a timer. Polling stays as a fallback that
   activates whenever the socket is closed/reconnecting. */

function applyMetricsEvent(m) {
  const host = {
    ts: m.ts,
    cpu_total: m.cpu_total,
    cpu_user: 0, cpu_system: 0, cpu_iowait: 0, cpu_idle: 100 - m.cpu_total,
    load_1: m.load_1, load_5: m.load_5, load_15: m.load_15,
    mem_total: m.mem_total, mem_used: m.mem_used, mem_used_pct: m.mem_used_pct,
    swap_total: 0, swap_used: 0, mem_cached: 0,
    net_rx_bytes: m.net_rx_bytes, net_tx_bytes: m.net_tx_bytes,
    disk_read_bytes:  m.disk_read_bytes,
    disk_write_bytes: m.disk_write_bytes,
    disk_read_ops:    m.disk_read_ops,
    disk_write_ops:   m.disk_write_ops,
    disk_total: m.disk_total, disk_used: m.disk_used, disk_used_pct: m.disk_used_pct,
  };
  // Pretend we got the standard /current shape.
  renderCurrent({ host, containers: m.containers || [] });
}

// Refactor: extract the existing pollCurrent body into something reusable.
function renderCurrent(data) {
  const host = data.host;
  if (host) {
    document.getElementById("tile-cpu-pct").textContent = host.cpu_total.toFixed(1);
    document.getElementById("tile-cpu-load").textContent =
      `load ${host.load_1.toFixed(2)} · ${host.load_5.toFixed(2)} · ${host.load_15.toFixed(2)}`;
    document.getElementById("tile-cpu-status").className = "tile-status " + statusClassFor(host.cpu_total);
    document.getElementById("tile-mem-pct").textContent = host.mem_used_pct.toFixed(1);
    document.getElementById("tile-mem-detail").textContent = `${fmtBytes(host.mem_used)} / ${fmtBytes(host.mem_total)}`;
    document.getElementById("tile-mem-status").className = "tile-status " + statusClassFor(host.mem_used_pct);
    document.getElementById("tile-disk-pct").textContent = host.disk_used_pct.toFixed(1);
    document.getElementById("tile-disk-detail").textContent = `${fmtBytes(host.disk_used)} / ${fmtBytes(host.disk_total)}`;
    document.getElementById("tile-disk-status").className = "tile-status " + statusClassFor(host.disk_used_pct, 80, 90);

    if (lastDiskRead != null && lastDiskTs != null && host.ts > lastDiskTs) {
      const dt = host.ts - lastDiskTs;
      const rRate = (host.disk_read_bytes  - lastDiskRead)  / dt;
      const wRate = (host.disk_write_bytes - lastDiskWrite) / dt;
      const rOps  = (host.disk_read_ops  - lastDiskOps.read)  / dt;
      const wOps  = (host.disk_write_ops - lastDiskOps.write) / dt;
      document.getElementById("tile-disk-read").textContent  = fmtRate(Math.max(0, rRate));
      document.getElementById("tile-disk-write").textContent = fmtRate(Math.max(0, wRate));
      document.getElementById("tile-disk-iops").textContent  =
        `${(Math.max(0, rOps) + Math.max(0, wOps)).toFixed(0)} IOPS`;
    }
    lastDiskRead  = host.disk_read_bytes;
    lastDiskWrite = host.disk_write_bytes;
    lastDiskOps   = { read: host.disk_read_ops, write: host.disk_write_ops };
    lastDiskTs    = host.ts;

    if (lastNetRx != null && lastNetTs != null && host.ts > lastNetTs) {
      const dt = host.ts - lastNetTs;
      document.getElementById("tile-net-rx").textContent = fmtRate(Math.max(0, (host.net_rx_bytes - lastNetRx.rx) / dt));
      document.getElementById("tile-net-tx").textContent = fmtRate(Math.max(0, (host.net_tx_bytes - lastNetRx.tx) / dt));
    }
    lastNetRx = { rx: host.net_rx_bytes, tx: host.net_tx_bytes };
    lastNetTs = host.ts;
  }

  const tbody = document.querySelector("#container-table tbody");
  document.getElementById("container-count").textContent = data.containers.length;
  if (data.containers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">No running containers</td></tr>';
  } else {
    tbody.innerHTML = data.containers.map(c => {
      const memPct = c.mem_limit > 0 ? (c.mem_used / c.mem_limit * 100) : 0;
      return `<tr>
        <td>${escapeHtml(c.name)}</td>
        <td><div class="bar-cell"><span>${c.cpu_pct.toFixed(1)}%</span>
            <div class="bar ${statusClassFor(c.cpu_pct)}"><span style="width:${Math.min(c.cpu_pct, 100)}%"></span></div></div></td>
        <td><div class="bar-cell"><span>${fmtBytes(c.mem_used)} / ${fmtBytes(c.mem_limit)}</span>
            <div class="bar ${statusClassFor(memPct)}"><span style="width:${Math.min(memPct, 100)}%"></span></div></div></td>
        <td class="numeric">↓ ${fmtBytes(c.net_rx_bytes)} · ↑ ${fmtBytes(c.net_tx_bytes)}</td>
      </tr>`;
    }).join("");
  }
}

if (window.LiveConnection) {
  const conn = new LiveConnection({
    topics: ["metrics"],
    onEvent: (topic, data) => {
      if (topic === "metrics") applyMetricsEvent(data);
    },
    onStateChange: (state) => {
      // Pause polling whenever we have a live stream so we don't double-update.
      if (state === "live") {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      } else if (!pollTimer) {
        pollTimer = setInterval(pollCurrent, LIVE_POLL_MS);
      }
    },
  });
  conn.start();
}
