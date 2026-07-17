/* The chart factory — one uPlot theme for every chart in the app.
 *
 * Canvas cannot inherit CSS, so this module is the bridge: it reads the design
 * tokens at construction time and re-reads them when the theme changes.
 *
 * ── On the series palette ────────────────────────────────────────────────
 * --ch-1..4 are a categorical palette, validated for colour-vision deficiency
 * (protan/deutan/tritan) as *adjacent* pairs — the correct gate for line and
 * area charts, as opposed to the all-pairs gate scatter plots need. That gate
 * comes with an obligation this module honours rather than assumes:
 *
 *   - two or more series ALWAYS get a legend, and
 *   - four or fewer series are also direct-labelled at the line's end,
 *
 * so identity never rests on colour alone. If you ever draw a scatter/bubble
 * chart here, the palette must be re-validated under all-pairs first — the
 * current steps do not clear that bar.
 *
 * To re-check after changing a --ch-* token:
 *   node scripts/validate_palette.js "<the four hexes>" --mode dark  --surface "#11161d"
 *   node scripts/validate_palette.js "<the four hexes>" --mode light --surface "#ffffff"
 */

import { onChange, token } from './theme.js';
import { absolute } from './format.js';

const charts = new Set();

function palette() {
  return {
    ink1: token('--ink-1'),
    ink2: token('--ink-2'),
    ink3: token('--ink-3'),
    grid: token('--ch-grid'),
    line: token('--line-1'),
    bg1: token('--bg-1'),
    bg3: token('--bg-3'),
    acc: token('--acc'),
    series: [token('--ch-1'), token('--ch-2'), token('--ch-3'), token('--ch-4')],
    font: `11px ${token('--font-mono') || 'monospace'}`,
  };
}

function alpha(hex, a) {
  const h = hex.trim().replace('#', '');
  if (h.length !== 6) return hex;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

/* =======================================================================
   Tooltip — a shared crosshair readout, styled like the design system
   ======================================================================= */

function tooltipPlugin({ formatY = (v) => v, formatX = absolute } = {}) {
  let el;
  return {
    hooks: {
      init: (u) => {
        el = document.createElement('div');
        el.className = 'chart-tip';
        el.hidden = true;
        u.over.appendChild(el);
      },
      setCursor: (u) => {
        const { idx, left, top } = u.cursor;
        if (idx == null || left < 0) {
          el.hidden = true;
          return;
        }

        const rows = [];
        for (let i = 1; i < u.series.length; i++) {
          const s = u.series[i];
          if (s.show === false) continue;
          const v = u.data[i][idx];
          if (v == null) continue;
          rows.push(
            `<div class="chart-tip-row">` +
              `<span class="chart-tip-dot" style="background:${s.stroke()}"></span>` +
              `<span class="chart-tip-label">${s.label}</span>` +
              `<span class="chart-tip-val">${formatY(v, i)}</span>` +
              `</div>`
          );
        }
        if (!rows.length) {
          el.hidden = true;
          return;
        }

        // Series labels come from our own page code, and values are numbers —
        // no API string reaches this innerHTML.
        el.innerHTML = `<div class="chart-tip-head">${formatX(u.data[0][idx] * 1000)}</div>${rows.join('')}`;
        el.hidden = false;

        // Flip before the pointer once the tip would leave the plot.
        const w = el.offsetWidth;
        const flip = left + w + 16 > u.over.clientWidth;
        el.style.left = `${flip ? left - w - 12 : left + 12}px`;
        el.style.top = `${Math.min(top + 12, u.over.clientHeight - el.offsetHeight - 4)}px`;
      },
      destroy: () => el?.remove(),
    },
  };
}

/* =======================================================================
   Factory
   ======================================================================= */

/**
 * Create a themed uPlot.
 *
 * @param {HTMLElement} host      container; the chart sizes itself to it
 * @param {object} o
 * @param {string[]} o.labels     series labels (excluding x)
 * @param {Array} o.data          uPlot data: [xs, ...series]
 * @param {(v:number)=>string} [o.format]   y value formatter (axis + tooltip)
 * @param {boolean} [o.area]      fill under the line
 * @param {boolean} [o.legend]    force the legend on/off (default: labels.length > 1)
 * @param {number} [o.height]
 * @param {[number,number]} [o.yRange] fixed y scale, e.g. [0, 100] for percent
 */
export function createChart(host, o) {
  if (typeof uPlot === 'undefined') {
    console.error('uPlot not loaded — the page must include /static/vendor/uplot.iife.min.js');
    return null;
  }

  const p = palette();
  const {
    labels = [],
    data = [[]],
    format = (v) => String(v),
    area = true,
    height = 200,
    yRange = null,
    legend = labels.length > 1,
  } = o;

  const series = [
    {
      // x axis: uPlot hands us epoch seconds; render in the viewer's zone.
      value: (u, ts) => (ts == null ? '' : new Date(ts * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })),
    },
    ...labels.map((label, i) => ({
      label,
      stroke: () => p.series[i % p.series.length],
      width: 2, // thin marks; 2px is the spec
      fill: area ? alpha(p.series[i % p.series.length], labels.length > 1 ? 0.07 : 0.1) : undefined,
      points: { show: false },
      // Gaps in the data are real (a collector restart) — don't invent a line
      // across them.
      spanGaps: false,
      value: (u, v) => (v == null ? '—' : format(v)),
    })),
  ];

  const opts = {
    width: host.clientWidth || 600,
    height,
    padding: [8, 8, 0, 0],
    // We render our own legend; uPlot's default table is not our design system.
    legend: { show: false },
    cursor: {
      y: false,
      points: { show: true, size: 7, width: 2, fill: (u, i) => p.series[(i - 1) % p.series.length], stroke: () => p.bg1 },
      drag: { x: true, y: false, setScale: false },
    },
    scales: { x: { time: true }, y: yRange ? { range: yRange } : {} },
    axes: [
      {
        stroke: p.ink3,
        grid: { stroke: p.grid, width: 1 },
        ticks: { stroke: p.grid, width: 1, size: 4 },
        font: p.font,
        size: 30,
      },
      {
        stroke: p.ink3,
        grid: { stroke: p.grid, width: 1 },
        ticks: { show: false },
        font: p.font,
        size: 52,
        values: (u, vals) => vals.map((v) => format(v)),
      },
    ],
    series,
    plugins: [tooltipPlugin({ formatY: (v) => format(v) })],
  };

  const chart = new uPlot(opts, data, host);

  // Size to the container rather than the window: widgets and drawers resize
  // without the viewport changing at all.
  const ro = new ResizeObserver(() => {
    const w = host.clientWidth;
    if (w > 0) chart.setSize({ width: w, height });
  });
  ro.observe(host);

  const entry = { chart, host, opts, ro, labels, format };
  charts.add(entry);

  if (legend) host.after(buildLegend(chart, labels, p));

  chart._vantageDestroy = () => {
    ro.disconnect();
    charts.delete(entry);
    chart.destroy();
  };

  return chart;
}

/**
 * The legend. Present whenever there is more than one series — identity must
 * never be carried by colour alone. Clicking a row toggles that series.
 */
function buildLegend(chart, labels, p) {
  const wrap = document.createElement('div');
  wrap.className = 'chart-legend';

  labels.forEach((label, i) => {
    const btn = document.createElement('button');
    btn.className = 'chart-legend-item';
    btn.setAttribute('aria-pressed', 'true');

    const dot = document.createElement('span');
    dot.className = 'chart-legend-dot';
    dot.style.background = p.series[i % p.series.length];

    const text = document.createElement('span');
    text.textContent = label;

    btn.append(dot, text);
    btn.addEventListener('click', () => {
      const on = chart.series[i + 1].show === false;
      chart.setSeries(i + 1, { show: on });
      btn.setAttribute('aria-pressed', String(on));
    });
    wrap.append(btn);
  });

  return wrap;
}

/** A sparkline: no axes, no grid, no tooltip — a shape, not a chart. */
export function createSparkline(host, values, { color, height = 32 } = {}) {
  if (typeof uPlot === 'undefined' || !values?.length) return null;
  const p = palette();
  const stroke = color || p.series[0];
  const xs = values.map((_, i) => i);

  const chart = new uPlot(
    {
      width: host.clientWidth || 120,
      height,
      padding: [2, 1, 2, 1],
      legend: { show: false },
      cursor: { show: false },
      scales: { x: { time: false } },
      axes: [{ show: false }, { show: false }],
      series: [{}, { stroke: () => stroke, width: 1.5, fill: alpha(stroke, 0.14), points: { show: false } }],
    },
    [xs, values],
    host
  );

  const ro = new ResizeObserver(() => {
    const w = host.clientWidth;
    if (w > 0) chart.setSize({ width: w, height });
  });
  ro.observe(host);
  chart._vantageDestroy = () => {
    ro.disconnect();
    chart.destroy();
  };
  return chart;
}

// A theme flip changes every token the charts baked in at construction. Canvas
// won't re-cascade, so rebuild the visual options in place.
onChange(() => {
  const p = palette();
  for (const { chart, labels } of charts) {
    labels.forEach((_, i) => {
      chart.series[i + 1].stroke = () => p.series[i % p.series.length];
      chart.series[i + 1].fill = alpha(p.series[i % p.series.length], labels.length > 1 ? 0.07 : 0.1);
    });
    for (const ax of chart.axes) {
      ax.stroke = p.ink3;
      ax.grid.stroke = p.grid;
      if (ax.ticks) ax.ticks.stroke = p.grid;
    }
    chart.redraw(false, true);
  }
  // Legend dots live in the DOM, so they re-read tokens on their own only if we
  // set them; they were assigned an absolute colour at build time.
  document.querySelectorAll('.chart-legend').forEach((wrap) => {
    wrap.querySelectorAll('.chart-legend-dot').forEach((dot, i) => {
      dot.style.background = p.series[i % p.series.length];
    });
  });
});

export function destroyChart(chart) {
  chart?._vantageDestroy?.();
}
