/* The home dashboard: the widget catalogue.
 *
 * Every widget reads an endpoint that already existed — the customisable
 * dashboard needed no new backend routes. Each one declares what it needs and
 * knows nothing about the others; core/widgets.js owns the grid, edit mode and
 * persistence.
 */

import * as widgets from '../core/widgets.js';
import { get } from '../core/api.js';
import { h, icon, pill, render, emptyState } from '../core/ui.js';
import { bytes, percent, num, relative, latency } from '../core/format.js';
import { createSparkline } from '../core/chart.js';

/* =======================================================================
   Small shared pieces
   ======================================================================= */

/** A big mono readout with an eyebrow — the shape most widgets want. */
function readout(value, sub, { status } = {}) {
  return h(
    'div',
    { class: `readout${status ? ` ${status}` : ''}` },
    h('div', { class: 'readout-value' }, value),
    sub ? h('div', { class: 'readout-sub' }, sub) : null
  );
}

function statusOf(pct, warn = 75, down = 90) {
  return pct >= down ? 'down' : pct >= warn ? 'warn' : null;
}

/** A row of "label — value" lines. */
function lines(rows) {
  return h(
    'ul',
    { class: 'w-list' },
    ...rows.map(([label, value, extra]) =>
      h('li', { class: 'w-list-row' }, h('span', { class: 'w-list-label truncate' }, label), extra || null, h('span', { class: 'w-list-val' }, value))
    )
  );
}

const linkAll = (href, label) => h('a', { class: 'w-more', href }, label, icon('arrow-right'));

/* =======================================================================
   Host resource widgets — one metrics fetch, four widgets
   ======================================================================= */

// The four resource widgets would otherwise each fetch /metrics/current on
// load. One in-flight promise, shared: the endpoint is cheap but four identical
// requests on every page load is just sloppy.
let metricsPromise = null;
let metricsAt = 0;
function currentMetrics() {
  const now = Date.now();
  if (!metricsPromise || now - metricsAt > 2000) {
    metricsAt = now;
    metricsPromise = get('/metrics/current');
  }
  return metricsPromise;
}

function hostWidget({ id, title, iconName, pick, live: liveTopic = 'metrics' }) {
  const paint = (el, host) => {
    if (!host) {
      render(el, emptyState({ icon: 'clock', title: 'No sample yet', sub: 'Vantage has not completed its first scrape of this host.' }));
      return;
    }
    const { value, sub, status } = pick(host);
    render(el, readout(value, sub, { status }));
  };

  return {
    id,
    title,
    icon: iconName,
    size: 's',
    sizes: ['s', 'm'],
    topic: liveTopic,
    href: '/metrics',
    blurb: 'Live host reading',
    load: async () => (await currentMetrics())?.host ?? null,
    render: (el, host) => paint(el, host),
    // The WS payload is the same shape as /metrics/current's `host`, so the
    // live path and the fetch path render through one function.
    onLive: (el, data) => paint(el, data?.host ?? data),
  };
}

widgets.register(
  hostWidget({
    id: 'cpu',
    title: 'CPU',
    iconName: 'cpu',
    pick: (m) => ({
      value: h('span', {}, percent(m.cpu_total), h('span', { class: 'unit' }, '')),
      sub: `load ${m.load_1?.toFixed(2) ?? '—'} · ${percent(m.cpu_iowait)} iowait`,
      status: statusOf(m.cpu_total, 70, 90),
    }),
  })
);

widgets.register(
  hostWidget({
    id: 'memory',
    title: 'Memory',
    iconName: 'memory-stick',
    pick: (m) => ({
      value: percent(m.mem_used_pct),
      sub: `${bytes(m.mem_used)} of ${bytes(m.mem_total)}`,
      status: statusOf(m.mem_used_pct, 80, 92),
    }),
  })
);

widgets.register(
  hostWidget({
    id: 'disk',
    title: 'Disk',
    iconName: 'hard-drive',
    pick: (m) => ({
      value: percent(m.disk_used_pct),
      sub: `${bytes(m.disk_total - m.disk_used)} free of ${bytes(m.disk_total)}`,
      status: statusOf(m.disk_used_pct, 80, 90),
    }),
  })
);

widgets.register(
  hostWidget({
    id: 'network',
    title: 'Network',
    iconName: 'network',
    pick: (m) => ({
      // rx/tx are cumulative counters since boot; a rate needs two samples, so
      // the honest thing to show from one sample is the total moved.
      value: bytes(m.net_rx_bytes + m.net_tx_bytes),
      sub: `${bytes(m.net_rx_bytes)} in · ${bytes(m.net_tx_bytes)} out`,
    }),
  })
);

/* =======================================================================
   CPU history — the one widget with a chart
   ======================================================================= */

widgets.register({
  id: 'cpu-history',
  title: 'CPU · last hour',
  icon: 'activity',
  size: 'm',
  sizes: ['m', 'l'],
  href: '/metrics',
  blurb: 'Sparkline of recent CPU',
  load: () => get('/metrics/history?range=1h'),
  render: (el, data) => {
    const points = data?.points || [];
    if (points.length < 2) {
      render(el, emptyState({ icon: 'activity', title: 'Not enough history', sub: 'Vantage needs a few samples before it can draw a trend.' }));
      return;
    }
    const host = h('div', { class: 'w-chart' });
    const last = points[points.length - 1];
    render(el, readout(percent(last.cpu_total), `peak ${percent(Math.max(...points.map((p) => p.cpu_total)))} in the last hour`), host);
    createSparkline(host, points.map((p) => p.cpu_total), { height: 56 });
  },
});

/* =======================================================================
   Services
   ======================================================================= */

widgets.register({
  id: 'services',
  title: 'Services',
  icon: 'container',
  size: 'm',
  sizes: ['m', 'l'],
  needs: 'docker',
  href: '/docker',
  blurb: 'Container status board',
  load: async () => {
    // Update badges are a nice-to-have: if the checker is disabled or has not
    // run, the board must still render.
    const [services, updates] = await Promise.all([get('/docker/services/data'), get('/api/updates').catch(() => [])]);
    return { services, updates };
  },
  render: (el, { services, updates }) => {
    if (!services?.length) {
      render(el, emptyState({ icon: 'container', title: 'No services configured', sub: 'Add services to your config.json to manage them here.' }));
      return;
    }
    const updatable = new Set(updates.filter((u) => u.state === 'update_available').map((u) => u.service));
    const down = services.filter((s) => !s.running).length;

    render(
      el,
      h(
        'div',
        { class: 'w-head-row' },
        readout(`${services.length - down}/${services.length}`, down ? `${down} not running` : 'all running', { status: down ? 'down' : null }),
        updatable.size ? h('span', { class: 'chip acc' }, `${updatable.size} update${updatable.size > 1 ? 's' : ''}`) : null
      ),
      lines(
        services.slice(0, 8).map((s) => [
          s.name,
          s.running ? (s.cpu_pct != null ? percent(s.cpu_pct) : 'up') : 'stopped',
          h('span', { class: 'hstack' }, updatable.has(s.name) ? h('span', { class: 'chip acc' }, 'update') : null, pill(s.running ? 'ok' : 'down', s.running ? 'up' : 'down')),
        ])
      ),
      services.length > 8 ? linkAll('/docker', `All ${services.length} services`) : null
    );
  },
});

/* =======================================================================
   Monitors + incidents
   ======================================================================= */

widgets.register({
  id: 'monitors',
  title: 'Monitors',
  icon: 'heart-pulse',
  size: 'm',
  sizes: ['s', 'm', 'l'],
  href: '/monitors',
  blurb: 'Uptime probe board',
  topic: 'health',
  load: () => get('/monitors/data'),
  render: (el, d) => {
    if (!d?.total_targets) {
      render(el, emptyState({ icon: 'heart-pulse', title: 'No monitors yet', sub: 'Add an uptime probe to watch a service from the outside.', action: h('a', { class: 'btn sm', href: '/monitors' }, 'Add a monitor') }));
      return;
    }
    const bad = (d.down_count || 0) + (d.degraded_count || 0);
    render(
      el,
      readout(`${d.up_count}/${d.total_targets}`, bad ? `${d.down_count} down · ${d.degraded_count} degraded` : 'all operational', { status: d.down_count ? 'down' : d.degraded_count ? 'warn' : null }),
      lines(
        (d.summaries || [])
          // Problems first: a monitor board is read to find what is broken.
          .slice()
          .sort((a, b) => rank(a.last_status) - rank(b.last_status))
          .slice(0, 8)
          .map((s) => [s.name, s.last_latency_ms != null ? latency(s.last_latency_ms) : '—', pill(pillOf(s.last_status), s.last_status || 'unknown')])
      ),
      (d.summaries || []).length > 8 ? linkAll('/monitors', `All ${d.total_targets} monitors`) : null
    );
  },
});

const pillOf = (s) => (s === 'up' ? 'ok' : s === 'down' ? 'down' : s === 'degraded' ? 'warn' : 'idle');
const rank = (s) => (s === 'down' ? 0 : s === 'degraded' ? 1 : s === 'up' ? 3 : 2);

widgets.register({
  id: 'incidents',
  title: 'Open incidents',
  icon: 'triangle-alert',
  size: 'm',
  sizes: ['m', 'l'],
  href: '/monitors',
  blurb: 'Currently firing incidents',
  topic: 'health.event',
  load: () => get('/monitors/data'),
  render: (el, d) => {
    const open = d?.open_incidents || [];
    if (!open.length) {
      render(el, emptyState({ icon: 'circle-check', title: 'No open incidents', sub: 'Every monitor has been steady.' }));
      return;
    }
    render(
      el,
      lines(open.slice(0, 6).map((i) => [i.target_name || i.name || `#${i.id}`, relative(i.started_at), pill('down', 'firing')])),
      open.length > 6 ? linkAll('/monitors', `All ${open.length} incidents`) : null
    );
  },
});

/* =======================================================================
   Firewall
   ======================================================================= */

widgets.register({
  id: 'firewall',
  title: 'Firewall',
  icon: 'brick-wall',
  size: 's',
  sizes: ['s', 'm'],
  needs: 'firewall',
  href: '/firewall',
  blurb: 'Rules and active lockouts',
  load: () => get('/firewall/data'),
  render: (el, d) => {
    const rules = d?.rules || [];
    const lockouts = d?.lockouts || [];
    render(
      el,
      readout(num(rules.length), `${rules.filter((r) => r.enabled).length} enabled · ${d.backend}`),
      lockouts.length
        ? lines(lockouts.slice(0, 5).map((l) => [l.ip || l.address, relative(l.created_at || l.since), pill('down', 'locked')]))
        : h('p', { class: 'w-note' }, 'No addresses are locked out.')
    );
  },
});

/* =======================================================================
   Secrets
   ======================================================================= */

widgets.register({
  id: 'secrets',
  title: 'Secret findings',
  icon: 'key-round',
  size: 's',
  sizes: ['s', 'm'],
  href: '/secrets',
  blurb: 'Open scanner findings',
  load: () => get('/secrets/data'),
  render: (el, d) => {
    if (!d?.scanner_enabled) {
      render(el, emptyState({ title: 'Scanner is off', sub: 'Set secret_scan_paths in config.json to scan this host.', degraded: true }));
      return;
    }
    const c = d.counts || {};
    render(
      el,
      readout(num(c.open || 0), c.critical_open ? `${c.critical_open} critical` : 'open findings', { status: c.critical_open ? 'down' : c.open ? 'warn' : null }),
      d.last_scan ? h('p', { class: 'w-note' }, `Last scan ${relative(d.last_scan.finished_at || d.last_scan.started_at)}`) : null
    );
  },
});

/* =======================================================================
   Boot
   ======================================================================= */

const grid = document.getElementById('widget-grid');

widgets.start({
  grid,
  caps: {
    // Askama renders a bool as "true"/"false".
    docker: grid.dataset.docker === 'true',
    firewall: grid.dataset.firewall === 'true',
  },
  // The default view answers "is this box healthy?" before anything else.
  defaults: [
    { id: 'cpu', size: 's' },
    { id: 'memory', size: 's' },
    { id: 'disk', size: 's' },
    { id: 'network', size: 's' },
    { id: 'services', size: 'm' },
    { id: 'monitors', size: 'm' },
    { id: 'cpu-history', size: 'm' },
    { id: 'incidents', size: 'm' },
  ],
});
