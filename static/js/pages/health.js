/* Health / uptime monitors.
 *
 * Data: GET /monitors/data, GET /monitors/incidents, POST /monitors (create),
 * POST /monitors/:id (update), DELETE /monitors/:id, POST /monitors/:id/toggle,
 * POST /monitors/:id/check. Live: `health` (a check completed) and
 * `health.event` (a monitor changed state).
 *
 * Note the upsert endpoints are axum `Form(...)` extractors, so they take
 * url-encoded bodies, and per-kind settings ride in a `config_json` string
 * field rather than as real columns.
 */

import { get, post, del, postUrlEncoded } from '../core/api.js';
import {
  h,
  icon,
  pill,
  render,
  emptyRow,
  skeletonRows,
  reportError,
  toast,
  confirm,
  openModal,
  closeModal,
  withLoading,
  wireSegmented,
  emptyState,
} from '../core/ui.js';
import { latency, relative, duration, num } from '../core/format.js';
import * as live from '../core/live.js';

const tilesEl = document.getElementById('tiles');
const bodyEl = document.getElementById('targets-body');
const countEl = document.getElementById('monitor-count');
const incBodyEl = document.getElementById('incidents-body');
const editor = document.getElementById('editor');
const form = document.getElementById('editor-form');

let incidentFilter = 'open';
let data = null;

const PILL = { up: 'ok', down: 'down', degraded: 'warn' };
const pillFor = (s) => PILL[s] || 'idle';

/* =======================================================================
   Tiles
   ======================================================================= */

function renderTiles(d) {
  const t = (label, value, sub, status, iconName) =>
    h(
      'div',
      { class: `stat${status ? ` ${status}` : ''}` },
      h('span', { class: 'stat-key' }, icon(iconName), label),
      h('span', { class: 'stat-value' }, num(value)),
      h('span', { class: 'stat-sub' }, sub)
    );

  render(
    tilesEl,
    t('Monitors', d.total_targets, 'configured', null, 'heart-pulse'),
    t('Up', d.up_count, 'responding normally', d.up_count ? 'ok' : null, 'circle-check'),
    t('Degraded', d.degraded_count, 'slow, or near expiry', d.degraded_count ? 'warn' : null, 'triangle-alert'),
    t('Down', d.down_count, 'failing their check', d.down_count ? 'down' : null, 'circle-x')
  );
}

/* =======================================================================
   Monitor table
   ======================================================================= */

/** A 24h uptime bar. The number alone hides the difference between "one long
 *  outage" and "flapping all day", so it gets a bar and a colour too. */
function uptimeCell(pct) {
  const status = pct >= 99.5 ? 'ok' : pct >= 95 ? 'warn' : 'down';
  return h(
    'div',
    { class: 'usage' },
    h('div', { class: `progress ${status}` }, h('div', { class: 'progress-bar', style: { width: `${Math.max(0, Math.min(100, pct))}%` } })),
    h('span', { class: 'usage-val' }, `${pct.toFixed(2)}%`)
  );
}

function renderTargets(d) {
  const rows = d.summaries || [];
  countEl.textContent = num(rows.length);

  if (!rows.length) {
    render(
      bodyEl,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 7 },
          emptyState({
            icon: 'heart-pulse',
            title: 'No monitors yet',
            sub: 'Add a probe and Vantage will check it on a schedule, track uptime, and open an incident when it fails.',
            action: h('button', { class: 'btn sm', onclick: () => openEditor() }, 'New monitor'),
          })
        )
      )
    );
    return;
  }

  // Trouble first — this table is read to find what is broken.
  const order = { down: 0, degraded: 1, up: 3 };
  const sorted = rows.slice().sort((a, b) => (order[a.last_status] ?? 2) - (order[b.last_status] ?? 2) || a.name.localeCompare(b.name));

  render(
    bodyEl,
    ...sorted.map((s) =>
      h(
        'tr',
        { dataset: { id: s.id } },
        h(
          'td',
          {},
          h(
            'div',
            { class: 'monitor-cell' },
            pill(pillFor(s.last_status), s.last_status || 'unknown'),
            h('span', { class: 'monitor-name truncate' }, s.name),
            s.enabled ? null : h('span', { class: 'chip' }, 'paused')
          )
        ),
        h('td', {}, h('span', { class: 'chip' }, s.kind)),
        h('td', { class: 'mono truncate', style: { maxWidth: '260px' }, title: s.target }, s.target),
        h('td', { class: 'num' }, s.last_latency_ms != null ? latency(s.last_latency_ms) : '—'),
        h('td', {}, uptimeCell(s.uptime_24h ?? 0)),
        h('td', {}, s.last_check ? h('time', { class: 'js-ts', datetime: s.last_check, title: s.last_check }, relative(s.last_check)) : '—'),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            h(
              'button',
              {
                class: 'btn sm ghost icon-only',
                'data-tip': 'Check now',
                'aria-label': `Check ${s.name} now`,
                onclick: (e) => checkNow(e.currentTarget, s),
              },
              icon('refresh-cw')
            ),
            h(
              'button',
              {
                class: 'btn sm ghost icon-only',
                'data-tip': s.enabled ? 'Pause' : 'Resume',
                'aria-label': s.enabled ? `Pause ${s.name}` : `Resume ${s.name}`,
                onclick: (e) => toggle(e.currentTarget, s),
              },
              icon(s.enabled ? 'pause' : 'play')
            ),
            h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Edit', 'aria-label': `Edit ${s.name}`, onclick: () => openEditor(s) }, icon('pencil')),
            h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Delete', 'aria-label': `Delete ${s.name}`, onclick: () => remove(s) }, icon('trash-2'))
          )
        )
      )
    )
  );
}

/* =======================================================================
   Incidents
   ======================================================================= */

function renderIncidents(rows) {
  if (!rows.length) {
    render(incBodyEl, emptyRow(5, incidentFilter === 'open' ? 'No open incidents — everything has been steady.' : 'No incidents recorded yet.'));
    return;
  }

  render(
    incBodyEl,
    ...rows.map((i) => {
      const ended = i.ended_at ? new Date(i.ended_at) : null;
      const secs = ((ended ? ended.getTime() : Date.now()) - new Date(i.started_at).getTime()) / 1000;
      return h(
        'tr',
        {},
        h('td', {}, ended ? pill('ok', 'resolved') : pill('down', 'firing')),
        h('td', { class: 'mono' }, i.target_name || `#${i.target_id}`),
        h('td', {}, h('time', { class: 'js-ts', datetime: i.started_at, title: i.started_at }, relative(i.started_at))),
        h('td', { class: 'mono' }, duration(secs)),
        h('td', { class: 'truncate', style: { maxWidth: '320px' }, title: i.last_error || '' }, i.last_error || '—')
      );
    })
  );
}

/* =======================================================================
   Actions
   ======================================================================= */

async function checkNow(btn, s) {
  await withLoading(btn, async () => {
    await post(`/monitors/${s.id}/check`);
    toast('ok', `Checked ${s.name}`);
    await load();
  }, { errorTitle: `Couldn't check ${s.name}` });
}

async function toggle(btn, s) {
  await withLoading(btn, async () => {
    await post(`/monitors/${s.id}/toggle`);
    toast('ok', s.enabled ? `Paused ${s.name}` : `Resumed ${s.name}`);
    await load();
  }, { errorTitle: `Couldn't update ${s.name}` });
}

async function remove(s) {
  const ok = await confirm({
    title: `Delete ${s.name}?`,
    message: 'Its history and incidents go with it. This cannot be undone.',
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;
  try {
    await del(`/monitors/${s.id}`);
    toast('ok', `Deleted ${s.name}`);
    await load();
  } catch (e) {
    reportError(e, "Couldn't delete the monitor");
  }
}

/* =======================================================================
   Editor
   ======================================================================= */

const $ = (id) => document.getElementById(id);

const TARGET_HINT = {
  http: 'A URL Vantage can reach from this host.',
  keyword: 'A URL whose body should contain the keyword.',
  tcp: 'host:port — a successful connect counts as up.',
  ssl: 'host:port — usually :443.',
};

function syncKind() {
  const kind = $('f-kind').value;
  for (const sec of document.querySelectorAll('.kind-section')) {
    sec.hidden = !sec.dataset.kind.split(' ').includes(kind);
  }
  $('target-hint').textContent = TARGET_HINT[kind] || '';
  $('f-target').placeholder = kind === 'tcp' || kind === 'ssl' ? 'example.com:443' : 'https://example.com/health';
}

function openEditor(s = null) {
  form.reset();
  $('f-id').value = s?.id ?? '';
  $('editor-title').textContent = s ? `Edit ${s.name}` : 'New monitor';
  $('editor-save').textContent = s ? 'Save changes' : 'Create monitor';

  if (s) {
    $('f-name').value = s.name;
    $('f-kind').value = s.kind;
    $('f-target').value = s.target;
    $('f-interval').value = s.interval_seconds;
    $('f-timeout').value = s.timeout_ms;
    $('f-degraded').value = s.degraded_ms;
    $('f-enabled').checked = !!s.enabled;

    // Per-kind settings live in an opaque JSON string; a monitor saved by an
    // older build may not have every key, so read defensively.
    let cfg = {};
    try {
      cfg = JSON.parse(s.config_json || '{}');
    } catch {
      /* keep defaults */
    }
    if (cfg.method) $('f-method').value = cfg.method;
    if (cfg.expected_status) $('f-expected').value = [].concat(cfg.expected_status).join(',');
    if (cfg.keyword) $('f-keyword').value = cfg.keyword;
    $('f-invert').checked = !!cfg.invert;
    if (cfg.warn_days) $('f-warn-days').value = cfg.warn_days;
  } else {
    $('f-enabled').checked = true;
  }

  syncKind();
  openModal(editor);
}

function buildConfig(kind) {
  const cfg = {};
  if (kind === 'http' || kind === 'keyword') {
    cfg.method = $('f-method').value;
    const expected = $('f-expected')
      .value.split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n));
    if (expected.length) cfg.expected_status = expected;
  }
  if (kind === 'keyword') {
    cfg.keyword = $('f-keyword').value;
    if ($('f-invert').checked) cfg.invert = true;
  }
  if (kind === 'ssl') cfg.warn_days = parseInt($('f-warn-days').value, 10) || 14;
  return cfg;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = $('f-id').value;
  const kind = $('f-kind').value;

  if (kind === 'keyword' && !$('f-keyword').value.trim()) {
    toast('warn', 'A keyword check needs a keyword', 'Enter the text that must appear in the response.');
    $('f-keyword').focus();
    return;
  }

  const payload = {
    name: $('f-name').value.trim(),
    kind,
    target: $('f-target').value.trim(),
    interval_seconds: $('f-interval').value,
    timeout_ms: $('f-timeout').value,
    degraded_ms: $('f-degraded').value,
    // The server reads this as matches!("on"|"true"|"1") — an absent field is
    // false, which is exactly how an unchecked box should behave.
    enabled: $('f-enabled').checked ? 'on' : undefined,
    config_json: JSON.stringify(buildConfig(kind)),
  };

  await withLoading($('editor-save'), async () => {
    await postUrlEncoded(id ? `/monitors/${id}` : '/monitors', payload);
    closeModal(editor);
    toast('ok', id ? 'Monitor saved' : 'Monitor created');
    await load();
  }, { errorTitle: "Couldn't save the monitor" });
});

$('f-kind').addEventListener('change', syncKind);

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  try {
    data = await get('/monitors/data');
    renderTiles(data);
    renderTargets(data);
    await loadIncidents();
  } catch (e) {
    reportError(e, "Couldn't load monitors");
    render(bodyEl, emptyRow(7, 'Failed to load.'));
  }
}

async function loadIncidents() {
  if (incidentFilter === 'open') {
    renderIncidents(data?.open_incidents || []);
    return;
  }
  try {
    renderIncidents(await get('/monitors/incidents?limit=100'));
  } catch (e) {
    reportError(e, "Couldn't load incidents");
  }
}

/* =======================================================================
   Boot
   ======================================================================= */

render(bodyEl, ...skeletonRows(7, 4));
render(incBodyEl, ...skeletonRows(5, 2));

document.getElementById('new-btn').addEventListener('click', () => openEditor());
document.getElementById('refresh-btn').addEventListener('click', (e) => withLoading(e.currentTarget, load));
wireSegmented(document.getElementById('incident-filter'), (v) => {
  incidentFilter = v;
  loadIncidents();
});

load();

// A completed check or a state change both mean the table is stale.
live.subscribe('health', () => load());
live.subscribe('health.event', (e) => {
  load();
  if (e?.status === 'down') toast('error', `${e.name || 'A monitor'} is down`, e.error || undefined);
  else if (e?.status === 'up') toast('ok', `${e.name || 'A monitor'} recovered`);
});
