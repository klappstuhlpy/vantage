/* Docker page: services, action log, dependency graph, live events, log console.
 *
 * Data:
 *   GET  /docker/services/data      live service state (poll + WS-triggered)
 *   POST /docker/action             start|stop|restart|pull|recreate (form-encoded)
 *   GET  /docker/actions/log        the in-memory action ring buffer
 *   GET  /docker/graph              nodes + edges for the dependency graph
 *   GET  /docker/inspect/:id        full container inspect (drawer)
 *   GET  /docker/logs/:name         SSE log stream
 *   WS   `docker`                   raw docker events (start/stop/die/…)
 *   GET  /api/updates               image-update badges
 *
 * The service cards are server-rendered; this module updates them in place
 * rather than re-rendering, so a card never flickers while you are aiming at
 * its button.
 */

import { get, postUrlEncoded } from '../core/api.js';
import {
  h,
  icon,
  render,
  reportError,
  toast,
  confirm,
  openModal,
  openDrawer,
  closeDrawer,
  setLoading,
  wireSegmented,
  showMenu,
  hideMenu,
} from '../core/ui.js';
import { bytes, percent, relative, clock, shortId, num } from '../core/format.js';
import * as live from '../core/live.js';

const grid = document.getElementById('service-grid');
const dockerAvailable = !!document.getElementById('cy');

/* =======================================================================
   Services
   ======================================================================= */

const cards = () => [...(grid?.querySelectorAll('.service-card') || [])];
const cardFor = (name) => grid?.querySelector(`.service-card[data-name="${CSS.escape(name)}"]`);

function applyService(card, s) {
  card.dataset.running = String(s.running);
  card.classList.toggle('is-down', !s.running);

  const status = card.querySelector('[data-role="status"]');
  status.className = `pill ${s.running ? 'ok' : 'down'}`;
  status.textContent = s.running ? 'running' : 'stopped';

  const started = card.querySelector('[data-role="started"]');
  if (started) {
    if (s.running && s.started_at) {
      render(started, 'started ', h('time', { class: 'js-ts', datetime: s.started_at, title: s.started_at }, relative(s.started_at)));
    } else {
      render(started, h('span', { class: 'faint' }, s.running ? 'start time unavailable' : 'not running'));
    }
  }

  const img = card.querySelector('[data-role="image"]');
  if (img && s.image) {
    img.textContent = s.image;
    img.title = s.image;
  }
  const id = card.querySelector('[data-role="id"]');
  if (id && s.short_id) id.textContent = s.short_id;
  const restarts = card.querySelector('[data-role="restarts"]');
  if (restarts && s.restart_count != null) restarts.textContent = String(s.restart_count);

  // Stats only exist while the container is running and `docker stats` reported.
  const stats = card.querySelector('[data-role="stats"]');
  if (s.cpu_pct != null || s.mem_used != null) {
    stats.hidden = false;
    const memPct = s.mem_limit ? (s.mem_used / s.mem_limit) * 100 : 0;
    setBar(card, 'cpu', s.cpu_pct ?? 0, percent(s.cpu_pct ?? 0));
    setBar(card, 'mem', memPct, bytes(s.mem_used ?? 0));
  } else {
    stats.hidden = true;
  }

  for (const btn of card.querySelectorAll('[data-action]')) {
    const a = btn.dataset.action;
    btn.disabled = (a === 'start' && s.running) || (a === 'stop' && !s.running);
  }
}

function setBar(card, key, pct, label) {
  const bar = card.querySelector(`[data-role="${key}-bar"]`);
  const val = card.querySelector(`[data-role="${key}-value"]`);
  const clamped = Math.max(0, Math.min(100, pct));
  bar.style.width = `${clamped}%`;
  bar.parentElement.className = `progress${clamped >= 90 ? ' down' : clamped >= 75 ? ' warn' : ''}`;
  val.textContent = label;
}

async function refreshServices() {
  if (!grid) return;
  try {
    const services = await get('/docker/services/data');
    for (const s of services) {
      const card = cardFor(s.name);
      if (card) applyService(card, s);
    }
  } catch (e) {
    // A background refresh must not spam toasts; the page still shows the last
    // known state, which is the honest thing to do.
    console.error('service refresh failed', e);
  }
}

/* =======================================================================
   Update badges — /api/updates has never had a frontend
   ======================================================================= */

async function refreshUpdates() {
  if (!grid) return;
  try {
    const updates = await get('/api/updates');
    for (const u of updates) {
      const card = cardFor(u.service);
      const badge = card?.querySelector('[data-role="update"]');
      if (!badge) continue;
      const avail = u.state === 'update_available';
      badge.hidden = !avail;
      badge.className = `chip service-update${avail ? ' acc' : ''}`;
      if (avail) badge.title = `The registry has a newer image for ${u.image}. Pull to update.`;
    }
  } catch {
    // The checker is optional (update_check_interval_hours may be unset).
  }
}

/* =======================================================================
   Actions
   ======================================================================= */

const DESTRUCTIVE = {
  stop: (n) => ({ title: `Stop ${n}?`, message: 'The container stops serving immediately.' }),
  recreate: (n) => ({
    title: `Recreate ${n}?`,
    message: 'The container is destroyed and rebuilt from its image. Anything not on a volume is lost.',
  }),
};

async function runAction(btn, name, action) {
  const warn = DESTRUCTIVE[action];
  if (warn) {
    const { title, message } = warn(name);
    if (!(await confirm({ title, message, confirmLabel: action === 'stop' ? 'Stop' : 'Recreate', danger: true }))) return;
  }

  setLoading(btn, true);
  try {
    const res = await postUrlEncoded('/docker/action', { name, action });
    toast('ok', `${name}: ${action} done`, res.output?.trim()?.split('\n').slice(-1)[0] || undefined);
  } catch (e) {
    // The handler returns 500 with {ok:false, output} on a failed action — the
    // output is the whole point, so surface it rather than a generic message.
    const out = e.body?.output?.trim();
    reportError(out ? Object.assign(e, { message: out.split('\n').slice(-3).join('\n') }) : e, `${name}: ${action} failed`);
  } finally {
    setLoading(btn, false);
    await Promise.all([refreshServices(), loadActionLog()]);
  }
}

grid?.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const card = btn.closest('.service-card');
  runAction(btn, card.dataset.name, btn.dataset.action);
});

// The "more" menu holds pull/recreate: they are rarer and one of them is
// destructive, so they stay out of the primary row.
grid?.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-role="more"]');
  if (!btn) return;
  e.stopPropagation();
  const name = btn.closest('.service-card').dataset.name;

  const menu = h(
    'div',
    { class: 'menu' },
    h('button', { class: 'menu-item', onclick: () => runAction(btn, name, 'pull') }, icon('download'), 'Pull image'),
    h('button', { class: 'menu-item', onclick: () => runAction(btn, name, 'recreate') }, icon('list-restart'), 'Recreate'),
    h('div', { class: 'menu-sep' }),
    h('a', { class: 'menu-item', href: '/docker/snapshots' }, icon('camera'), 'Snapshots')
  );
  document.body.append(menu);
  menu.addEventListener('click', () => {
    hideMenu(menu, btn);
    setTimeout(() => menu.remove(), 200);
  });
  showMenu(menu, btn, { align: 'end' });
});

/* =======================================================================
   Filter
   ======================================================================= */

document.getElementById('services-search')?.addEventListener('input', (e) => {
  const q = e.target.value.trim().toLowerCase();
  let shown = 0;
  for (const card of cards()) {
    const match = !q || card.dataset.name.toLowerCase().includes(q);
    card.hidden = !match;
    if (match) shown++;
  }
  document.getElementById('filter-empty').hidden = shown > 0;
  document.getElementById('service-count').textContent = num(shown);
});

/* =======================================================================
   Action log
   ======================================================================= */

async function loadActionLog() {
  const body = document.getElementById('action-log-body');
  if (!body) return;
  try {
    const { actions = [] } = await get('/docker/actions/log');
    document.getElementById('action-count').textContent = num(actions.length);

    if (!actions.length) {
      render(body, h('div', { class: 'log-empty' }, 'Nothing yet. Start, stop, pull or recreate a service and its output lands here.'));
      return;
    }

    render(
      body,
      ...actions
        .slice()
        .reverse()
        .map((a) =>
          h(
            'details',
            { class: `action-entry${a.success ? '' : ' failed'}` },
            h(
              'summary',
              {},
              h('span', { class: `pill ${a.success ? 'ok' : 'down'}` }, a.success ? 'ok' : 'failed'),
              h('span', { class: 'action-service mono' }, a.service),
              h('span', { class: 'action-verb' }, a.action),
              h('span', { class: 'spacer' }),
              h('span', { class: 'action-actor faint' }, a.actor),
              h('time', { class: 'js-ts action-ts', datetime: a.ts, title: a.ts }, relative(a.ts))
            ),
            h('pre', { class: 'action-output' }, a.output || '(no output)')
          )
        )
    );
  } catch (e) {
    console.error('action log failed', e);
  }
}

document.getElementById('action-log')?.addEventListener('toggle', (e) => {
  if (e.currentTarget.open) loadActionLog();
});

/* =======================================================================
   Log console (SSE)
   ======================================================================= */

const logModal = document.getElementById('log-modal');
const terminal = document.getElementById('log-terminal');
let source = null;

// Lines are buffered here and flushed once per animation frame (see appendLine).
let pending = [];
let flushQueued = false;

const MAX_LOG_ROWS = 2000; // a busy container emits thousands of lines a minute
const LOG_SIZE_KEY = 'vantage.docker.log-size';

// ── Line formatting ─────────────────────────────────────────────────────
// Container output is raw text: it may carry ANSI colour codes, and — because
// we ask docker for `--timestamps` — every line is prefixed with an RFC3339
// stamp. Split those off so each line renders as [time] [level] message with
// the level colour-coded, instead of one undifferentiated grey wall.
const ANSI_RE = /\x1b\[[0-9;]*m/g;
const TS_RE = /^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2}))\s+([\s\S]*)$/;
const LEVEL_RE = /\b(TRACE|DEBUG|INFO(?:RMATION)?|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRIT(?:ICAL)?)\b/i;
const LEVEL_CANON = {
  trace: 'TRACE', debug: 'DEBUG', info: 'INFO', information: 'INFO', notice: 'INFO',
  warn: 'WARN', warning: 'WARN', error: 'ERROR', err: 'ERROR', fatal: 'FATAL', crit: 'FATAL', critical: 'FATAL',
};

function logRow(raw) {
  const clean = raw.replace(ANSI_RE, '');
  let ts = '';
  let body = clean;
  const m = clean.match(TS_RE);
  if (m) {
    ts = clock(m[1]);
    body = m[2];
  }
  const lm = body.match(LEVEL_RE);
  const level = lm ? LEVEL_CANON[lm[1].toLowerCase()] : '';

  // The ts and level columns are always present (empty string when unknown) so
  // messages stay aligned down the whole log regardless of which lines matched.
  return h(
    'div',
    { class: `log-row${level ? ` lvl-${level.toLowerCase()}` : ''}` },
    h('span', { class: 'log-ts' }, ts),
    h('span', { class: `log-lvl${level ? ` ${level}` : ''}` }, level),
    h('span', { class: 'log-msg' }, body)
  );
}

function openLogs(name) {
  document.getElementById('log-title').textContent = `${name} · logs`;
  render(terminal);
  pending = [];
  setLogState('connecting', 'idle');
  restoreLogSize();
  openModal(logModal, { onClose: stopLogs });

  source = new EventSource(`/docker/logs/${encodeURIComponent(name)}`);
  source.onopen = () => setLogState('streaming', 'ok');
  source.onmessage = (e) => appendLine(e.data);
  source.onerror = () => {
    // EventSource reconnects on its own; report the gap rather than pretend.
    setLogState('reconnecting', 'warn');
  };
}

function setLogState(text, kind) {
  const el = document.getElementById('log-state');
  el.className = `pill ${kind}`;
  el.textContent = text;
}

// Lines arrive one SSE event at a time and a chatty container can fire dozens
// per frame. Rendering each on arrival thrashes layout; instead we buffer and
// flush once per animation frame — one fragment insert, one trim, one scroll.
function appendLine(line) {
  pending.push(line);
  if (!flushQueued) {
    flushQueued = true;
    requestAnimationFrame(flushLog);
  }
}

function flushLog() {
  flushQueued = false;
  if (!pending.length) return;

  const follow = document.getElementById('log-follow').checked;
  const frag = document.createDocumentFragment();
  for (const line of pending) frag.append(logRow(line));
  pending = [];
  terminal.append(frag);

  // Trim in a single pass rather than per line — the DOM stays bounded.
  for (let over = terminal.childElementCount - MAX_LOG_ROWS; over > 0; over--) {
    terminal.firstElementChild.remove();
  }
  if (follow) terminal.scrollTop = terminal.scrollHeight;
}

function stopLogs() {
  source?.close();
  source = null;
  pending = [];
  flushQueued = false;
}

// ── Size persistence ────────────────────────────────────────────────────
// The dialog is `resize: both` (docker.css); remember the last size the admin
// dragged it to so the log console opens the way they left it.
function restoreLogSize() {
  try {
    const s = JSON.parse(localStorage.getItem(LOG_SIZE_KEY) || 'null');
    if (s && s.w > 0 && s.h > 0) {
      logModal.style.width = `${s.w}px`;
      logModal.style.height = `${s.h}px`;
    }
  } catch {
    /* corrupt/absent storage — fall back to the CSS default size */
  }
}

if (logModal) {
  let saveTimer;
  new ResizeObserver(() => {
    if (!logModal.open) return; // ignore the collapse to 0 on close
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try {
        localStorage.setItem(LOG_SIZE_KEY, JSON.stringify({ w: logModal.offsetWidth, h: logModal.offsetHeight }));
      } catch {
        /* storage full or blocked — sizing just won't persist */
      }
    }, 250);
  }).observe(logModal);
}

grid?.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-role="logs"]');
  if (btn) openLogs(btn.closest('.service-card').dataset.name);
});

document.getElementById('log-clear')?.addEventListener('click', () => render(terminal));

/* =======================================================================
   Live events
   ======================================================================= */

const eventsBody = document.getElementById('events-body');
let eventCount = 0;

if (eventsBody) {
  live.subscribe('docker', (evt) => {
    if (eventCount === 0) render(eventsBody);
    eventCount++;

    const action = evt.action || evt.Action || '';
    const name = evt.Actor?.Attributes?.name || evt.actor?.attributes?.name || evt.id?.slice(0, 12) || '';
    const type = evt.Type || evt.type || 'container';
    const bad = /die|kill|destroy|oom/.test(action);

    eventsBody.prepend(
      h(
        'div',
        { class: 'log-row' },
        h('span', { class: 'log-ts' }, clock(Date.now())),
        h('span', { class: `log-lvl ${bad ? 'ERROR' : 'INFO'}` }, type),
        h('span', { class: 'log-msg' }, `${action} ${name}`.trim())
      )
    );
    while (eventsBody.childElementCount > 200) eventsBody.lastElementChild.remove();

    // A container changing state makes the cards stale.
    if (/start|stop|die|restart|create|destroy/.test(action)) {
      refreshServices();
      if (graph) loadGraph();
    }
  });

  document.getElementById('events-clear').addEventListener('click', () => {
    eventCount = 0;
    render(eventsBody, h('div', { class: 'log-empty' }, 'Waiting for Docker events…'));
  });
}

/* =======================================================================
   Dependency graph (Cytoscape)
   ======================================================================= */

let graph = null;
let graphFilter = 'all';

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function graphStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color': cssVar('--bg-2'),
        'border-width': 1.5,
        'border-color': cssVar('--line-2'),
        label: 'data(label)',
        color: cssVar('--ink-2'),
        'font-family': 'IBM Plex Mono, monospace',
        'font-size': 10,
        'text-valign': 'bottom',
        'text-margin-y': 6,
        width: 34,
        height: 34,
      },
    },
    { selector: 'node[kind="container"]', style: { 'border-color': cssVar('--acc'), 'background-color': cssVar('--acc-soft'), shape: 'round-rectangle' } },
    { selector: 'node[kind="network"]', style: { 'border-color': cssVar('--ch-3'), shape: 'diamond' } },
    { selector: 'node[kind="volume"]', style: { 'border-color': cssVar('--ch-2'), shape: 'barrel' } },
    { selector: 'node:selected', style: { 'border-width': 3, 'border-color': cssVar('--acc'), color: cssVar('--ink-1') } },
    {
      selector: 'edge',
      style: {
        width: 1,
        'line-color': cssVar('--line-2'),
        'target-arrow-color': cssVar('--line-2'),
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.7,
        'curve-style': 'bezier',
      },
    },
    { selector: 'edge[type="depends"]', style: { 'line-style': 'dashed', 'line-color': cssVar('--acc-line') } },
  ];
}

async function loadGraph() {
  const host = document.getElementById('cy');
  if (!host || typeof cytoscape === 'undefined') return;

  try {
    const data = await get('/docker/graph');
    const elements = [
      ...(data.nodes || []).map((n) => ({ data: { id: n.id, label: n.label, kind: n.kind, raw: n.data } })),
      ...(data.edges || []).map((e) => ({ data: { source: e.source, target: e.target, type: e.type, label: e.label } })),
    ];

    if (graph) graph.destroy();
    graph = cytoscape({
      container: host,
      elements,
      style: graphStyle(),
      layout: { name: 'cose', animate: false, padding: 24, nodeRepulsion: 9000, idealEdgeLength: 90 },
      wheelSensitivity: 0.2,
    });

    graph.on('tap', 'node', (e) => showNode(e.target));
    applyGraphFilter();
  } catch (e) {
    reportError(e, "Couldn't load the dependency graph");
  }
}

function applyGraphFilter() {
  if (!graph) return;
  graph.batch(() => {
    graph.nodes().forEach((n) => {
      const show = graphFilter === 'all' || n.data('kind') === graphFilter;
      n.style('display', show ? 'element' : 'none');
    });
  });
  graph.fit(undefined, 24);
}

/* =======================================================================
   Node drawer
   ======================================================================= */

const nodeDrawer = document.getElementById('node-drawer');

async function showNode(node) {
  const kind = node.data('kind');
  const raw = node.data('raw') || {};
  document.getElementById('node-title').textContent = node.data('label');
  const body = document.getElementById('node-body');

  const kv = (rows) => h('dl', { class: 'kv' }, ...rows.flatMap(([k, v]) => [h('dt', {}, k), h('dd', { class: 'mono' }, v ?? '—')]));

  render(
    body,
    h('div', { class: 'hstack', style: { marginBottom: 'var(--sp-4)' } }, h('span', { class: 'chip acc' }, kind)),
    kv(
      kind === 'container'
        ? [
            ['State', raw.state || '—'],
            ['Status', raw.status || '—'],
            ['Image', raw.image || '—'],
            ['ID', shortId(raw.full_id)],
            ['Ports', (raw.ports || []).join(', ') || 'none'],
            ['Compose', raw.compose_service || '—'],
          ]
        : Object.entries(raw).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)])
    )
  );

  openDrawer(nodeDrawer);

  if (kind === 'container' && raw.full_id) {
    try {
      const info = await get(`/docker/inspect/${encodeURIComponent(raw.full_id)}`);
      body.append(
        h(
          'details',
          { class: 'inspect', style: { marginTop: 'var(--sp-4)' } },
          h('summary', {}, 'Full inspect'),
          // Inspect dumps env vars and mounts, which routinely contain
          // credentials — it stays collapsed behind an explicit click.
          h('pre', { class: 'inspect-json' }, JSON.stringify(info, null, 2))
        )
      );
    } catch {
      /* inspect is best-effort detail */
    }
  }
}

document.getElementById('node-close')?.addEventListener('click', () => closeDrawer(nodeDrawer));

/* =======================================================================
   Boot
   ======================================================================= */

if (dockerAvailable) {
  wireSegmented(document.getElementById('graph-filter'), (v) => {
    graphFilter = v;
    applyGraphFilter();
  });
  document.getElementById('btn-fit').addEventListener('click', () => graph?.fit(undefined, 24));
  document.getElementById('btn-refresh').addEventListener('click', loadGraph);
  loadGraph();
}

refreshServices();
refreshUpdates();
loadActionLog();

// The `docker` topic already triggers a refresh on state changes; this is the
// fallback for stat drift and for when the socket is down.
setInterval(() => {
  if (live.getState() !== 'live' || document.visibilityState === 'visible') refreshServices();
}, 15_000);
