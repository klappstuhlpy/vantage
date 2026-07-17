/* Secrets — credentials found in plain text on this host.
 *
 * ── On masking the match ─────────────────────────────────────────────────
 * The old page printed the matched snippet straight into the table. That is
 * the one thing this page must not do by default: the whole premise is that
 * these strings are live credentials, and rendering them unprompted leaks them
 * to anyone glancing at the screen, and into every screenshot an operator
 * pastes into a ticket while asking for help.
 *
 * So a match is masked until you ask for it, per row, and never in bulk. That
 * is a deliberate ergonomic cost: revealing a credential should be an act, not
 * the default state of a page you left open on a second monitor.
 */

import { get, post, postUrlEncoded } from '../core/api.js';
import { h, icon, render, pill, emptyRow, emptyState, skeletonRows, reportError, withLoading, wireSegmented, toastOk, copyText } from '../core/ui.js';
import { num, relative, absolute, startTimestampTicker } from '../core/format.js';

const tilesEl = document.getElementById('tiles');
const bodyEl = document.getElementById('findings-body');
const scanBtn = document.getElementById('scan-btn');
const refreshBtn = document.getElementById('refresh-btn');

let filter = 'open';
let seq = 0;

const SEVERITY_TONE = { critical: 'down', high: 'warn', medium: 'info', low: 'idle' };

/* =======================================================================
   Tiles
   ======================================================================= */

function tile(label, value, sub, status, iconName) {
  return h(
    'div',
    { class: `stat${status ? ` ${status}` : ''}` },
    h('span', { class: 'stat-key' }, icon(iconName), label),
    h('span', { class: 'stat-value' }, value),
    h('span', { class: 'stat-sub' }, sub)
  );
}

function renderTiles(d) {
  const c = d.counts;
  const scan = d.last_scan;

  let scanValue = 'Never';
  let scanSub = d.scanner_enabled ? 'no scan has run yet' : 'scanner is idle';
  if (scan?.finished_at) {
    scanValue = relative(scan.finished_at);
    scanSub = `${num(scan.files_scanned)} files · ${num(scan.findings_new)} new`;
  } else if (scan?.started_at) {
    // Started but never finished: the scan is either running now or it died.
    scanValue = 'Running…';
    scanSub = `started ${relative(scan.started_at)}`;
  }

  render(
    tilesEl,
    tile('Open', num(c.open), 'need a decision', c.open ? 'warn' : 'ok', 'key-round'),
    tile('Critical', num(c.critical_open), 'match a known key format', c.critical_open ? 'down' : 'ok', 'triangle-alert'),
    tile('Dismissed', num(c.dismissed), 'marked not a leak', null, 'eye-off'),
    tile('Last scan', scanValue, scanSub, scan?.error ? 'down' : null, 'radar')
  );

  if (scan?.error) {
    tilesEl.append(
      h('div', { class: 'scan-error' }, icon('circle-x'), h('span', {}, `The last scan failed: ${scan.error}`))
    );
  }
}

/* =======================================================================
   Findings
   ======================================================================= */

/**
 * The masked form. We show the shape of the match — its length and the rule
 * that caught it — without showing the value, so a row is still triageable at
 * a glance without being a disclosure.
 */
function maskedMatch(snippet) {
  const len = snippet.length;
  const dots = '•'.repeat(Math.min(Math.max(len, 8), 24));
  return h('span', { class: 'masked' }, dots, h('span', { class: 'masked-len' }, `${len} chars`));
}

function matchCell(f) {
  const wrap = h('div', { class: 'match' });
  const value = h('span', { class: 'match-value' }, maskedMatch(f.snippet));
  let revealed = false;

  const toggle = h(
    'button',
    {
      class: 'btn sm ghost icon-only',
      type: 'button',
      'aria-label': 'Reveal match',
      'aria-pressed': 'false',
      onclick: () => {
        revealed = !revealed;
        render(value, revealed ? h('code', { class: 'match-raw' }, f.snippet) : maskedMatch(f.snippet));
        render(toggle, icon(revealed ? 'eye-off' : 'eye'));
        toggle.setAttribute('aria-pressed', String(revealed));
        toggle.setAttribute('aria-label', revealed ? 'Hide match' : 'Reveal match');
      },
    },
    icon('eye')
  );

  const copy = h(
    'button',
    { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': 'Copy match', onclick: () => copyText(f.snippet, 'Match copied') },
    icon('copy')
  );

  wrap.append(value, h('span', { class: 'match-actions' }, toggle, copy));
  return wrap;
}

/** The actions a finding can take, given where it currently is. */
function actionsFor(f, refresh) {
  const act = (label, status, cls) =>
    h(
      'button',
      {
        class: `btn sm ${cls}`,
        type: 'button',
        onclick: (e) =>
          withLoading(e.currentTarget, async () => {
            await postUrlEncoded(`/secrets/${f.id}/status`, { status });
            toastOk(label === 'Reopen' ? 'Finding reopened' : `Marked ${status}`);
            refresh();
          }),
      },
      label
    );

  if (f.status === 'open') {
    return h(
      'div',
      { class: 'btn-row' },
      act('Dismiss', 'dismissed', 'quiet'),
      act('Resolve', 'resolved', 'outline')
    );
  }
  return h('div', { class: 'btn-row' }, act('Reopen', 'open', 'quiet'));
}

function renderFindings(rows, refresh) {
  if (!rows.length) {
    const msg =
      filter === 'open'
        ? 'No open findings — nothing on this host is leaking a credential that Vantage recognises.'
        : `No ${filter} findings.`;
    render(bodyEl, emptyRow(6, msg));
    return;
  }

  render(
    bodyEl,
    ...rows.map((f) =>
      h(
        'tr',
        { class: f.status !== 'open' ? 'is-muted' : '' },
        h('td', {}, pill(SEVERITY_TONE[f.severity] || 'idle', f.severity)),
        h('td', {}, h('span', { class: 'rule' }, f.rule)),
        // Path and line together: a finding you can't locate is not actionable.
        h(
          'td',
          { class: 'mono path', title: f.file_path },
          h('span', { class: 'path-text' }, f.file_path),
          h('span', { class: 'path-line' }, `:${f.line}`)
        ),
        h('td', {}, matchCell(f)),
        h('td', {}, h('time', { class: 'js-ts', datetime: f.last_seen, title: absolute(f.last_seen) }, relative(f.last_seen))),
        h('td', { class: 'actions' }, actionsFor(f, refresh))
      )
    )
  );
}

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  const mySeq = ++seq;
  render(bodyEl, ...skeletonRows(6));

  try {
    const d = await get(`/secrets/data?status=${encodeURIComponent(filter)}`);
    if (mySeq !== seq) return;
    renderTiles(d);
    renderFindings(d.findings, load);
  } catch (e) {
    if (mySeq !== seq) return;
    reportError(e, "Couldn't load findings");
    render(tilesEl, emptyState({ degraded: true, title: "Couldn't load findings", sub: e?.message }));
    render(bodyEl, emptyRow(6, 'Unavailable.'));
  }
}

scanBtn?.addEventListener('click', () =>
  withLoading(scanBtn, async () => {
    const r = await post('/secrets/scan');
    // The endpoint answers 200 with started:false when nothing is configured —
    // a queued scan and a refused one must not look the same.
    if (!r.started) {
      reportError(new Error(r.detail), "Scan didn't start");
      return;
    }
    toastOk('Scan queued', 'Findings will appear here as the scan works through your paths.');
    // The scan is asynchronous; give it a moment before the first look.
    setTimeout(load, 2500);
  })
);

refreshBtn?.addEventListener('click', () => withLoading(refreshBtn, load));

wireSegmented(document.getElementById('filter'), (v) => {
  filter = v;
  load();
});

startTimestampTicker();
load();
