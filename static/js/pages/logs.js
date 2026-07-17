/* Logs — tail and filter Vantage's rolling log, and the site's when configured.
 *
 * Two things the old viewer got wrong, both about trust:
 *
 *   - It never showed which file it was reading. The backend falls back to the
 *     newest rotated file when today.log is missing, so the page could quietly
 *     be showing yesterday. The filename is now on screen.
 *
 *   - Its file picker had exactly one option ("Application") and the endpoint
 *     accepts no file parameter at all. A control that cannot do anything is
 *     worse than no control, so it was removed. The source picker below is the
 *     same rule applied the other way: the server only renders it when
 *     `site_logs_path` gives it a second source to actually switch to.
 *
 * The level filter is exact-match, not a threshold — that is what the backend
 * does (`level.eq_ignore_ascii_case`), so "Warn" means warnings only, not
 * "warnings and worse". The labels say "All / Error / Warn …" rather than
 * "minimum level" so the control doesn't promise semantics it doesn't have.
 */

import { get, withQuery } from '../core/api.js';
import { h, render, wireSegmented, reportError, copyText } from '../core/ui.js';
import { num, clock, absolute } from '../core/format.js';

const viewEl = document.getElementById('view');
const qEl = document.getElementById('q');
const limitEl = document.getElementById('limit');
const followEl = document.getElementById('follow');
const refreshBtn = document.getElementById('refresh-btn');
const copyBtn = document.getElementById('copy-btn');
const fileChip = document.getElementById('file-chip');
const countEl = document.getElementById('count');

const sourceEl = document.getElementById('source');

const FOLLOW_MS = 5000;

let level = '';
// Absent picker means one source, and the server defaults to it anyway.
let source = 'vantage';
let timer = null;
let seq = 0;
let lines = [];

/* =======================================================================
   Render
   ======================================================================= */

/**
 * Highlight the search term inside a line.
 * Built as DOM nodes, never innerHTML: a log line is arbitrary text from
 * anywhere in the system, and this page's whole job is to display strings an
 * attacker may have chosen.
 */
function highlight(text, needle) {
  if (!needle) return [text];
  const out = [];
  const hay = text.toLowerCase();
  const n = needle.toLowerCase();
  let i = 0;
  while (true) {
    const at = hay.indexOf(n, i);
    if (at === -1) {
      out.push(text.slice(i));
      break;
    }
    if (at > i) out.push(text.slice(i, at));
    out.push(h('mark', {}, text.slice(at, at + n.length)));
    i = at + n.length;
  }
  return out;
}

function renderLines() {
  const needle = qEl.value.trim();

  if (!lines.length) {
    render(
      viewEl,
      h(
        'div',
        { class: 'log-empty' },
        needle || level ? 'No line matches this filter.' : 'The log is empty — nothing has been written to it yet.'
      )
    );
    countEl.textContent = '—';
    return;
  }

  render(
    viewEl,
    ...lines.map((l) =>
      h(
        'div',
        { class: 'log-row' },
        // The log stores a full RFC3339 stamp; the clock is what you read while
        // scanning, and the date stays one hover away.
        h('span', { class: 'log-ts', title: l.ts ? absolute(l.ts) : '' }, l.ts ? clock(l.ts) : '—'),
        h('span', { class: `log-lvl ${l.level}` }, l.level),
        l.target ? h('span', { class: 'log-target', title: l.target }, l.target) : null,
        h('span', { class: 'log-msg' }, ...highlight(l.message, needle))
      )
    )
  );

  countEl.textContent = `${num(lines.length)} ${lines.length === 1 ? 'line' : 'lines'}`;
}

/* =======================================================================
   Load
   ======================================================================= */

async function load({ keepScroll = false } = {}) {
  const mySeq = ++seq;

  // Following means "keep me at the newest line" — but only if the operator is
  // already there. Yanking the view back down while they are reading something
  // further up is the single most irritating thing a log tail can do.
  const atBottom = viewEl.scrollHeight - viewEl.scrollTop - viewEl.clientHeight < 40;
  const prevTop = viewEl.scrollTop;

  try {
    const d = await get(
      withQuery('/logs/data', {
        source,
        q: qEl.value.trim() || undefined,
        level: level || undefined,
        limit: limitEl.value,
      })
    );
    if (mySeq !== seq) return;

    lines = d.lines || [];

    if (d.file) {
      fileChip.hidden = false;
      fileChip.textContent = d.file;
      fileChip.title = `Reading ${d.file}`;
    } else {
      fileChip.hidden = false;
      fileChip.textContent = 'no log file';
      fileChip.title = 'No log file was found in the log directory.';
    }

    renderLines();

    if (keepScroll && !atBottom) viewEl.scrollTop = prevTop;
    else viewEl.scrollTop = viewEl.scrollHeight;
  } catch (e) {
    if (mySeq !== seq) return;
    reportError(e, "Couldn't read the log");
    render(viewEl, h('div', { class: 'log-empty' }, 'The log could not be read.'));
  }
}

/* =======================================================================
   Wiring
   ======================================================================= */

let debounce;
qEl.addEventListener('input', () => {
  clearTimeout(debounce);
  // The filter runs server-side over the whole file; don't fire on every key.
  debounce = setTimeout(() => load(), 250);
});

limitEl.addEventListener('change', () => load());

wireSegmented(document.getElementById('level'), (v) => {
  level = v;
  load();
});

// Only present when the server rendered it (site_logs_path configured).
if (sourceEl) {
  wireSegmented(sourceEl, (v) => {
    source = v;
    // A different file is a different log, not a scrolled position in this one.
    lines = [];
    load();
  });
}

refreshBtn.addEventListener('click', () => load());

followEl.addEventListener('change', () => {
  clearInterval(timer);
  timer = null;
  if (followEl.checked) {
    timer = setInterval(() => load({ keepScroll: true }), FOLLOW_MS);
    load();
  }
});

// A tab in the background doesn't need polling, and an operator returning to it
// wants what is true now, not a five-second-old frame.
document.addEventListener('visibilitychange', () => {
  if (!followEl.checked) return;
  if (document.hidden) {
    clearInterval(timer);
    timer = null;
  } else if (!timer) {
    load({ keepScroll: true });
    timer = setInterval(() => load({ keepScroll: true }), FOLLOW_MS);
  }
});

copyBtn.addEventListener('click', () => {
  if (!lines.length) return;
  copyText(lines.map((l) => l.raw).join('\n'), `Copied ${num(lines.length)} lines`);
});

load();
