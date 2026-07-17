/* SSH audit — the key and token event log.
 *
 * ssh_audit.html said "Loading SSH audit log..." forever: its script tag
 * pointed at a file that did not exist. This is new.
 *
 * The backend filters `action` by prefix, so "ssh.key" matches every key event.
 * The filter box says "action" rather than pretending to be a full-text search
 * over a log it cannot search.
 */

import { get, withQuery } from '../core/api.js';
import { h, render, pill, emptyRow, skeletonRows, reportError, withLoading } from '../core/ui.js';
import { num, relative, absolute, humanize, startTimestampTicker } from '../core/format.js';

const bodyEl = document.getElementById('audit-body');
const actionEl = document.getElementById('action');
const limitEl = document.getElementById('limit');
const countEl = document.getElementById('count');
const refreshBtn = document.getElementById('refresh-btn');

let seq = 0;

/**
 * The tone of an event. Anything that removes access (revoke, delete) is not a
 * failure — it is an operator doing their job — so it reads as a warning rather
 * than an error. A rejected authentication is the one that should catch an eye.
 */
function tone(action) {
  const a = action.toLowerCase();
  if (a.includes('fail') || a.includes('reject') || a.includes('denied')) return 'down';
  if (a.includes('revoke') || a.includes('delete')) return 'warn';
  if (a.includes('add') || a.includes('issue') || a.includes('create')) return 'acc';
  return 'idle';
}

function renderRows(entries) {
  countEl.textContent = entries.length ? `${num(entries.length)} ${entries.length === 1 ? 'event' : 'events'}` : '';

  if (!entries.length) {
    render(
      bodyEl,
      emptyRow(
        5,
        actionEl.value.trim()
          ? 'No event matches that action.'
          : 'Nothing recorded yet. Key and token activity will appear here as it happens.'
      )
    );
    return;
  }

  render(
    bodyEl,
    ...entries.map((e) =>
      h(
        'tr',
        {},
        h('td', {}, h('time', { class: 'js-ts', datetime: e.created_at, title: absolute(e.created_at) }, relative(e.created_at))),
        // The raw action is the searchable identifier, so keep it verbatim in
        // the title while showing the readable form.
        h('td', { title: e.action }, pill(tone(e.action), humanize(e.action.replace(/^ssh\./, '')))),
        h('td', { class: 'mono' }, e.key_id != null ? h('span', {}, `#${e.key_id}`) : h('span', { class: 'muted' }, '—')),
        h('td', { class: 'mono' }, e.ip || h('span', { class: 'muted' }, 'local')),
        h(
          'td',
          { class: 'ua', title: e.user_agent || '' },
          e.user_agent || h('span', { class: 'muted' }, '—')
        )
      )
    )
  );
}

async function load() {
  const mySeq = ++seq;
  render(bodyEl, ...skeletonRows(5));

  try {
    const d = await get(
      withQuery('/ssh/audit/data', {
        action: actionEl.value.trim() || undefined,
        limit: limitEl.value,
      })
    );
    if (mySeq !== seq) return;
    renderRows(d.entries || []);
  } catch (e) {
    if (mySeq !== seq) return;
    reportError(e, "Couldn't load the audit log");
    render(bodyEl, emptyRow(5, 'Unavailable.'));
  }
}

let debounce;
actionEl.addEventListener('input', () => {
  clearTimeout(debounce);
  debounce = setTimeout(load, 250);
});

limitEl.addEventListener('change', load);
refreshBtn.addEventListener('click', () => withLoading(refreshBtn, load));

startTimestampTicker();
load();
