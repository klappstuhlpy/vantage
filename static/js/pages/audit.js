/* The audit log: every change made through Vantage, searchable.
 *
 * Read-only. The page's whole job is to get you from "something changed" to the
 * row that explains it, so the filters compose and the URL carries them — an
 * audit finding you cannot send to someone else is half a finding.
 */

import { get, withQuery } from '../core/api.js';
import { relative, absolute, humanize } from '../core/format.js';
import { h, icon, pill, render, emptyRow, reportError, skeletonRows, openModal, copyText } from '../core/ui.js';

const $ = (id) => document.getElementById(id);

const body = $('entries-body');
const moreBtn = $('more');
const coverage = $('coverage');
const qInput = $('q');
const actionSelect = $('action');
const actorSelect = $('actor');
const failuresBox = $('failures');

/** Rows currently shown. Kept so "Load older" appends rather than replaces. */
let rows = [];
/** The id to page below, or null at the top of the log. */
let before = null;
/** Filter values recovered from the URL, applied once the selects are filled. */
let fromUrl = { action: '', actor: '' };

/* An action name is `area.thing.verb`. The area is how anyone actually reads
 * this log ("what happened to the firewall?"), so it gets the icon and the
 * grouping, and the rest is shown as written. */
const AREA_ICONS = {
  account: 'user-cog',
  alerts: 'bell',
  backup: 'archive',
  database: 'database',
  docker: 'container',
  firewall: 'brick-wall',
  health: 'heart-pulse',
  proxy: 'route',
  script: 'square-terminal',
  ssh: 'key-round',
};

const areaOf = (action) => action.split('.')[0];

// ─── Filters ─────────────────────────────────────────────────────────────────

function currentFilter() {
  return {
    q: qInput.value.trim() || undefined,
    action: actionSelect.value || undefined,
    actor: actorSelect.value || undefined,
    failures: failuresBox.checked || undefined,
  };
}

/** Mirrors the filter into the URL so a view can be sent to someone else. */
function syncUrl(filter) {
  const url = withQuery(location.pathname, filter);
  history.replaceState(null, '', url);
}

/** Restores the filter from the URL on load, so a shared link opens the view. */
function restoreFilter() {
  const params = new URLSearchParams(location.search);
  qInput.value = params.get('q') || '';
  failuresBox.checked = params.get('failures') === 'true';
  // The selects are populated from the data, so their values are applied once
  // the first response has told us what the options are.
  return { action: params.get('action') || '', actor: params.get('actor') || '' };
}

/** `firewall.` reads as an area; `ssh.key.revoke` is already how it is written. */
const optionLabel = (value) => (value.endsWith('.') ? `${humanize(value.slice(0, -1))} — everything` : value);

/** Fills a <select> without losing what is currently chosen. */
function fillSelect(select, values, { keep }) {
  const chosen = select.value || keep || '';
  const first = select.options[0];
  render(
    select,
    first,
    ...values.map((v) => h('option', { value: v, selected: v === chosen ? '' : null }, optionLabel(v)))
  );
  select.value = chosen;
}

/** The distinct areas, plus the exact actions, as one menu.
 *
 * Both are offered because both questions get asked: "what happened to the
 * firewall?" wants `firewall.`, and "who revoked a key?" wants `ssh.key.revoke`.
 * The server treats a trailing dot as a prefix, so one field answers both.
 */
function actionOptions(actions) {
  const areas = [...new Set(actions.map(areaOf))].sort();
  return [...areas.map((a) => `${a}.`), ...actions];
}

// ─── Rows ────────────────────────────────────────────────────────────────────

function detailModal(entry) {
  const dialog = h(
    'dialog',
    { class: 'modal', style: { width: 'min(680px, calc(100vw - 32px))' } },
    h(
      'div',
      { class: 'modal-header' },
      h('span', { class: 'modal-title' }, entry.action),
      entry.ok ? null : pill('down', 'refused or failed')
    ),
    h(
      'div',
      { class: 'modal-body' },
      h(
        'dl',
        { class: 'detail-list' },
        h('dt', {}, 'When'),
        h('dd', {}, absolute(entry.at)),
        h('dt', {}, 'Who'),
        h('dd', {}, entry.actor),
        h('dt', {}, 'From'),
        h('dd', {}, entry.ip || 'no address recorded'),
        ...(entry.target ? [h('dt', {}, 'Target'), h('dd', {}, entry.target)] : [])
      ),
      entry.detail && Object.keys(entry.detail).length
        ? h('pre', { class: 'detail-json' }, h('code', {}, JSON.stringify(entry.detail, null, 2)))
        : h('p', { class: 'muted' }, 'No further detail was recorded for this action.')
    ),
    h(
      'div',
      { class: 'modal-footer' },
      h(
        'button',
        {
          class: 'btn quiet',
          type: 'button',
          // The whole row, not just the JSON: an audit entry quoted into a
          // ticket is worthless without who and when.
          onclick: () => copyText(JSON.stringify(entry, null, 2), 'Entry copied'),
        },
        icon('copy'),
        'Copy'
      ),
      h('button', { class: 'btn', type: 'button', 'data-close': '' }, 'Close')
    )
  );
  document.body.append(dialog);
  openModal(dialog, { onClose: () => setTimeout(() => dialog.remove(), 400) });
}

function entryRow(entry) {
  const area = areaOf(entry.action);
  return h(
    'tr',
    { class: entry.ok ? null : 'is-failed' },
    h('td', { class: 'nowrap', title: absolute(entry.at) }, relative(entry.at)),
    h('td', {}, entry.actor),
    h(
      'td',
      {},
      h(
        'span',
        { class: 'action-cell' },
        icon(AREA_ICONS[area] || 'circle-dashed'),
        h('code', {}, entry.action),
        // Only failures are marked. Marking the successes too would put a badge
        // on every row, which is the same as marking none of them.
        entry.ok ? null : pill('down', 'failed')
      )
    ),
    h('td', { class: 'target-cell' }, entry.target || h('span', { class: 'muted' }, '—')),
    h('td', { class: 'nowrap' }, entry.ip || h('span', { class: 'muted' }, '—')),
    h(
      'td',
      {},
      h(
        'button',
        { class: 'link-btn', type: 'button', onclick: () => detailModal(entry) },
        h('span', { class: 'sr-only' }, `Show detail for ${entry.action}`),
        icon('chevron-right')
      )
    )
  );
}

// ─── Load ────────────────────────────────────────────────────────────────────

function describeCoverage({ rows: total, oldest, retention_days }) {
  if (!total) {
    return `Nothing has been recorded yet. Entries are kept for ${retention_days} days.`;
  }
  // What is actually held, not what the policy promises: on a young install
  // those differ by months, and the second answer is the one that matters when
  // you are looking for something from March.
  const since = oldest ? `back to ${absolute(oldest)}` : '';
  return `${total} ${total === 1 ? 'entry' : 'entries'} ${since} — kept for ${retention_days} days.`;
}

async function load({ append = false } = {}) {
  const filter = currentFilter();
  if (!append) {
    before = null;
    rows = [];
    render(body, ...skeletonRows(6, 5));
  }
  syncUrl(filter);

  try {
    const data = await get(withQuery('/audit/data', { ...filter, before: before ?? undefined }));

    rows = append ? [...rows, ...data.entries] : data.entries;
    if (!rows.length) {
      render(
        body,
        emptyRow(
          6,
          Object.values(filter).some(Boolean)
            ? 'Nothing matches those filters.'
            : 'Nothing has been recorded yet. Changes you make through Vantage will appear here.'
        )
      );
    } else {
      render(body, ...rows.map(entryRow));
    }

    fillSelect(actionSelect, actionOptions(data.actions), { keep: fromUrl.action });
    fillSelect(actorSelect, [...new Set(data.entries.map((e) => e.actor))].sort(), { keep: fromUrl.actor });

    moreBtn.hidden = !data.more;
    before = rows.length ? rows[rows.length - 1].id : null;
    coverage.textContent = describeCoverage(data.coverage);
  } catch (err) {
    reportError(err, 'Could not read the audit log');
    render(body, emptyRow(6, 'Could not read the audit log.'));
  }
}

// ─── Wiring ──────────────────────────────────────────────────────────────────

let debounce;
qInput.addEventListener('input', () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => load(), 250);
});

for (const el of [actionSelect, actorSelect, failuresBox]) {
  el.addEventListener('change', () => load());
}

moreBtn.addEventListener('click', () => load({ append: true }));

fromUrl = restoreFilter();
load().then(() => {
  // The selects only have options once the first response has said what they
  // are, so a filter restored from the URL is applied after the first fetch —
  // and only re-fetched if the option actually exists, since a link to an action
  // that has since aged out must not loop.
  actionSelect.value = fromUrl.action;
  actorSelect.value = fromUrl.actor;
  if (actionSelect.value || actorSelect.value) load();
});
