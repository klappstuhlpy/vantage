/* Database console — browse Vantage's own tables and run ad-hoc SQL.
 *
 * The whole design question on this page is safe mode. The backend runs queries
 * on a `query_only` connection unless `danger_mode` is set, so safe mode is a
 * real guarantee, not a lint — and turning it off is the single most dangerous
 * thing this UI can do. The old page made it a checkbox sitting next to Run,
 * which is a UI you can disarm by accident.
 *
 * Here it is a switch that confirms before it disengages, and stays visibly
 * off (a persistent banner, not a subtle tint) for as long as it is off. It
 * also re-arms on reload, because "I left danger mode on last Tuesday" should
 * never be a thing that can happen.
 */

import { get, postUrlEncoded, ApiError } from '../core/api.js';
import { h, icon, render, emptyRow, emptyState, skeletonRows, reportError, confirm, setLoading } from '../core/ui.js';
import { num } from '../core/format.js';

const tablesBody = document.getElementById('tables-body');
const tableCount = document.getElementById('table-count');
const sqlEl = document.getElementById('sql');
const runBtn = document.getElementById('run-btn');
const safeEl = document.getElementById('safe-mode');
const dangerBanner = document.getElementById('danger-banner');
const errorEl = document.getElementById('error');
const metaEl = document.getElementById('meta');
const headEl = document.getElementById('result-head');
const bodyEl = document.getElementById('result-body');

/* =======================================================================
   Catalog
   ======================================================================= */

async function loadTables() {
  render(tablesBody, ...skeletonRows(2, 6));
  try {
    const tables = await get('/database/tables');
    tableCount.textContent = num(tables.length);

    if (!tables.length) {
      render(tablesBody, emptyRow(2, 'No tables.'));
      return;
    }

    render(
      tablesBody,
      ...tables.map((t) =>
        h(
          'tr',
          { class: 'table-row-btn' },
          h(
            'td',
            {},
            h(
              'button',
              {
                class: 'table-link',
                type: 'button',
                // Browsing a table is the most common thing anyone does here,
                // and typing the SELECT by hand every time is friction with no
                // purpose. The identifier is quoted because a table may be
                // named after a keyword.
                onclick: () => {
                  sqlEl.value = `SELECT * FROM "${t.name}" LIMIT 100;`;
                  run();
                },
              },
              t.name
            )
          ),
          // "Estimate" is the server's word (row_estimate) and it is honest:
          // it comes from the query planner's statistics, not a COUNT(*).
          h('td', { class: 'num mono dim', title: 'Estimated from the table statistics, not counted' }, num(t.row_estimate))
        )
      )
    );
  } catch (e) {
    reportError(e, "Couldn't list the tables");
    render(tablesBody, emptyRow(2, 'Unavailable.'));
  }
}

/* =======================================================================
   Safe mode
   ======================================================================= */

function syncSafeMode() {
  dangerBanner.hidden = safeEl.checked;
}

safeEl.addEventListener('change', async () => {
  if (safeEl.checked) {
    syncSafeMode();
    return;
  }

  // Unchecking means "let me write to the live database". Ask, and default to no.
  const ok = await confirm({
    title: 'Turn off safe mode?',
    message:
      "Queries will run on a read/write connection against Vantage's live database. A mistaken UPDATE or DROP takes effect immediately and cannot be undone from here. Safe mode comes back on when you reload the page.",
    confirmLabel: 'Turn it off',
    cancelLabel: 'Keep it on',
    danger: true,
  });

  if (!ok) safeEl.checked = true;
  syncSafeMode();
});

/* =======================================================================
   Results
   ======================================================================= */

function clearResult() {
  render(errorEl);
  render(headEl);
  render(bodyEl);
  metaEl.textContent = '';
}

function renderResult(r) {
  render(errorEl);

  const parts = [`${num(r.row_count)} ${r.row_count === 1 ? 'row' : 'rows'}`, `${num(r.elapsed_ms)} ms`];
  metaEl.textContent = parts.join(' · ');

  if (!r.columns.length) {
    // A write in danger mode, or a PRAGMA that returns nothing: it ran, and
    // "no columns" is a result, not a failure.
    render(headEl);
    render(bodyEl);
    render(errorEl, emptyState({ icon: 'circle-check', title: 'The statement ran', sub: 'It returned no rows.' }));
    return;
  }

  render(headEl, h('tr', {}, ...r.columns.map((c) => h('th', {}, c))));

  if (!r.rows.length) {
    render(bodyEl, emptyRow(r.columns.length, 'No rows matched.'));
    return;
  }

  render(
    bodyEl,
    ...r.rows.map((row) =>
      h(
        'tr',
        {},
        // The server stringifies every value before it gets here: a NULL
        // arrives as the text "NULL", a blob as "<blob: n bytes>". So we cannot
        // tell a real NULL from a TEXT value that happens to spell "NULL", and
        // we don't pretend to — cells render exactly what the server said. The
        // one thing worth marking is the empty string, which would otherwise be
        // an invisible cell indistinguishable from a rendering fault.
        ...row.map((cell) =>
          h('td', { class: 'mono cell', title: cell }, cell === '' ? h('span', { class: 'cell-empty' }, 'empty') : cell)
        )
      )
    )
  );

  if (r.truncated) {
    metaEl.textContent = `${parts.join(' · ')} · truncated`;
    metaEl.title = 'The server capped this result set. Add a LIMIT to see a defined slice.';
  } else {
    metaEl.title = '';
  }
}

function renderError(message) {
  render(headEl);
  render(bodyEl);
  metaEl.textContent = '';
  render(
    errorEl,
    h(
      'div',
      { class: 'callout danger db-error', role: 'alert' },
      icon('circle-x'),
      h('div', { class: 'callout-body' }, h('strong', {}, 'The query failed'), h('pre', { class: 'db-error-msg' }, message))
    )
  );
}

/* =======================================================================
   Run
   ======================================================================= */

async function run() {
  const sql = sqlEl.value.trim();
  if (!sql) return;

  setLoading(runBtn, true);
  clearResult();

  try {
    const r = await postUrlEncoded('/database/query', { sql, danger_mode: !safeEl.checked });
    renderResult(r);
    // A write may well have changed the row counts beside us.
    if (!safeEl.checked) loadTables();
  } catch (e) {
    // A rejected query is the operator's SQL being wrong — that is ordinary,
    // it belongs in the result panel, and it must not raise a red toast in the
    // corner as though the host had fallen over.
    if (e instanceof ApiError && (e.status === 400 || e.status === 403)) {
      renderError(e.body?.error || e.message);
    } else {
      reportError(e, "Couldn't run that query");
    }
  } finally {
    setLoading(runBtn, false);
  }
}

runBtn.addEventListener('click', run);

// Ctrl/Cmd+Enter runs — the convention in every SQL console there is, and the
// textarea would otherwise swallow a plain Enter as a newline (correctly).
sqlEl.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    run();
  }
});

syncSafeMode();
loadTables();
