/* Database console — browse the configured databases and run ad-hoc SQL.
 *
 * The whole design question on this page is safe mode. The backend runs queries
 * read-only unless `danger_mode` is set — `PRAGMA query_only` on SQLite, a
 * `READ ONLY` transaction on Postgres — so safe mode is a real guarantee, not a
 * lint, and turning it off is the single most dangerous thing this UI can do.
 * The old page made it a checkbox sitting next to Run, which is a UI you can
 * disarm by accident.
 *
 * Here it is a switch that confirms before it disengages, and stays visibly off
 * (a persistent banner, not a subtle tint) for as long as it is off. It also
 * re-arms on reload, because "I left danger mode on last Tuesday" should never
 * be a thing that can happen.
 *
 * The source picker sharpens that: once the console can reach a Postgres that
 * Vantage does not own, "safe mode is off" is not enough on its own — *which*
 * database is unguarded is the part that matters. So the confirmation names the
 * source, the banner names the source, and switching source re-arms safe mode
 * rather than carrying the disarmed state to a new target.
 */

import { get, postUrlEncoded, ApiError } from '../core/api.js';
import { h, icon, render, emptyRow, emptyState, skeletonRows, reportError, confirm, setLoading, wireSegmented } from '../core/ui.js';
import { num } from '../core/format.js';

const tablesBody = document.getElementById('tables-body');
const tableCount = document.getElementById('table-count');
const sourceEl = document.getElementById('source');
const sourceMeta = document.getElementById('source-meta');
const sourceChip = document.getElementById('source-chip-text');
const sqlEl = document.getElementById('sql');
const runBtn = document.getElementById('run-btn');
const safeEl = document.getElementById('safe-mode');
const dangerBanner = document.getElementById('danger-banner');
const dangerSource = document.getElementById('danger-source');
const errorEl = document.getElementById('error');
const metaEl = document.getElementById('meta');
const headEl = document.getElementById('result-head');
const bodyEl = document.getElementById('result-body');
const rolesTab = document.getElementById('roles-tab');
const rolesPanel = document.getElementById('roles-panel');
const queryPanel = document.getElementById('query-panel');

/** Every database the server offered, by source id. */
let sources = new Map();

/** The source id every request on this page is addressed to. */
function current() {
  return sourceEl.value;
}

function currentInfo() {
  return sources.get(current());
}

/** A human name for the active source, for prose (confirmations, the banner). */
function currentLabel() {
  const info = currentInfo();
  if (!info) return 'this database';
  return info.kind === 'postgres' ? `${info.name} (PostgreSQL)` : `${info.name}.db`;
}

/* =======================================================================
   Sources
   ======================================================================= */

async function loadSources() {
  try {
    const list = await get('/database/sources');
    sources = new Map(list.map((d) => [d.id, d]));

    render(
      sourceEl,
      ...list.map((d) =>
        h('option', { value: d.id }, d.kind === 'postgres' ? `${d.name} · postgres` : `${d.name} · sqlite`)
      )
    );

    // Vantage's own database is the one people come here for most, so it is the
    // landing source when it is present.
    if (sources.has('sqlite:admin')) sourceEl.value = 'sqlite:admin';
    syncSource();
  } catch (e) {
    reportError(e, "Couldn't list the databases");
  }
}

/** Repaint everything that names or depends on the active source. */
function syncSource() {
  const info = currentInfo();
  const isPg = info?.kind === 'postgres';

  sourceChip.textContent = info ? `${info.name} · ${info.size_pretty}` : '—';
  sourceMeta.textContent = info ? [info.kind, isPg ? `owner ${info.owner}` : null, info.encoding].filter(Boolean).join(' · ') : '';
  dangerSource.textContent = currentLabel();

  // SQLite has no roles, so the tab is meaningless for those sources. Hiding it
  // rather than showing an empty table keeps the page honest about what the
  // backend can actually answer.
  if (rolesTab) {
    rolesTab.hidden = !isPg;
    if (!isPg && !rolesPanel.hidden) showPanel('query');
  }

  // A sensible opening query per backend: `sqlite_master` does not exist on
  // Postgres, and leaving the old one in the box would just fail on first Run.
  const stale = !sqlEl.dataset.touched;
  if (stale) {
    sqlEl.value = isPg
      ? "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
      : "SELECT name FROM sqlite_master WHERE type='table';";
  }
}

sourceEl.addEventListener('change', () => {
  // Danger mode does not follow you to another database. It was granted for the
  // source you were looking at, and silently re-pointing an unguarded console at
  // a production Postgres is precisely the accident this page exists to prevent.
  if (!safeEl.checked) {
    safeEl.checked = true;
    syncSafeMode();
  }
  syncSource();
  clearResult();
  loadTables();
});

/* =======================================================================
   Catalog
   ======================================================================= */

async function loadTables() {
  render(tablesBody, ...skeletonRows(2, 6));
  try {
    const tables = await get(`/database/tables?source=${encodeURIComponent(current())}`);
    tableCount.textContent = num(tables.length);

    if (!tables.length) {
      render(tablesBody, emptyRow(2, 'No tables.'));
      return;
    }

    const isPg = currentInfo()?.kind === 'postgres';

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
                // Postgres puts the same table name in several schemas, so the
                // list has to say which one — but only where that is a real
                // distinction. Every SQLite table is in `main`.
                title: isPg ? `${t.schema}.${t.name} · owner ${t.owner} · ${t.size_pretty}` : t.name,
                // Browsing a table is the most common thing anyone does here,
                // and typing the SELECT by hand every time is friction with no
                // purpose. Identifiers are quoted because a table may be named
                // after a keyword — and quoting is per-part, so a dot in a name
                // cannot turn into a schema separator.
                onclick: () => {
                  const target = isPg ? `"${t.schema}"."${t.name}"` : `"${t.name}"`;
                  sqlEl.value = `SELECT * FROM ${target} LIMIT 100;`;
                  sqlEl.dataset.touched = '1';
                  run();
                },
              },
              isPg && t.schema !== 'public' ? `${t.schema}.${t.name}` : t.name
            )
          ),
          // On Postgres this is the planner's estimate (n_live_tup), on SQLite
          // an exact COUNT(*). The title says which, rather than one label
          // quietly meaning two things.
          h(
            'td',
            {
              class: 'num mono dim',
              title: isPg ? 'Estimated from the table statistics, not counted' : 'Counted exactly',
            },
            num(t.row_estimate)
          )
        )
      )
    );
  } catch (e) {
    reportError(e, "Couldn't list the tables");
    render(tablesBody, emptyRow(2, 'Unavailable.'));
  }
}

/* =======================================================================
   Roles (Postgres only)
   ======================================================================= */

const yesNo = (on) => h('span', { class: on ? 'pill warn' : 'pill' }, on ? 'yes' : 'no');

async function loadRoles() {
  const body = document.getElementById('roles-body');
  render(body, ...skeletonRows(5, 5));
  try {
    const roles = await get('/database/roles');
    document.getElementById('role-count').textContent = num(roles.length);

    if (!roles.length) {
      render(body, emptyRow(5, 'No roles.'));
      return;
    }

    render(
      body,
      ...roles.map((r) =>
        h(
          'tr',
          {},
          h('td', { class: 'mono' }, r.name),
          // A superuser and a login-capable role are the two facts on this page
          // worth spotting from across the room, so they read as warnings.
          h('td', {}, yesNo(r.superuser)),
          h('td', {}, yesNo(r.can_login)),
          h('td', {}, yesNo(r.can_create_db)),
          h('td', {}, yesNo(r.can_create_role))
        )
      )
    );
  } catch (e) {
    reportError(e, "Couldn't list the roles");
    render(body, emptyRow(5, 'Unavailable.'));
  }
}

/* =======================================================================
   Tabs
   ======================================================================= */

function showPanel(which) {
  queryPanel.hidden = which !== 'query';
  if (rolesPanel) rolesPanel.hidden = which !== 'roles';
  if (which === 'roles') loadRoles();
}

const tabsEl = document.getElementById('db-tabs');
if (tabsEl) wireSegmented(tabsEl, showPanel);

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

  // Unchecking means "let me write to the live database". Ask, name the target,
  // and default to no. The target is in the question because the answer differs:
  // an unguarded query against admin.db costs you Vantage, one against a
  // production Postgres costs you the thing Vantage was watching.
  const info = currentInfo();
  const ok = await confirm({
    title: `Turn off safe mode for ${currentLabel()}?`,
    message:
      `Queries will run unguarded against ${currentLabel()}` +
      (info?.kind === 'postgres' ? ', an external PostgreSQL instance Vantage does not own' : '') +
      '. A mistaken UPDATE or DROP takes effect immediately and cannot be undone from here. Safe mode comes back on when you reload the page or switch database.',
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
    const r = await postUrlEncoded('/database/query', { sql, source: current(), danger_mode: !safeEl.checked });
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

// Once the operator edits the box, the per-source default query stops
// overwriting it — switching source must not discard SQL someone is writing.
sqlEl.addEventListener('input', () => {
  sqlEl.dataset.touched = '1';
});

syncSafeMode();
// The catalog first: it decides which source is active, and the table list is
// addressed to that source.
loadSources().then(loadTables);
