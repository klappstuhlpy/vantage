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

import { get, post, postUrlEncoded, withQuery, ApiError } from '../core/api.js';
import { h, icon, render, emptyRow, emptyState, skeletonRows, reportError, confirm, setLoading, toast, toastOk } from '../core/ui.js';
import { num } from '../core/format.js';
import * as db from '../db/state.js';
import { initTree } from '../db/tree.js';
import { initTabs } from '../db/tabs.js';
import { createGrid } from '../db/grid.js';
import { createFilterBar } from '../db/filters.js';
import { openPeek } from '../db/peek.js';
import { createEditor } from '../db/editor.js';
import { createHistoryPanel } from '../db/history.js';
import { createExplainView } from '../db/explain.js';
import { createErd, erdLegend } from '../db/erd.js';
import { createJump } from '../db/jump.js';
import { formatSort, parseSort } from '../db/orderby.js';
import * as stage from '../db/stagecore.js';

const sourceEl = document.getElementById('source');
const sourceMeta = document.getElementById('source-meta');
const sourceChip = document.getElementById('source-chip-text');
const runBtn = document.getElementById('run-btn');
const explainBtn = document.getElementById('explain-btn');
const cancelBtn = document.getElementById('cancel-btn');
const historyBtn = document.getElementById('history-btn');
const erdBtn = document.getElementById('erd-btn');
const safeEl = document.getElementById('safe-mode');
const dangerBanner = document.getElementById('danger-banner');
const dangerSource = document.getElementById('danger-source');
const errorEl = document.getElementById('error');
const metaEl = document.getElementById('meta');
const headEl = document.getElementById('result-head');
const bodyEl = document.getElementById('result-body');
const rolesPanel = document.getElementById('roles-panel');
const queryPanel = document.getElementById('query-panel');
const tablePanel = document.getElementById('table-panel');

/* =======================================================================
   Editor (CM6) + History panel
   ======================================================================= */

let editorTouched = false;

const editor = createEditor(document.getElementById('editor-mount'), {
  onRun({ sql }) {
    editorTouched = true;
    run(sql);
  },
});

const historyPanel = createHistoryPanel(document.getElementById('history-panel'), {
  getEditor: () => editor,
  getSource: () => db.current(),
});

const explainPanel = document.getElementById('explain-panel');
const explainView = createExplainView(document.getElementById('explain-content'));

const erd = createErd(document.getElementById('erd-mount'), {
  onOpen: (t) => tabs.openTable({ source: db.current(), schema: t.schema, name: t.name }),
});
render(document.getElementById('erd-legend'), erdLegend());
document.getElementById('erd-fit').addEventListener('click', () => erd.fit());
document.getElementById('erd-relayout').addEventListener('click', () => erd.relayout());

historyBtn.addEventListener('click', () => historyPanel.toggle());

explainBtn.addEventListener('click', async () => {
  const sql = (editor.getSelection() || editor.getText()).trim();
  if (!sql) return;

  setLoading(explainBtn, true);
  try {
    const nodes = await postUrlEncoded('/database/explain', { sql, source: db.current() });
    explainPanel.hidden = false;
    explainView.show(nodes);
  } catch (e) {
    if (e instanceof ApiError && e.status === 400) {
      explainPanel.hidden = false;
      explainView.show([]);
      reportError(e, e.body?.error || 'EXPLAIN failed');
    } else {
      reportError(e, "Couldn't explain the query");
    }
  } finally {
    setLoading(explainBtn, false);
  }
});

erdBtn.addEventListener('click', () => {
  const panel = document.getElementById('erd-panel');
  if (erd.visible) {
    erd.hide();
    panel.hidden = true;
  } else {
    panel.hidden = false;
    erd.show();
  }
});

/* State (which sources exist, which one is active) lives in db/state.js — the
   select element is just the control that drives it. */

/* =======================================================================
   Sources
   ======================================================================= */

async function loadSources() {
  try {
    const list = await get('/database/sources');
    db.setSources(list);

    render(
      sourceEl,
      ...list.map((d) =>
        h('option', { value: d.id }, d.kind === 'postgres' ? `${d.name} · postgres` : `${d.name} · sqlite`)
      )
    );

    // A `?source=` deep link (the command palette's database entries) wins, but
    // only after the catalog has confirmed the id — an id that no longer
    // resolves falls back to the default rather than leaving the page pointed
    // at a source the server will refuse. The check is a convenience, not a
    // control: every request re-resolves the id through the catalog server-side.
    const wanted = new URLSearchParams(location.search).get('source');
    if (wanted && db.hasSource(wanted)) sourceEl.value = wanted;
    else if (db.hasSource('sqlite:admin')) sourceEl.value = 'sqlite:admin';
    // Vantage's own database is the one people come here for most, so it is the
    // landing source otherwise.
    db.setCurrent(sourceEl.value);
    syncSource();
  } catch (e) {
    reportError(e, "Couldn't list the databases");
  }
}

/** Repaint everything that names or depends on the active source. */
function syncSource() {
  const info = db.currentInfo();
  const isPg = info?.kind === 'postgres';

  sourceChip.textContent = info ? `${info.name} · ${info.size_pretty}` : '—';
  sourceMeta.textContent = info ? [info.kind, isPg ? `owner ${info.owner}` : null, info.encoding].filter(Boolean).join(' · ') : '';
  dangerSource.textContent = db.currentLabel();

  // SQLite has no roles, so the tab is meaningless for those sources. Hiding it
  // rather than showing an empty table keeps the page honest about what the
  // backend can actually answer.
  tabs.setRolesVisible(isPg);

  // Switch the editor's SQL dialect; schema completion is fed asynchronously
  // once the tree finishes loading (see loadCompletions).
  editor.setDialect(isPg ? 'postgres' : 'sqlite');

  // A sensible opening query per backend: `sqlite_master` does not exist on
  // Postgres, and leaving the old one in the box would just fail on first Run.
  if (!editorTouched) {
    editor.setText(isPg
      ? "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
      : "SELECT name FROM sqlite_master WHERE type='table';");
  }
}

/** Fetches column names for all tables and feeds them to the editor's
 *  autocomplete. Called after the tree loads its overview. */
async function loadCompletions() {
  const source = db.current();
  const overview = db.getOverview(source);
  if (!overview) return;

  const isPg = source.startsWith('pg:');
  const schema = {};

  // Fetch details for all tables in parallel (bounded by browser).
  const fetches = overview.tables.map(async (t) => {
    const params = new URLSearchParams({ source, table: t.name });
    if (isPg && t.schema) params.set('schema', t.schema);
    try {
      const detail = await get(`/database/table?${params}`);
      const key = isPg && t.schema !== 'public' ? `${t.schema}.${t.name}` : t.name;
      schema[key] = detail.columns.map((c) => c.name);
    } catch {
      // Best-effort: a table we can't introspect just won't autocomplete.
    }
  });

  await Promise.all(fetches);

  // Only apply if the source hasn't changed while we were fetching.
  if (db.current() === source) {
    editor.setDialect(isPg ? 'postgres' : 'sqlite', schema);
  }
}

sourceEl.addEventListener('change', () => {
  db.setCurrent(sourceEl.value);
  // Danger mode does not follow you to another database. It was granted for the
  // source you were looking at, and silently re-pointing an unguarded console at
  // a production Postgres is precisely the accident this page exists to prevent.
  if (!safeEl.checked) {
    safeEl.checked = true;
    syncSafeMode();
  }
  syncSource();
  clearResult();
  tree.reload().then(loadCompletions);
});

/* =======================================================================
   Schema tree
   ======================================================================= */

const tree = initTree({
  tree: document.getElementById('db-tree'),
  filter: document.getElementById('tree-filter'),
  count: document.getElementById('tree-count'),
  // Clicking a table opens (or refocuses) its browser tab — the tree finally
  // has a real destination (P2). Views browse the same way, read-only.
  onOpen: (t) => tabs.openTable({ source: db.current(), schema: t.schema, name: t.name }),
});

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

const tabs = initTabs({
  strip: document.getElementById('db-tabstrip'),
  hasRoles: Boolean(rolesPanel),
  onShow(tab) {
    queryPanel.hidden = tab.kind !== 'query';
    if (rolesPanel) rolesPanel.hidden = tab.kind !== 'roles';
    tablePanel.hidden = tab.kind !== 'table';
    if (tab.kind === 'roles') loadRoles();
    if (tab.kind === 'table') showTable(tab);
  },
  onClose(tab) {
    tableStates.delete(tab.id);
  },
});

/* =======================================================================
   Table browser (P2)
   ======================================================================= */

/** Per-tab browser state: loaded rows, filter/sort model, counts, scroll. */
const tableStates = new Map();

/** The table tab currently bound to the grid. */
let activeTable = null;

const gridRange = document.getElementById('grid-range');
const gridHint = document.getElementById('grid-hint');
const countBtn = document.getElementById('count-exact');
const tableError = document.getElementById('table-error');

function stateOf(tab) {
  if (!tableStates.has(tab.id)) {
    tableStates.set(tab.id, {
      columns: [],
      rows: [],
      filters: [],
      sort: null, // {column, desc}
      hasMore: false,
      loaded: false,
      loading: false,
      total: null, // {kind: 'exact'|'estimate'|'unknown', value}
      elapsed: 0,
      scrollTop: 0,
      detail: null, // columns/PK/kind from /database/table — decides editability
      stage: stage.emptyStage(), // P5: staged edits, never sent until Submit
    });
  }
  return tableStates.get(tab.id);
}

const orderByInput = document.getElementById('order-by');

/** Rewrites the ORDER BY box from the tab's sort model. */
function syncOrderBy(tab) {
  orderByInput.value = formatSort(stateOf(tab).sort);
}

const grid = createGrid(document.getElementById('db-grid'), {
  onSort(column) {
    if (!activeTable) return;
    const s = stateOf(activeTable);
    // Click cycles asc → desc → none; a different column starts at asc.
    if (s.sort?.column !== column) s.sort = { column, desc: false };
    else if (!s.sort.desc) s.sort = { column, desc: true };
    else s.sort = null;
    syncOrderBy(activeTable);
    reload(activeTable);
  },
  onNeedMore() {
    if (activeTable) fetchMore(activeTable);
  },
  onPeek({ col, value }) {
    openPeek({ col, value });
  },
  canEdit: () => Boolean(activeTable) && editability(activeTable).ok,
  onEditCommit({ r, c, value }) {
    if (!activeTable) return;
    const s = stateOf(activeTable);
    stage.editCell(s.stage, { columns: s.columns, base: s.rows }, r, c, value);
    paintStage(activeTable);
  },
  cellClass(r, c, column) {
    if (!activeTable) return '';
    const s = stateOf(activeTable);
    return stage.cellStaged(s.stage, s.rows.length, r, column) ? 'staged' : '';
  },
  rowClass(r) {
    if (!activeTable) return '';
    const s = stateOf(activeTable);
    const state = stage.rowStateOf(s.stage, s.rows.length, r);
    return state ? `row-${state}` : '';
  },
  onSelectionChange: () => paintEditBar(),
});

/* Enter applies; blur re-syncs. Typing is not a commit — a sort that reran on
   every keystroke would fire a query per character against a live database. */
orderByInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    applyOrderBy();
  } else if (e.key === 'Escape') {
    e.preventDefault();
    if (activeTable) syncOrderBy(activeTable);
    orderByInput.blur();
  }
});
orderByInput.addEventListener('blur', () => activeTable && applyOrderBy());

function applyOrderBy() {
  if (!activeTable) return;
  const s = stateOf(activeTable);
  const parsed = parseSort(orderByInput.value, s.columns);

  if (!parsed.ok) {
    // The operator's own typo, shown where they typed it — not a toast (§6).
    paintTableError(parsed.error);
    return;
  }

  paintTableError(null);
  const same =
    (parsed.sort?.column ?? null) === (s.sort?.column ?? null) && (parsed.sort?.desc ?? null) === (s.sort?.desc ?? null);
  s.sort = parsed.sort;
  // Normalize what is displayed even when nothing changed: typing `NAME desc`
  // should settle to `name DESC` rather than sitting there as entered.
  syncOrderBy(activeTable);
  if (!same) reload(activeTable);
}

const filterBar = createFilterBar(document.getElementById('filter-bar'), {
  getColumns: () => (activeTable ? stateOf(activeTable).columns : []),
  onChange(filters) {
    if (!activeTable) return;
    stateOf(activeTable).filters = filters;
    reload(activeTable);
  },
});

/** The shared query-string for /rows, /count and /export (D5: filters as JSON). */
function browseUrl(path, tab, s, extra = {}) {
  const params = { source: tab.source, table: tab.name, ...extra };
  if (tab.source.startsWith('pg:')) params.schema = tab.schema;
  if (s.filters.length) params.filters = JSON.stringify(s.filters);
  if (s.sort) {
    params.sort = s.sort.column;
    params.desc = s.sort.desc;
  }
  return withQuery(path, params);
}

async function showTable(tab) {
  if (activeTable && activeTable.id !== tab.id) {
    stateOf(activeTable).scrollTop = grid.scrollTop;
  }
  activeTable = tab;
  const s = stateOf(tab);
  filterBar.set(s.filters);
  syncOrderBy(tab);
  paintTableError(null);
  paintEditBar();
  ensureDetail(tab);

  if (!s.loaded) {
    await reload(tab);
  } else {
    // Through the staging buffer, so switching away from a tab and back does
    // not silently drop edits that are still pending on it.
    grid.setData({ columns: s.columns, rows: stage.viewRows(s.stage, s.columns, s.rows), hasMore: s.hasMore });
    grid.setSort(s.sort);
    grid.setScrollTop(s.scrollTop);
    paintFooter(tab);
    paintEditBar();
  }
}

/** Refetches from offset 0 — the entry point for filter/sort changes too. */
async function reload(tab) {
  const s = stateOf(tab);
  if (s.loading) return;

  // The staging buffer addresses rows by their index in *this* page of results,
  // so any refetch invalidates every index in it. Rebasing would mean guessing
  // which row is "the same row" after a sort or a filter — a guess that, when
  // wrong, writes to the wrong row. Dropping the buffer is the honest move, and
  // it is said out loud rather than done quietly.
  if (stage.isDirty(s.stage)) {
    const n = stage.stagedCount(s.stage);
    stage.clearStage(s.stage);
    toast('warn', 'Staged changes discarded', `Reloading the table dropped ${n} pending change${n === 1 ? '' : 's'}.`);
  }

  s.loading = true;
  paintTableError(null);
  gridRange.textContent = 'loading…';

  try {
    const page = await get(browseUrl('/database/rows', tab, s, { limit: 500, offset: 0 }));
    s.columns = page.columns;
    s.rows = page.rows;
    s.hasMore = page.has_more;
    s.elapsed = page.elapsed_ms;
    s.loaded = true;
    s.scrollTop = 0;
    if (activeTable?.id === tab.id) {
      grid.setData({ columns: s.columns, rows: s.rows, hasMore: s.hasMore });
      grid.setSort(s.sort);
      syncOrderBy(tab);
      paintEditBar();
    }
    updateCount(tab);
  } catch (e) {
    // A refused filter or a broken view is the operator's situation, not an
    // outage: it renders in-pane, exactly where they are looking (§6).
    if (e instanceof ApiError && e.status === 400) paintTableError(e.body?.error || e.message);
    else reportError(e, "Couldn't load the table");
  } finally {
    s.loading = false;
    paintFooter(tab);
  }
}

async function fetchMore(tab) {
  const s = stateOf(tab);
  if (s.loading || !s.hasMore || !s.loaded) return;
  s.loading = true;
  try {
    const page = await get(browseUrl('/database/rows', tab, s, { limit: 500, offset: s.rows.length }));
    s.rows = s.rows.concat(page.rows);
    s.hasMore = page.has_more;
    s.elapsed = page.elapsed_ms;
    if (activeTable?.id === tab.id) {
      // With a dirty buffer the grid's row array is the *view* (base rows plus
      // added ones at the end), so a plain append would land the new page after
      // the added rows. Rebuilding the view puts them back where they belong.
      if (stage.isDirty(s.stage)) {
        grid.replaceRows(stage.viewRows(s.stage, s.columns, s.rows), { hasMore: s.hasMore });
      } else {
        grid.appendRows(page.rows, { hasMore: s.hasMore });
      }
    }
  } catch (e) {
    reportError(e, "Couldn't load more rows");
  } finally {
    s.loading = false;
    paintFooter(tab);
  }
}

/** Counts per D8: exact where cheap (SQLite), labelled estimate + an explicit
 *  "count exactly" affordance where not (Postgres). Never one posing as the
 *  other. */
async function updateCount(tab) {
  const s = stateOf(tab);
  if (tab.source.startsWith('sqlite:')) {
    try {
      const c = await get(browseUrl('/database/count', tab, s));
      s.total = { kind: 'exact', value: c.count };
    } catch {
      s.total = { kind: 'unknown' };
    }
  } else {
    const est = s.filters.length ? null : db.tableEstimate(tab.source, tab.schema, tab.name);
    s.total = est == null ? { kind: 'unknown' } : { kind: 'estimate', value: est };
  }
  if (activeTable?.id === tab.id) paintFooter(tab);
}

countBtn.addEventListener('click', async () => {
  if (!activeTable) return;
  const tab = activeTable;
  const s = stateOf(tab);
  countBtn.disabled = true;
  try {
    const c = await get(browseUrl('/database/count', tab, s));
    s.total = { kind: 'exact', value: c.count };
  } catch (e) {
    reportError(e, "Couldn't count the rows");
  } finally {
    countBtn.disabled = false;
    if (activeTable?.id === tab.id) paintFooter(tab);
  }
});

function paintFooter(tab) {
  if (activeTable?.id !== tab.id) return;
  const s = stateOf(tab);
  const total =
    s.total?.kind === 'exact'
      ? num(s.total.value)
      : s.total?.kind === 'estimate'
        ? `≈ ${num(s.total.value)}`
        : '?';
  gridRange.textContent = s.loaded ? `rows 1–${num(s.rows.length)} of ${total}` : '';
  countBtn.hidden = !s.loaded || s.total?.kind === 'exact';

  const parts = [`${num(s.elapsed)} ms`];
  // The deep-scroll nudge (D8): past 50k rows, OFFSET is doing real work and
  // a filter would serve better than more scrolling.
  if (s.rows.length > 50_000) parts.unshift('deep scroll — a filter would be faster');
  gridHint.textContent = s.loaded ? parts.join(' · ') : '';
}

function paintTableError(message) {
  if (!message) {
    render(tableError);
    return;
  }
  render(
    tableError,
    h(
      'div',
      { class: 'callout danger db-error', role: 'alert' },
      icon('circle-x'),
      h('div', { class: 'callout-body' }, h('strong', {}, 'The table could not be read'), h('pre', { class: 'db-error-msg' }, message))
    )
  );
}

document.getElementById('table-refresh').addEventListener('click', () => {
  if (activeTable) reload(activeTable);
});

/** Downloads go through a transient anchor: the attachment disposition keeps
 *  the page where it is, and every export lands in the audit log server-side. */
function exportTable(format) {
  if (!activeTable) return;
  const url = browseUrl('/database/export', activeTable, stateOf(activeTable), { format });
  const a = h('a', { href: url, download: '' });
  document.body.append(a);
  a.click();
  a.remove();
}

document.getElementById('export-csv').addEventListener('click', () => exportTable('csv'));
document.getElementById('export-ndjson').addEventListener('click', () => exportTable('ndjson'));

const ddlWrap = document.getElementById('table-ddl-wrap');
const ddlCode = document.getElementById('table-ddl-code');

document.getElementById('table-ddl').addEventListener('click', async () => {
  if (!activeTable) return;
  if (!ddlWrap.hidden) {
    ddlWrap.hidden = true;
    return;
  }
  const tab = activeTable;
  const params = { source: tab.source, table: tab.name };
  if (tab.source.startsWith('pg:') && tab.schema) params.schema = tab.schema;
  try {
    const result = await get(withQuery('/database/ddl', params));
    ddlCode.textContent = result.ddl;
    ddlWrap.hidden = false;
  } catch (e) {
    reportError(e, "Couldn't fetch DDL");
  }
});

/* =======================================================================
   Staged editing (P5)
   ======================================================================= *
 *
 * Everything in this section stays in the browser until Submit. Editing a cell,
 * adding a row, marking rows for deletion — all of it lands in the tab's
 * staging buffer (db/stagecore.js), which compiles to a change list only when
 * the operator asks for a preview or a submit.
 *
 * The gates are the interesting part, and they are all server-side: the apply
 * route needs admin, needs global safe mode *off*, needs `danger_mode`, and
 * needs a sudo window no older than ten minutes. The buttons below mirror those
 * so the operator learns which one is closed before they stage twelve edits —
 * but the buttons are courtesy. The server refuses regardless.
 */

const addBtn = document.getElementById('edit-add');
const delBtn = document.getElementById('edit-delete');
const previewBtn = document.getElementById('edit-preview');
const submitBtn = document.getElementById('edit-submit');
const discardBtn = document.getElementById('edit-discard');
const stagedCountEl = document.getElementById('edit-count');
const editHint = document.getElementById('edit-hint');
const previewWrap = document.getElementById('edit-preview-wrap');
const previewList = document.getElementById('edit-preview-list');

/** The primary key's columns, in ordinal order. Empty means the table cannot be
 *  edited here at all — there is no way to address one row. */
function pkColumns(s) {
  if (!s.detail) return [];
  return s.detail.columns
    .filter((c) => c.pk_ordinal != null)
    .sort((a, b) => a.pk_ordinal - b.pk_ordinal)
    .map((c) => c.name);
}

/** Whether this tab can be edited, and if not, the sentence that says why. */
function editability(tab) {
  const s = stateOf(tab);
  if (!s.detail) return { ok: false, why: 'Reading this table’s definition…' };
  if (s.detail.kind !== 'table') return { ok: false, why: 'This is a view — views are read-only here.' };
  if (!pkColumns(s).length) {
    return { ok: false, why: 'No primary key, so a row cannot be addressed. Edit this table from the SQL tab.' };
  }
  return { ok: true, why: '' };
}

/** Fetches the table's definition once per tab; editability depends on it. */
async function ensureDetail(tab) {
  const s = stateOf(tab);
  if (s.detail) return;
  const params = { source: tab.source, table: tab.name };
  if (tab.source.startsWith('pg:') && tab.schema) params.schema = tab.schema;
  try {
    s.detail = await get(withQuery('/database/table', params));
  } catch {
    // Leave it null: the toolbar stays disabled and says it is still reading,
    // which is truthful — we did not learn whether this table has a key.
  }
  if (activeTable?.id === tab.id) paintEditBar();
}

/** Repaints the grid through the staging buffer and refreshes the toolbar. */
function paintStage(tab) {
  const s = stateOf(tab);
  if (activeTable?.id === tab.id) grid.replaceRows(stage.viewRows(s.stage, s.columns, s.rows));
  paintEditBar();
}

function paintEditBar() {
  const tab = activeTable;
  if (!tab) return;
  const s = stateOf(tab);
  const ed = editability(tab);
  const n = stage.stagedCount(s.stage);
  const selected = grid.selectedRows();

  addBtn.disabled = !ed.ok;
  addBtn.title = ed.ok ? 'Add an empty row' : ed.why;

  delBtn.disabled = !ed.ok || !selected.length;
  delBtn.title = !ed.ok ? ed.why : selected.length ? `Delete ${selected.length} selected row(s)` : 'Select rows first';

  previewBtn.disabled = n === 0;
  previewBtn.title = n ? 'Show the statements these changes would run' : 'Nothing staged yet';

  // Submit is the only control here that writes. It needs danger mode for this
  // source on top of everything else, and says so rather than sitting greyed
  // out with no explanation.
  submitBtn.disabled = n === 0 || safeEl.checked;
  submitBtn.title =
    n === 0
      ? 'Nothing staged yet'
      : safeEl.checked
        ? `Safe mode is on for ${db.currentLabel()}. Turn it off to write.`
        : `Run ${n} statement${n === 1 ? '' : 's'} against ${db.currentLabel()}`;

  stagedCountEl.hidden = n === 0;
  stagedCountEl.textContent = `${n} pending`;
  discardBtn.hidden = n === 0;
  editHint.textContent = ed.ok ? '' : ed.why;
  if (!n) previewWrap.hidden = true;
}

/** The payload both routes take — identical, so what the preview shows is
 *  produced from exactly what a submit would send. */
function editPayload(tab) {
  const s = stateOf(tab);
  const built = stage.buildChanges(s.stage, { columns: s.columns, base: s.rows, pkColumns: pkColumns(s) });
  if (!built.ok) {
    paintTableError(built.error);
    return null;
  }
  paintTableError(null);
  const body = { source: tab.source, table: tab.name, changes: built.changes };
  if (tab.source.startsWith('pg:') && tab.schema) body.schema = tab.schema;
  return body;
}

addBtn.addEventListener('click', () => {
  if (!activeTable) return;
  stage.addRow(stateOf(activeTable).stage);
  paintStage(activeTable);
});

delBtn.addEventListener('click', () => {
  if (!activeTable) return;
  const s = stateOf(activeTable);
  const rows = grid.selectedRows();
  // The same button un-marks a selection that is already entirely marked, so
  // an accidental delete is undone by repeating the gesture.
  const allMarked = rows.length && rows.every((r) => stage.rowStateOf(s.stage, s.rows.length, r) === 'deleted');
  if (allMarked) stage.undeleteRows(s.stage, rows);
  else stage.deleteRows(s.stage, s.rows.length, rows);
  paintStage(activeTable);
});

discardBtn.addEventListener('click', () => {
  if (!activeTable) return;
  stage.clearStage(stateOf(activeTable).stage);
  previewWrap.hidden = true;
  paintStage(activeTable);
});

document.getElementById('edit-preview-close').addEventListener('click', () => {
  previewWrap.hidden = true;
});

/* The preview is generated by the server, from the same planner the apply path
   uses. A preview the browser composed would show what the browser *thinks*
   will run, which is the one thing a review step must not do. */
previewBtn.addEventListener('click', async () => {
  if (!activeTable) return;
  const body = editPayload(activeTable);
  if (!body) return;
  setLoading(previewBtn, true);
  try {
    const plan = await post('/database/preview', body);
    render(
      previewList,
      ...plan.statements.map((st) =>
        h('li', { class: `db-preview-item ${st.kind}` }, h('span', { class: 'db-preview-kind' }, st.kind), st.preview)
      )
    );
    previewWrap.hidden = false;
  } catch (e) {
    if (e instanceof ApiError && e.status === 400) paintTableError(e.body?.error || e.message);
    else reportError(e, "Couldn't build the preview");
  } finally {
    setLoading(previewBtn, false);
  }
});

submitBtn.addEventListener('click', async () => {
  if (!activeTable) return;
  const tab = activeTable;
  const body = editPayload(tab);
  if (!body) return;

  const n = body.changes.length;
  const ok = await confirm({
    title: `Run ${n} statement${n === 1 ? '' : 's'} against ${db.currentLabel()}?`,
    message:
      `This writes to ${db.currentLabel()}` +
      (db.isPostgres() ? ', an external PostgreSQL instance Vantage does not own' : '') +
      '. All of it runs in one transaction: if any statement matches a number of rows other than one, the whole batch is rolled back. What it does apply cannot be undone from here.',
    confirmLabel: 'Run them',
    cancelLabel: 'Cancel',
    danger: true,
  });
  if (!ok) return;

  setLoading(submitBtn, true);
  try {
    // `danger_mode` states the intent explicitly; the server still demands a
    // sudo window on top, and core/api.js turns its 403 into the reauth prompt
    // and one transparent retry.
    const report = await post('/database/apply', { ...body, danger_mode: true });
    stage.clearStage(stateOf(tab).stage);
    previewWrap.hidden = true;
    toastOk('Applied', `${report.applied} statement${report.applied === 1 ? '' : 's'} in ${num(report.elapsed_ms)} ms`);
    // Refetch rather than patching the grid in place: the database may have
    // changed more than we asked for (triggers, defaults, cascades), and
    // showing our own guess of the result would be a quiet lie.
    await reload(tab);
    tree.reload();
  } catch (e) {
    if (e instanceof ApiError && (e.status === 400 || e.status === 403 || e.status === 423)) {
      paintTableError(e.body?.error || e.message);
    } else {
      reportError(e, "Couldn't apply the changes");
    }
  } finally {
    setLoading(submitBtn, false);
    paintEditBar();
  }
});

/* =======================================================================
   Safe mode
   ======================================================================= */

function syncSafeMode() {
  dangerBanner.hidden = safeEl.checked;
  // Submit's availability hangs off this switch, so the toolbar has to hear
  // about it — including when switching source re-arms safe mode.
  paintEditBar();
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
  const ok = await confirm({
    title: `Turn off safe mode for ${db.currentLabel()}?`,
    message:
      `Queries will run unguarded against ${db.currentLabel()}` +
      (db.isPostgres() ? ', an external PostgreSQL instance Vantage does not own' : '') +
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
  explainPanel.hidden = true;
  explainView.hide();
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
        // A SQL NULL arrives as a real JSON null (D2) and renders as a styled
        // marker — finally distinguishable from a TEXT value that happens to
        // spell "NULL", which renders as plain text like any other. The empty
        // string is the other invisible value worth marking: an unmarked empty
        // cell is indistinguishable from a rendering fault.
        ...row.map((cell) => {
          if (cell === null) return h('td', { class: 'mono cell' }, h('span', { class: 'cell-null' }, 'NULL'));
          return h(
            'td',
            { class: 'mono cell', title: cell },
            cell === '' ? h('span', { class: 'cell-empty' }, 'empty') : cell
          );
        })
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

let activeRunId = null;

async function run(sqlOverride) {
  const sql = (sqlOverride || editor.getSelection() || editor.getText()).trim();
  if (!sql) return;

  editorTouched = true;
  const runId = crypto.randomUUID();
  activeRunId = runId;

  setLoading(runBtn, true);
  cancelBtn.hidden = false;
  clearResult();

  try {
    const r = await postUrlEncoded('/database/query', {
      sql,
      source: db.current(),
      danger_mode: !safeEl.checked,
      run_id: runId,
    });
    renderResult(r);
    if (!safeEl.checked) tree.reload();
  } catch (e) {
    if (e instanceof ApiError && (e.status === 400 || e.status === 403)) {
      renderError(e.body?.error || e.message);
    } else {
      reportError(e, "Couldn't run that query");
    }
  } finally {
    activeRunId = null;
    setLoading(runBtn, false);
    cancelBtn.hidden = true;
    historyPanel.refresh();
  }
}

runBtn.addEventListener('click', () => run());

cancelBtn.addEventListener('click', async () => {
  if (!activeRunId) return;
  try {
    await post('/database/query/cancel', { run_id: activeRunId });
  } catch (e) {
    reportError(e, "Couldn't cancel the query");
  }
});

/* =======================================================================
   Ctrl+P — open-table jump (P4 palette)
   ======================================================================= */

const jump = createJump({
  onPick: (t) => tabs.openTable({ source: db.current(), schema: t.schema, name: t.name }),
});

document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== 'p') return;
  const overview = db.getOverview(db.current());
  // Nothing introspected yet (a source that failed, or the first paint): let
  // the browser keep Ctrl+P rather than swallowing it for a dialog with no
  // rows in it.
  if (!overview) return;
  e.preventDefault();
  jump.open(overview);
});

syncSafeMode();
// The catalog first: it decides which source is active, the schema tree is
// addressed to that source, and only then can persisted table tabs be
// validated against sources that still exist.
loadSources().then(() => {
  tree.reload().then(loadCompletions);
  tabs.restore((t) => db.hasSource(t.source));
});
