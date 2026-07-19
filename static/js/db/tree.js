/* Schema tree (left rail) — DB Studio Phase 1.
 *
 * Replaces the flat tables card: a filterable tree of Tables and Views for the
 * active source, where expanding a table inlines its columns with type and
 * PK/FK glyphs — the answer to "what was that column called" without leaving
 * the editor. Clicking a name still opens the table the way the old list did
 * (the page decides what "open" means; in P1 it pre-fills and runs a SELECT).
 *
 * Data comes from the two P1 endpoints: `/database/schema` (one call per
 * source) and `/database/table` (fetched lazily on first expand, cached per
 * source+table for the life of the page).
 */

import { get } from '../core/api.js';
import { h, icon, render, emptyState, reportError } from '../core/ui.js';
import { num } from '../core/format.js';
import * as db from './state.js';

/**
 * @param {object} opts
 * @param {HTMLElement} opts.tree    container the tree renders into
 * @param {HTMLInputElement} opts.filter  the filter text input
 * @param {HTMLElement} opts.count   badge showing how many relations exist
 * @param {(t: {schema: string, name: string}, kind: string) => void} opts.onOpen
 */
export function initTree({ tree, filter, count, onOpen }) {
  /** The `/database/schema` response for the active source, or null. */
  let overview = null;
  let filterText = '';

  /** Expanded keys (`source|schema|name`) — survives filter repaints. */
  const expanded = new Set();

  /** Table detail promises, keyed like `expanded` — fetch once per page life. */
  const details = new Map();

  const keyOf = (t) => `${db.current()}|${t.schema}|${t.name}`;

  filter.addEventListener('input', () => {
    filterText = filter.value.trim().toLowerCase();
    paint();
  });

  async function reload() {
    overview = null;
    count.textContent = '…';
    render(tree, skeleton());
    try {
      overview = await get(`/database/schema?source=${encodeURIComponent(db.current())}`);
      db.setOverview(db.current(), overview);
      paint();
    } catch (e) {
      count.textContent = '0';
      render(tree, emptyState({ icon: 'database', title: 'Unavailable', sub: 'The schema could not be read.', degraded: true }));
      reportError(e, "Couldn't read the schema");
    }
  }

  function paint() {
    if (!overview) return;
    const total = overview.tables.length + overview.views.length;
    count.textContent = num(total);

    if (!total) {
      render(tree, emptyState({ icon: 'database', title: 'No tables', sub: 'This database is empty.' }));
      return;
    }

    const matches = (t) => !filterText || t.name.toLowerCase().includes(filterText);
    const tables = overview.tables.filter(matches);
    const views = overview.views.filter(matches);

    if (!tables.length && !views.length) {
      render(tree, emptyState({ icon: 'search', title: 'No matches', sub: 'Clear the filter to see every table.' }));
      return;
    }

    render(
      tree,
      tables.length ? section('Tables', overview.tables.length, tables, 'table') : null,
      views.length ? section('Views', overview.views.length, views, 'view') : null
    );
  }

  function section(label, total, items, kind) {
    return h(
      'div',
      { class: 'db-tree-section' },
      h('div', { class: 'db-tree-head' }, h('span', {}, label), h('span', { class: 'dim' }, num(total))),
      ...items.map((t) => item(t, kind))
    );
  }

  function item(t, kind) {
    const key = keyOf(t);
    const isPg = db.isPostgres();
    const label = isPg && t.schema !== 'public' ? `${t.schema}.${t.name}` : t.name;

    const colsEl = h('div', { class: 'db-tree-cols' });
    const toggleBtn = h(
      'button',
      {
        class: 'db-tree-toggle',
        type: 'button',
        'aria-expanded': String(expanded.has(key)),
        'aria-label': `Columns of ${label}`,
        onclick: () => {
          const open = !expanded.has(key);
          if (open) {
            expanded.add(key);
            loadColumns(t, colsEl);
          } else {
            expanded.delete(key);
            render(colsEl);
          }
          toggleBtn.setAttribute('aria-expanded', String(open));
        },
      },
      icon('chevron-right')
    );

    const nameBtn = h(
      'button',
      {
        class: 'table-link',
        type: 'button',
        // Postgres puts the same table name in several schemas, so the title
        // says which one — but only where that is a real distinction.
        title: isPg ? `${t.schema}.${t.name}` : t.name,
        onclick: () => onOpen(t, kind),
      },
      label
    );

    const badge =
      kind === 'table'
        ? h(
            'span',
            {
              class: 'num mono dim',
              // On Postgres the count is the planner's estimate (n_live_tup),
              // on SQLite an exact COUNT(*). The title says which.
              title: isPg ? 'Estimated from the table statistics, not counted' : 'Counted exactly',
            },
            num(t.row_estimate)
          )
        : h('span', { class: 'dim db-tree-kind' }, 'view');

    const row = h('div', { class: 'db-tree-row' }, toggleBtn, nameBtn, badge);
    const wrap = h('div', { class: 'db-tree-item' }, row, colsEl);
    if (expanded.has(key)) loadColumns(t, colsEl);
    return wrap;
  }

  function detail(t) {
    const key = keyOf(t);
    if (!details.has(key)) {
      const params = new URLSearchParams({ source: db.current(), table: t.name });
      if (db.isPostgres()) params.set('schema', t.schema);
      // Cache the promise, not the result: two rapid expands share one fetch.
      // A failure is evicted so a retry can actually retry.
      const p = get(`/database/table?${params}`).catch((e) => {
        details.delete(key);
        throw e;
      });
      details.set(key, p);
    }
    return details.get(key);
  }

  async function loadColumns(t, el) {
    render(el, h('div', { class: 'db-tree-col dim' }, 'Loading…'));
    try {
      const d = await detail(t);
      render(el, ...d.columns.map((col) => columnRow(col, d)));
    } catch {
      // The toast is skipped on purpose: a broken expand is local to this row,
      // and the message sits exactly where the operator is looking.
      render(el, h('div', { class: 'db-tree-col dim' }, "Couldn't read the columns."));
    }
  }

  function columnRow(col, d) {
    const fk = d.foreign_keys.find((f) => f.columns.includes(col.name));
    return h(
      'div',
      { class: 'db-tree-col' },
      col.pk_ordinal
        ? h('span', { class: 'db-tree-pk', title: `Primary key, position ${col.pk_ordinal}` }, icon('key-round'))
        : h('span', { class: 'db-tree-glyph-pad' }),
      h('span', { class: 'mono db-tree-colname', title: col.name }, col.name),
      fk
        ? h(
            'span',
            {
              class: 'mono db-tree-fk',
              title: `References ${fk.ref_schema}.${fk.ref_table}${fk.ref_columns.length ? ` (${fk.ref_columns.join(', ')})` : ''}`,
            },
            `→${fk.ref_table}`
          )
        : null,
      h('span', { class: 'mono dim db-tree-type' }, col.data_type ? col.data_type.toLowerCase() : '')
    );
  }

  const skeleton = () =>
    h(
      'div',
      { class: 'db-tree-skel' },
      ...Array.from({ length: 5 }, () =>
        h('div', { class: 'skel skel-line', style: { width: `${45 + Math.random() * 45}%` } })
      )
    );

  return { reload };
}
