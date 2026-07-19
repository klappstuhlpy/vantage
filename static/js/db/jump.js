/* Jump-to-table (Ctrl+P) — DB Studio Phase 4.
 *
 * The global palette (Ctrl+K) is server-ranked and cross-app; this is its
 * in-studio counterpart and deliberately *not* the same thing. Table names are
 * only knowable by introspecting a source, which is a privileged read the
 * audit log records per source — doing that on every palette keystroke would
 * turn a launcher into a stream of audited schema dumps. So the jump searches
 * the overview the tree already fetched for the active source: no network call,
 * no new audit event, and it works offline of the server entirely.
 *
 * Reuses the `.palette` component classes rather than inventing a second
 * lookalike, so it inherits the palette's glass, motion and density for free.
 */

import { h, icon, render, lockScroll, unlockScroll } from '../core/ui.js';
import { rank } from './jumpcore.js';

/** @param {{onPick: (t: {schema: string, name: string}) => void}} opts */
export function createJump({ onPick }) {
  let dialog, input, results;
  let entries = [];
  let shown = [];
  let active = 0;

  function build() {
    input = h('input', {
      class: 'palette-input',
      type: 'text',
      placeholder: 'Jump to a table or view…',
      autocomplete: 'off',
      spellcheck: 'false',
      'aria-label': 'Jump to table',
      'aria-controls': 'db-jump-results',
      role: 'combobox',
    });

    results = h('div', { class: 'palette-results', id: 'db-jump-results', role: 'listbox' });

    dialog = h(
      'dialog',
      { class: 'palette', 'aria-label': 'Jump to table' },
      h('div', { class: 'palette-input-wrap' }, icon('search', { size: 20 }), input),
      results,
      h(
        'div',
        { class: 'palette-foot' },
        h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, '↑'), h('span', { class: 'kbd' }, '↓'), ' navigate'),
        h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, '↵'), ' open'),
        h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, 'esc'), ' close')
      )
    );

    document.body.append(dialog);

    input.addEventListener('input', () => {
      shown = rank(entries, input.value.trim());
      active = 0;
      paint();
    });
    input.addEventListener('keydown', onKey);
    dialog.addEventListener('click', (e) => e.target === dialog && close());
    dialog.addEventListener('cancel', (e) => {
      e.preventDefault();
      close();
    });
    dialog.addEventListener('close', () => unlockScroll());
  }

  function onKey(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      move(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      move(-1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(shown[active]);
    }
  }

  function move(d) {
    if (!shown.length) return;
    active = (active + d + shown.length) % shown.length;
    paint();
  }

  function close() {
    if (dialog?.open) dialog.close();
  }

  function choose(entry) {
    if (!entry) return;
    close();
    onPick({ schema: entry.schema, name: entry.name });
  }

  function paint() {
    render(results);

    if (!shown.length) {
      results.append(
        h(
          'div',
          { class: 'empty', style: { padding: 'var(--sp-6) var(--sp-4)' } },
          h('span', { class: 'empty-icon' }, icon('search', { size: 20 })),
          h('span', { class: 'empty-title' }, entries.length ? 'Nothing matches' : 'No tables'),
          h(
            'span',
            { class: 'empty-sub' },
            entries.length ? 'No table or view in this source matches that.' : 'This database has no tables or views.'
          )
        )
      );
      return;
    }

    let lastGroup = null;
    shown.forEach((entry, i) => {
      const group = entry.kind === 'view' ? 'Views' : 'Tables';
      if (group !== lastGroup) {
        lastGroup = group;
        results.append(h('div', { class: 'palette-group' }, group));
      }
      results.append(
        h(
          'button',
          {
            class: 'palette-item',
            type: 'button',
            role: 'option',
            'aria-selected': String(i === active),
            onclick: () => choose(entry),
            onmousemove: () => {
              if (active === i) return;
              active = i;
              for (const [j, el] of [...results.querySelectorAll('.palette-item')].entries()) {
                el.setAttribute('aria-selected', String(j === active));
              }
            },
          },
          h('span', { class: 'palette-item-icon' }, icon(entry.kind === 'view' ? 'eye' : 'table')),
          h(
            'span',
            { class: 'palette-item-text' },
            h('span', { class: 'palette-item-title mono' }, entry.qualified),
            entry.sub ? h('span', { class: 'palette-item-sub' }, entry.sub) : null
          ),
          i === active ? h('span', { class: 'kbd' }, '↵') : null
        )
      );
    });

    results.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }

  return {
    /** @param {object} overview — a `/database/schema` response, or null. */
    open(overview) {
      if (!overview) return;
      if (!dialog) build();
      if (dialog.open) return;

      // Postgres qualifies by schema; a SQLite source has exactly one, so
      // showing "main." in front of every row would be noise.
      const all = [...(overview.tables || []), ...(overview.views || [])];
      const multiSchema = new Set(all.map((t) => t.schema)).size > 1;
      const toEntry = (kind) => (t) => ({
        kind,
        schema: t.schema,
        name: t.name,
        qualified: multiSchema ? `${t.schema}.${t.name}` : t.name,
        sub: t.row_estimate == null ? null : `≈ ${Number(t.row_estimate).toLocaleString()} rows`,
      });
      entries = [...(overview.tables || []).map(toEntry('table')), ...(overview.views || []).map(toEntry('view'))];

      input.value = '';
      shown = rank(entries, '');
      active = 0;
      paint();
      dialog.showModal();
      lockScroll();
      input.focus();
    },
  };
}
