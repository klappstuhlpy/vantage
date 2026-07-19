/* Filter chip bar — DB Studio Phase 2 (plan D5).
 *
 * Chips, not a form: each chip renders one clause in words and *is* the
 * serialized filter model — what you see is exactly what the server was sent.
 * The "+ filter" button opens a small popover (column → operator → value);
 * the structured `{column, op, value}[]` list goes to the caller, which sends
 * it as JSON. No SQL is ever assembled here.
 */

import { h, icon, render } from '../core/ui.js';

/** Operator labels, in menu order. */
const OPS = [
  ['=', '='],
  ['!=', '≠'],
  ['<', '<'],
  ['<=', '≤'],
  ['>', '>'],
  ['>=', '≥'],
  ['contains', 'contains'],
  ['starts-with', 'starts with'],
  ['ends-with', 'ends with'],
  ['is-null', 'is NULL'],
  ['not-null', 'is not NULL'],
];

const NO_VALUE = new Set(['is-null', 'not-null']);

/**
 * @param {HTMLElement} el
 * @param {object} opts
 * @param {() => string[]} opts.getColumns  column names of the active table
 * @param {(filters: Array) => void} opts.onChange
 */
export function createFilterBar(el, { getColumns, onChange }) {
  let filters = [];
  let popover = null;

  el.classList.add('db-filterbar');

  function paint() {
    render(
      el,
      ...filters.map((f, i) => chip(f, i)),
      h(
        'button',
        { class: 'db-filter-add', type: 'button', onclick: (e) => openPopover(e.currentTarget) },
        icon('plus'),
        'filter'
      )
    );
  }

  function chip(f, i) {
    const label = NO_VALUE.has(f.op)
      ? `${f.column} ${opLabel(f.op)}`
      : `${f.column} ${opLabel(f.op)} "${f.value}"`;
    return h(
      'span',
      { class: 'db-filter-chip mono', title: label },
      label,
      h(
        'button',
        {
          class: 'db-filter-x',
          type: 'button',
          'aria-label': `Remove filter: ${label}`,
          onclick: () => {
            filters.splice(i, 1);
            paint();
            onChange(get());
          },
        },
        icon('x')
      )
    );
  }

  function opLabel(op) {
    return OPS.find(([v]) => v === op)?.[1] ?? op;
  }

  function openPopover(anchor) {
    closePopover();
    const columns = getColumns();
    if (!columns.length) return;

    const colSel = h('select', { class: 'select mono' }, ...columns.map((c) => h('option', { value: c }, c)));
    const opSel = h('select', { class: 'select mono' }, ...OPS.map(([v, l]) => h('option', { value: v }, l)));
    const valInput = h('input', { class: 'input mono', type: 'text', placeholder: 'value' });

    opSel.addEventListener('change', () => {
      valInput.hidden = NO_VALUE.has(opSel.value);
    });

    const add = () => {
      const op = opSel.value;
      filters.push({
        column: colSel.value,
        op,
        value: NO_VALUE.has(op) ? undefined : valInput.value,
      });
      closePopover();
      paint();
      onChange(get());
    };

    valInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') add();
    });

    popover = h(
      'div',
      { class: 'db-filter-pop card' },
      colSel,
      opSel,
      valInput,
      h('button', { class: 'btn', type: 'button', onclick: add }, 'Add')
    );
    // Anchored to the bar, not the button: the bar is position-relative and
    // the popover opens under wherever the + chip currently sits.
    popover.style.left = `${anchor.offsetLeft}px`;
    el.append(popover);
    colSel.focus();

    setTimeout(() => {
      document.addEventListener('mousedown', onOutside);
      document.addEventListener('keydown', onEsc);
    });
  }

  function onOutside(e) {
    if (popover && !popover.contains(e.target)) closePopover();
  }

  function onEsc(e) {
    if (e.key === 'Escape') closePopover();
  }

  function closePopover() {
    popover?.remove();
    popover = null;
    document.removeEventListener('mousedown', onOutside);
    document.removeEventListener('keydown', onEsc);
  }

  /** The structured filter list, exactly as it should be sent (D5). */
  function get() {
    return filters.map((f) => ({ column: f.column, op: f.op, value: f.value }));
  }

  paint();

  return {
    get,
    set(list) {
      filters = (list || []).map((f) => ({ ...f }));
      closePopover();
      paint();
    },
  };
}
