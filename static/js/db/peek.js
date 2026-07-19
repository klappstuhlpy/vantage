/* Cell inspector — DB Studio Phase 2.
 *
 * A grid cell is one ellipsized line; the peek shows the whole value: a
 * scrollable mono block, pretty-printed when it parses as JSON, with the byte
 * length and a Copy button. NULL renders as the same dim marker the grid uses
 * — a real NULL, not the string "NULL" (D2).
 */

import { h, icon } from '../core/ui.js';

let overlay = null;

/** @param {{col: string, value: string|null}} cell */
export function openPeek({ col, value }) {
  closePeek();

  let body;
  let meta = '';
  if (value === null) {
    body = h('span', { class: 'cell-null' }, 'NULL');
  } else {
    let text = value;
    let pretty = false;
    if (value.length > 1 && '[{"'.includes(value[0])) {
      try {
        text = JSON.stringify(JSON.parse(value), null, 2);
        pretty = true;
      } catch {
        /* not JSON — show it as it is */
      }
    }
    body = h('pre', { class: 'db-peek-value mono' }, text);
    const bytes = new TextEncoder().encode(value).length;
    meta = `${bytes.toLocaleString()} bytes${pretty ? ' · JSON' : ''}`;
  }

  const card = h(
    'div',
    { class: 'db-peek card', role: 'dialog', 'aria-label': `Value of ${col}` },
    h(
      'div',
      { class: 'db-peek-head' },
      h('span', { class: 'mono db-peek-col' }, col),
      h('span', { class: 'dim db-peek-meta' }, meta),
      h('div', { class: 'spacer' }),
      value !== null
        ? h(
            'button',
            {
              class: 'db-peek-btn',
              type: 'button',
              title: 'Copy the raw value',
              onclick: () => navigator.clipboard?.writeText(value).catch(() => {}),
            },
            icon('copy')
          )
        : null,
      h('button', { class: 'db-peek-btn', type: 'button', 'aria-label': 'Close', onclick: closePeek }, icon('x'))
    ),
    h('div', { class: 'db-peek-body' }, body)
  );

  overlay = h('div', { class: 'db-peek-overlay', onmousedown: (e) => e.target === overlay && closePeek() }, card);
  document.body.append(overlay);
  document.addEventListener('keydown', onKey);
}

export function closePeek() {
  overlay?.remove();
  overlay = null;
  document.removeEventListener('keydown', onKey);
}

function onKey(e) {
  if (e.key === 'Escape') closePeek();
}
