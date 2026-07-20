/* Virtualized data grid — DB Studio Phase 2 (plan D7).
 *
 * Hand-rolled fixed-height windowing: rows are uniform (single line, mono,
 * ellipsis — data grids don't wrap), which makes virtualization arithmetic:
 * `firstVisible = floor(scrollTop / rowHeight)`, render visible ± overscan
 * into an absolutely positioned layer inside a spacer sized `total × rowH`.
 * The DOM never holds more than ~60 rows, so 100k rows scroll at full rate.
 *
 * Semantics: `role="grid"` / `row` / `gridcell` with `aria-rowcount` /
 * `aria-rowindex`, because a real `<table>` fights absolute positioning.
 *
 * The window math and the selection model live DOM-free in gridcore.js
 * (exercised by `tools/grid-tests.mjs`); everything DOM stays in `createGrid`.
 */

import { h, render } from '../core/ui.js';
import { OVERSCAN, windowSlice, selectionRect, moveFocus, selectionTSV, measureWidths } from './gridcore.js';

/* =======================================================================
   The component
   ======================================================================= */

/**
 * @param {HTMLElement} root
 * @param {object} opts
 * @param {number}   [opts.rowHeight=26]
 * @param {(col: string) => void} [opts.onSort]  header click
 * @param {() => void} [opts.onNeedMore]         scroll nears the end of loaded rows
 * @param {(info: {row: number, col: string, value: string|null}) => void} [opts.onPeek]
 * @param {() => boolean} [opts.canEdit]         may cells be edited in place (P5)
 * @param {(info: {r: number, c: number, column: string, value: string|null}) => void} [opts.onEditCommit]
 * @param {(r: number, c: number, column: string) => string} [opts.cellClass]  extra classes (staging tints)
 * @param {(r: number) => string} [opts.rowClass]
 * @param {() => void} [opts.onSelectionChange]
 */
export function createGrid(root, opts = {}) {
  const rowH = opts.rowHeight || 26;

  let columns = []; // names
  let widths = []; // px per column
  let rows = []; // string|null cells
  let hasMore = false;
  let sort = null; // {column, desc}
  let sel = null; // {anchor:{r,c}, focus:{r,c}}
  let chPx = 7.2; // px per mono character; refined by the probe below
  let chMeasured = false;
  let editing = null; // {r, c, input, wasNull} while a cell editor is open (P5)

  const head = h('div', { class: 'dbgrid-head', role: 'row' });
  const windowEl = h('div', { class: 'dbgrid-window' });
  const spacer = h('div', { class: 'dbgrid-spacer' }, windowEl);
  // The header lives *inside* the scroll container, not beside it. Outside, a
  // table wider than the pane scrolled its rows horizontally while the header
  // stayed put, so every column sat under the wrong name — the failure mode
  // that makes a grid actively lie to you. Inside, `position: sticky; top: 0`
  // still pins it vertically while horizontal scrolling carries it along with
  // the cells it labels, and one scrollbar governs both.
  const viewport = h('div', { class: 'dbgrid-viewport' }, head, spacer);
  root.classList.add('dbgrid');
  root.setAttribute('role', 'grid');
  root.tabIndex = 0;
  render(root, viewport);

  viewport.addEventListener('scroll', () => {
    // Scrolling repaints the window, which would tear the open editor's input
    // out of the DOM mid-edit and lose whatever was typed into it. Committing
    // first is the same rule as clicking away, and keeps the buffer the only
    // place an in-progress edit can live.
    if (editing) closeEdit(true);
    paint();
  });
  window.addEventListener('resize', () => paint(true));

  /* ── Layout ────────────────────────────────────────────────────────── */

  /** Mono font makes column width arithmetic, not layout — one probe
   *  measurement, retried until the grid is actually visible (a probe inside
   *  a hidden panel measures zero and teaches nothing). */
  function ensureProbe() {
    if (chMeasured) return;
    const probe = h('span', { class: 'mono dbgrid-probe', 'aria-hidden': 'true' }, '0'.repeat(10));
    root.append(probe);
    if (probe.offsetWidth) {
      chPx = probe.offsetWidth / 10;
      chMeasured = true;
    }
    probe.remove();
  }

  /** Gutter width, sized to the widest row number it will ever show, so it
   *  does not jump a few pixels wider when the grid pages past 9 999. */
  function gutterWidth() {
    return Math.max(34, String(Math.max(rows.length, 1)).length * chPx + 18);
  }

  function layout() {
    ensureProbe();
    const chars = measureWidths(columns, rows);
    widths = chars.map((c) => Math.round(c * chPx) + 16); // + cell padding
    spacer.style.height = `${rows.length * rowH}px`;
    root.setAttribute('aria-rowcount', String(rows.length));
    // +1 for the gutter: it is a real column to assistive tech (it is the
    // row-selection control), so the count has to include it or the last
    // column reads as out of range.
    root.setAttribute('aria-colcount', String(columns.length + 1));
    paintHead();
  }

  function totalWidth() {
    return widths.reduce((a, b) => a + b, gutterWidth());
  }

  /** Is every row fully selected? Drives the corner's checked look. */
  function allSelected() {
    const rect = selectionRect(sel);
    return Boolean(
      rect && rows.length && rect.r0 === 0 && rect.r1 === rows.length - 1 && rect.c0 === 0 && rect.c1 === columns.length - 1
    );
  }

  /** Select whole rows r0..r1 — every column, like clicking a DataGrip gutter. */
  function selectRows(r0, r1) {
    if (!columns.length) return;
    sel = { anchor: { r: r0, c: 0 }, focus: { r: r1, c: columns.length - 1 } };
  }

  function paintHead() {
    render(
      head,
      // The corner: select-all, and the origin the row numbers line up under.
      h(
        'div',
        {
          class: `dbgrid-corner${allSelected() ? ' sel' : ''}`,
          role: 'columnheader',
          style: { width: `${gutterWidth()}px` },
          title: 'Select all rows',
          onclick: () => {
            if (!rows.length) return;
            if (allSelected()) sel = null;
            else selectRows(0, rows.length - 1);
            paintHead();
            paint(true);
          },
        },
        h('span', { class: 'dbgrid-corner-mark', 'aria-hidden': 'true' })
      ),
      ...columns.map((name, c) => {
        const isSorted = sort && sort.column === name;
        const cell = h(
          'div',
          {
            class: `dbgrid-hcell${isSorted ? ' sorted' : ''}`,
            role: 'columnheader',
            style: { width: `${widths[c]}px` },
            title: name,
            'aria-sort': isSorted ? (sort.desc ? 'descending' : 'ascending') : 'none',
            onclick: (e) => {
              if (e.target.classList.contains('dbgrid-resize')) return;
              opts.onSort?.(name);
            },
            ondblclick: (e) => {
              if (!e.target.classList.contains('dbgrid-resize')) return;
              autofit(c);
            },
          },
          h('span', { class: 'dbgrid-hlabel mono' }, name),
          // Always rendered, in three states: dim ⇅ when unsorted, accented
          // ▲/▼ when this column is the sort key. A marker that appears only
          // once you have already sorted cannot tell you that sorting is
          // available — which is the one thing a column header should say.
          h(
            'span',
            { class: `dbgrid-sort${isSorted ? ' active' : ''}`, 'aria-hidden': 'true' },
            isSorted ? (sort.desc ? '▼' : '▲') : '⇅'
          ),
          resizeHandle(c)
        );
        return cell;
      })
    );
    // All three carry the full content width. The spacer needs it explicitly:
    // its only child is absolutely positioned and so contributes no width, and
    // a spacer narrower than the rows would let the viewport think there is
    // nothing to scroll to once you scrolled past the header.
    const w = `${totalWidth()}px`;
    head.style.width = w;
    windowEl.style.width = w;
    spacer.style.width = w;
  }

  function resizeHandle(c) {
    return h('span', {
      class: 'dbgrid-resize',
      onmousedown: (e) => {
        e.preventDefault();
        const startX = e.clientX;
        const startW = widths[c];
        const move = (ev) => {
          widths[c] = Math.max(40, startW + (ev.clientX - startX));
          paintHead();
          paint(true);
        };
        const up = () => {
          window.removeEventListener('mousemove', move);
          window.removeEventListener('mouseup', up);
        };
        window.addEventListener('mousemove', move);
        window.addEventListener('mouseup', up);
      },
    });
  }

  function autofit(c) {
    const chars = measureWidths(columns, rows);
    widths[c] = Math.round(chars[c] * chPx) + 16;
    paintHead();
    paint(true);
  }

  /* ── Rows ──────────────────────────────────────────────────────────── */

  let painted = { start: -1, end: -1 };

  /* Height of the strip that actually shows rows. The sticky header is in the
   * scroll flow *and* painted over the top of the viewport, so it costs the
   * row area its own height — count it once, here, rather than in each of the
   * three places that reason about how many rows fit. `scrollTop` itself needs
   * no correction: the header's height shifts the rows down the content by
   * exactly the amount it covers at the top, and the two cancel. */
  function viewH() {
    return Math.max(0, viewport.clientHeight - head.offsetHeight);
  }

  function paint(force = false) {
    const { start, end } = windowSlice(viewport.scrollTop, viewH(), rowH, rows.length);
    if (!force && start === painted.start && end === painted.end) {
      paintSelection();
      return;
    }
    painted = { start, end };

    windowEl.style.transform = `translateY(${start * rowH}px)`;
    const rect = selectionRect(sel);
    const out = [];
    for (let r = start; r < end; r++) {
      out.push(rowEl(r, rect));
    }
    render(windowEl, ...out);

    if (hasMore && end > rows.length - OVERSCAN * 2) {
      opts.onNeedMore?.();
    }
  }

  function rowEl(r, rect) {
    const cells = columns.map((name, c) => {
      const v = rows[r][c];
      const selected = rect && r >= rect.r0 && r <= rect.r1 && c >= rect.c0 && c <= rect.c1;
      const isFocus = sel && sel.focus.r === r && sel.focus.c === c;
      const extra = opts.cellClass?.(r, c, columns[c]) || '';
      return h(
        'div',
        {
          class: `dbgrid-cell mono${selected ? ' sel' : ''}${isFocus ? ' focus' : ''}${v === null ? ' null' : ''}${v === '' ? ' empty' : ''}${extra ? ` ${extra}` : ''}`,
          role: 'gridcell',
          style: { width: `${widths[c]}px` },
          dataset: { r: String(r), c: String(c) },
          onmousedown: (e) => {
            if (editing && editing.r === r && editing.c === c) return; // clicking inside the open editor
            root.focus();
            e.preventDefault();
            sel = e.shiftKey && sel ? { anchor: sel.anchor, focus: { r, c } } : { anchor: { r, c }, focus: { r, c } };
            paintSelection();
            opts.onSelectionChange?.();
          },
          // On an editable table the double-click opens the editor and peek
          // moves to Alt+Enter; on a read-only one it still peeks. Peek stays
          // reachable either way — it is how you read a value too long for its
          // cell, which editing does not replace.
          ondblclick: () => (opts.canEdit?.() ? beginEdit(r, c) : peek(r, c)),
        },
        v === null ? 'NULL' : v === '' ? 'empty' : v
      );
    });
    // The gutter is the row handle: click selects the whole row, shift-click
    // extends the range. It is sticky-left in CSS, so it stays readable when a
    // wide table is scrolled sideways — losing track of which row you are on
    // is the thing that makes a wide grid unusable.
    const rowSelected = Boolean(rect && r >= rect.r0 && r <= rect.r1 && rect.c0 === 0 && rect.c1 === columns.length - 1);
    const gutter = h(
      'div',
      {
        class: `dbgrid-gutter mono${rowSelected ? ' sel' : ''}`,
        role: 'rowheader',
        style: { width: `${gutterWidth()}px` },
        title: 'Click to select the row, click again to deselect, shift-click to extend',
        onmousedown: (e) => {
          root.focus();
          e.preventDefault();
          if (e.shiftKey && sel) selectRows(sel.anchor.r, r);
          // Clicking the gutter of the only selected row clears it, the same way
          // the corner un-selects all. Without this a whole-row selection could
          // be moved but never dropped, so `−` stayed armed on a row you had
          // stopped meaning to touch.
          else if (rowSelected && rect.r0 === r && rect.r1 === r) sel = null;
          else selectRows(r, r);
          paint(true);
          opts.onSelectionChange?.();
        },
      },
      String(r + 1)
    );

    const state = opts.rowClass?.(r) || '';
    return h(
      'div',
      {
        class: `dbgrid-row${state ? ` ${state}` : ''}`,
        role: 'row',
        'aria-rowindex': String(r + 1),
        style: { height: `${rowH}px` },
      },
      gutter,
      ...cells
    );
  }

  /** Repaints only selection classes on the currently rendered rows. */
  function paintSelection() {
    const rect = selectionRect(sel);
    for (const cell of windowEl.querySelectorAll('.dbgrid-cell')) {
      const r = Number(cell.dataset.r);
      const c = Number(cell.dataset.c);
      const selected = rect && r >= rect.r0 && r <= rect.r1 && c >= rect.c0 && c <= rect.c1;
      cell.classList.toggle('sel', Boolean(selected));
      cell.classList.toggle('focus', Boolean(sel && sel.focus.r === r && sel.focus.c === c));
    }
    // The gutter and corner track the same selection; repainting cells alone
    // left a row highlighted with an unhighlighted number beside it.
    const full = rect && rect.c0 === 0 && rect.c1 === columns.length - 1;
    for (const g of windowEl.querySelectorAll('.dbgrid-gutter')) {
      const r = Number(g.parentElement?.getAttribute('aria-rowindex')) - 1;
      g.classList.toggle('sel', Boolean(full && r >= rect.r0 && r <= rect.r1));
    }
    head.querySelector('.dbgrid-corner')?.classList.toggle('sel', allSelected());
  }

  function peek(r, c) {
    opts.onPeek?.({ row: r, col: columns[c], value: rows[r][c] });
  }

  /* ── In-place editing (P5) ─────────────────────────────────────────────
   *
   * The editor is a plain `<input>` swapped into the cell for the duration.
   * Nothing it produces touches a database: the committed value goes to
   * `onEditCommit`, which stages it in the buffer, and Submit is what sends
   * the buffer anywhere. */

  function cellNode(r, c) {
    return windowEl.querySelector(`.dbgrid-cell[data-r="${r}"][data-c="${c}"]`);
  }

  /** Opens the editor on a cell. `seed` (a typed character) replaces the
   *  current value, the way typing over a selected cell works in a spreadsheet. */
  function beginEdit(r, c, seed = null) {
    if (!opts.canEdit?.() || !opts.onEditCommit) return;
    closeEdit(false);
    const node = cellNode(r, c);
    if (!node) return;

    const v = rows[r][c];
    const input = h('input', {
      class: 'dbgrid-edit mono',
      type: 'text',
      value: seed ?? (v === null ? '' : v),
      spellcheck: 'false',
      autocomplete: 'off',
      'aria-label': `Edit ${columns[c]}`,
      onkeydown: (e) => {
        // The editor owns its keys entirely: without this the grid's own
        // handler would also see them and move the selection out from under
        // the caret while you type.
        e.stopPropagation();
        if (e.key === 'Enter') {
          e.preventDefault();
          closeEdit(true);
          root.focus();
        } else if (e.key === 'Escape') {
          e.preventDefault();
          closeEdit(false);
          root.focus();
        }
      },
      // Clicking away commits, the way leaving a spreadsheet cell does. The
      // alternative — silently discarding on blur — loses typing that looked
      // accepted, which is the worse of the two surprises.
      onblur: () => closeEdit(true),
    });
    editing = { r, c, input, wasNull: v === null };
    render(node, input);
    input.focus();
    if (seed === null) input.select();
  }

  function closeEdit(commit) {
    if (!editing) return;
    const { r, c, input, wasNull } = editing;
    editing = null; // before the callback: committing repaints, which re-enters
    if (commit) {
      // A cell that was NULL and is still empty stays NULL rather than
      // silently becoming the empty string — they are different values, and
      // the operator did not say which one they meant. Setting NULL
      // deliberately is what the Delete key is for.
      const value = wasNull && input.value === '' ? null : input.value;
      opts.onEditCommit({ r, c, column: columns[c], value });
    } else {
      paint(true);
    }
  }

  function scrollFocusIntoView() {
    if (!sel) return;
    const top = sel.focus.r * rowH;
    if (top < viewport.scrollTop) viewport.scrollTop = top;
    else if (top + rowH > viewport.scrollTop + viewH()) {
      viewport.scrollTop = top + rowH - viewH();
    }
  }

  /* ── Keyboard ──────────────────────────────────────────────────────── */

  root.addEventListener('keydown', (e) => {
    if (!rows.length) return;
    const page = Math.max(1, Math.floor(viewH() / rowH) - 1);
    const nav = {
      ArrowUp: [-1, 0],
      ArrowDown: [1, 0],
      ArrowLeft: [0, -1],
      ArrowRight: [0, 1],
      PageUp: [-page, 0],
      PageDown: [page, 0],
    }[e.key];

    if (nav) {
      e.preventDefault();
      sel = moveFocus(sel, nav[0], nav[1], rows.length, columns.length, e.shiftKey);
      scrollFocusIntoView();
      paint(true);
      opts.onSelectionChange?.();
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      const last = e.key === 'End';
      if (e.ctrlKey) {
        sel = moveFocus(sel, last ? rows.length : -rows.length, 0, rows.length, columns.length, e.shiftKey);
      } else {
        sel = moveFocus(sel, 0, last ? columns.length : -columns.length, rows.length, columns.length, e.shiftKey);
      }
      scrollFocusIntoView();
      paint(true);
    } else if (e.key === 'Enter' && sel) {
      e.preventDefault();
      // Alt+Enter always peeks; plain Enter edits where editing is possible and
      // peeks where it is not.
      if (!e.altKey && opts.canEdit?.()) beginEdit(sel.focus.r, sel.focus.c);
      else peek(sel.focus.r, sel.focus.c);
    } else if ((e.key === 'Delete' || e.key === 'Backspace') && sel && opts.canEdit?.()) {
      // Stages SQL NULL. This is the only gesture that can say "NULL" rather
      // than "empty string", which is why it has a key of its own.
      e.preventDefault();
      opts.onEditCommit?.({ r: sel.focus.r, c: sel.focus.c, column: columns[sel.focus.c], value: null });
    } else if ((e.ctrlKey || e.metaKey) && e.key === 'c' && sel) {
      e.preventDefault();
      const tsv = selectionTSV(sel, rows);
      navigator.clipboard?.writeText(tsv).catch(() => {});
    } else if (sel && opts.canEdit?.() && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      // Typing over a selected cell starts editing with what you typed, the way
      // a spreadsheet does — the fastest path through a column of corrections.
      e.preventDefault();
      beginEdit(sel.focus.r, sel.focus.c, e.key);
    }
  });

  /* ── API ───────────────────────────────────────────────────────────── */

  return {
    /** Full reset: new columns + first page of rows. */
    setData({ columns: cols, rows: data, hasMore: more }) {
      columns = cols;
      rows = data;
      hasMore = Boolean(more);
      sel = null;
      editing = null; // a pending editor belongs to the table that just left
      painted = { start: -1, end: -1 };
      viewport.scrollTop = 0;
      layout();
      paint(true);
    },

    /** The next page arrived. */
    appendRows(data, { hasMore: more }) {
      rows = rows.concat(data);
      hasMore = Boolean(more);
      spacer.style.height = `${rows.length * rowH}px`;
      root.setAttribute('aria-rowcount', String(rows.length));
      painted = { start: -1, end: -1 };
      paint(true);
    },

    /** Swaps the row data in place, keeping scroll and selection (P5).
     *
     * `setData` is a new table; this is the same table with the staging buffer
     * painted over it. Resetting the scroll here would throw the operator back
     * to row 1 after every single cell edit. */
    replaceRows(data, { hasMore: more } = {}) {
      rows = data;
      if (more !== undefined) hasMore = Boolean(more);
      spacer.style.height = `${rows.length * rowH}px`;
      root.setAttribute('aria-rowcount', String(rows.length));
      // Clamp a selection that pointed past the end (an added row was dropped).
      if (sel && rows.length) {
        const clamp = (p) => ({ r: Math.min(p.r, rows.length - 1), c: p.c });
        sel = { anchor: clamp(sel.anchor), focus: clamp(sel.focus) };
      } else if (!rows.length) {
        sel = null;
      }
      painted = { start: -1, end: -1 };
      paint(true);
    },

    /** The row indices the current selection touches — what `−` deletes. */
    selectedRows() {
      const rect = selectionRect(sel);
      if (!rect) return [];
      const out = [];
      for (let r = rect.r0; r <= Math.min(rect.r1, rows.length - 1); r++) out.push(r);
      return out;
    },

    setSort(s) {
      sort = s;
      paintHead();
    },

    /** Restores a saved scroll offset (tab switches). */
    setScrollTop(y) {
      viewport.scrollTop = y;
    },
    get scrollTop() {
      return viewport.scrollTop;
    },
    get rowCount() {
      return rows.length;
    },
  };
}
