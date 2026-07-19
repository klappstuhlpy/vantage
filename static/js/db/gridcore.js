/* The grid's pure core — window math and the selection model (plan D7).
 *
 * No DOM in this file, deliberately: these functions are the part of the grid
 * where an off-by-one shows up as a missing row or a wrong copy, so they are
 * exercised headlessly by `tools/grid-tests.mjs` (plain `node`, no framework).
 * The DOM half lives in grid.js and is exercised manually.
 */

/** Overscan rows above and below the viewport. */
export const OVERSCAN = 15;

/** Which slice of `total` rows to render for this scroll position. */
export function windowSlice(scrollTop, viewportH, rowH, total) {
  const first = Math.floor(scrollTop / rowH);
  const visible = Math.ceil(viewportH / rowH) + 1;
  const end = Math.min(total, first + visible + OVERSCAN);
  // Clamped to `end`, not just to 0 — a stale scroll position over emptied
  // data must yield an empty slice, not an inverted one.
  const start = Math.min(Math.max(0, first - OVERSCAN), end);
  return { start, end };
}

/** Normalizes an anchor/focus pair into a rectangle {r0, c0, r1, c1}. */
export function selectionRect(sel) {
  if (!sel) return null;
  return {
    r0: Math.min(sel.anchor.r, sel.focus.r),
    r1: Math.max(sel.anchor.r, sel.focus.r),
    c0: Math.min(sel.anchor.c, sel.focus.c),
    c1: Math.max(sel.anchor.c, sel.focus.c),
  };
}

/** Moves the focus cell by (dr, dc), clamped to the data; extends when shift.
 *  The first keypress with no selection lands on the origin — it *creates* a
 *  selection rather than moving one that never existed. */
export function moveFocus(sel, dr, dc, rows, cols, extend) {
  if (!sel) {
    const origin = { r: 0, c: 0 };
    return { anchor: origin, focus: origin };
  }
  const to = {
    r: Math.max(0, Math.min(rows - 1, sel.focus.r + dr)),
    c: Math.max(0, Math.min(cols - 1, sel.focus.c + dc)),
  };
  if (!extend) return { anchor: to, focus: to };
  return { anchor: sel.anchor, focus: to };
}

/** The selected cells as TSV, bounded by what is actually loaded. */
export function selectionTSV(sel, rows) {
  const rect = selectionRect(sel);
  if (!rect) return '';
  const lines = [];
  for (let r = rect.r0; r <= Math.min(rect.r1, rows.length - 1); r++) {
    const cells = [];
    for (let c = rect.c0; c <= rect.c1; c++) {
      const v = rows[r]?.[c];
      // TSV cannot say NULL; the empty field is the least-wrong rendering.
      cells.push(v == null ? '' : String(v).replaceAll('\t', ' ').replaceAll('\n', ' '));
    }
    lines.push(cells.join('\t'));
  }
  return lines.join('\n');
}

/** Column widths in characters, measured from the header and a row sample. */
export function measureWidths(columns, rows, { min = 4, max = 60, sample = 200 } = {}) {
  return columns.map((name, c) => {
    let w = name.length + 2; // room for the sort glyph
    const n = Math.min(rows.length, sample);
    for (let r = 0; r < n; r++) {
      const v = rows[r]?.[c];
      const len = v == null ? 4 : String(v).length;
      if (len > w) w = len;
    }
    return Math.max(min, Math.min(max, w + 1));
  });
}
