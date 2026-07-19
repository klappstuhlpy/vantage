// Headless tests for the data grid's pure core (static/js/db/gridcore.js).
//
// No framework, no build step — run with:
//
//     node tools/grid-tests.mjs
//
// These cover the arithmetic where an off-by-one becomes a missing row or a
// wrong copy: window slicing, selection rectangles, focus movement clamping,
// TSV extraction, and width measurement.

import {
  OVERSCAN,
  windowSlice,
  selectionRect,
  moveFocus,
  selectionTSV,
  measureWidths,
} from '../static/js/db/gridcore.js';

let failed = 0;

function eq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) return;
  failed++;
  console.error(`FAIL ${label}\n  expected ${b}\n  got      ${a}`);
}

// ── windowSlice ────────────────────────────────────────────────────────

// At the top, the slice starts at 0 (no negative overscan) and covers the
// viewport plus overscan below.
eq(windowSlice(0, 260, 26, 1000), { start: 0, end: 11 + OVERSCAN }, 'slice at top');

// Mid-scroll, overscan applies both ways around the visible rows.
{
  const { start, end } = windowSlice(26 * 100, 260, 26, 1000);
  eq(start, 100 - OVERSCAN, 'mid slice start');
  eq(end, 100 + 11 + OVERSCAN, 'mid slice end');
}

// At the bottom, the slice never runs past the data.
{
  const { end } = windowSlice(26 * 995, 260, 26, 1000);
  eq(end, 1000, 'slice clamps to total');
}

// An empty grid renders nothing, whatever the scroll position claims.
eq(windowSlice(500, 260, 26, 0), { start: 0, end: 0 }, 'empty grid slice');

// ── selectionRect ──────────────────────────────────────────────────────

eq(selectionRect(null), null, 'no selection, no rect');
eq(
  selectionRect({ anchor: { r: 5, c: 3 }, focus: { r: 2, c: 7 } }),
  { r0: 2, r1: 5, c0: 3, c1: 7 },
  'rect normalizes an up-left drag'
);

// ── moveFocus ──────────────────────────────────────────────────────────

// First keypress with no selection lands on the origin.
eq(moveFocus(null, 1, 0, 10, 3, false), { anchor: { r: 0, c: 0 }, focus: { r: 0, c: 0 } }, 'first move selects origin');

// Movement clamps at every edge.
{
  const sel = { anchor: { r: 0, c: 0 }, focus: { r: 0, c: 0 } };
  eq(moveFocus(sel, -5, 0, 10, 3, false).focus, { r: 0, c: 0 }, 'clamps at top');
  eq(moveFocus(sel, 99, 0, 10, 3, false).focus, { r: 9, c: 0 }, 'clamps at bottom');
  eq(moveFocus(sel, 0, 99, 10, 3, false).focus, { r: 0, c: 2 }, 'clamps at right');
}

// Shift extends: the anchor stays put while the focus walks.
{
  const sel = { anchor: { r: 2, c: 1 }, focus: { r: 2, c: 1 } };
  const out = moveFocus(sel, 2, 1, 10, 3, true);
  eq(out.anchor, { r: 2, c: 1 }, 'extend keeps anchor');
  eq(out.focus, { r: 4, c: 2 }, 'extend moves focus');
}

// ── selectionTSV ───────────────────────────────────────────────────────

const data = [
  ['1', 'one', null],
  ['2', 'two\ttabbed', ''],
  ['3', 'three', 'x'],
];

eq(selectionTSV(null, data), '', 'no selection copies nothing');
eq(
  selectionTSV({ anchor: { r: 0, c: 1 }, focus: { r: 1, c: 2 } }, data),
  'one\t\ntwo tabbed\t',
  'rect copy: NULL as empty, tabs flattened'
);

// A selection reaching past the loaded rows copies only what is loaded.
eq(selectionTSV({ anchor: { r: 2, c: 0 }, focus: { r: 99, c: 0 } }, data), '3', 'copy is bounded by loaded rows');

// ── measureWidths ──────────────────────────────────────────────────────

{
  const w = measureWidths(['id', 'body'], [['1', 'x'.repeat(500)]]);
  eq(w[1], 60, 'width caps at max');
  eq(w[0] >= 4, true, 'width has a floor');
}

if (failed) {
  console.error(`\n${failed} failing`);
  process.exit(1);
} else {
  console.log('grid core: all tests pass');
}
