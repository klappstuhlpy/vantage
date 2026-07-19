// Headless tests for the ORDER BY box's parser (static/js/db/orderby.js).
//
//     node tools/orderby-tests.mjs
//
// This is user input that becomes a sort key, so the cases that matter are the
// rejections: a typo must say so rather than silently sorting by something
// else, or by nothing.

import { parseSort, formatSort } from '../static/js/db/orderby.js';

let failed = 0;

function eq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) return;
  failed++;
  console.error(`FAIL ${label}\n  expected ${b}\n  got      ${a}`);
}

const COLS = ['id', 'name', 'created_at'];

// ── formatSort ─────────────────────────────────────────────────────────

eq(formatSort(null), '', 'no sort renders empty');
eq(formatSort({ column: 'name', desc: false }), 'name ASC', 'asc spelled out');
eq(formatSort({ column: 'name', desc: true }), 'name DESC', 'desc spelled out');

// ── parseSort: the accepting cases ─────────────────────────────────────

eq(parseSort('', COLS), { ok: true, sort: null }, 'empty clears the sort');
eq(parseSort('   ', COLS), { ok: true, sort: null }, 'whitespace clears the sort');
eq(parseSort('name', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'bare column is ascending');
eq(parseSort('name DESC', COLS), { ok: true, sort: { column: 'name', desc: true } }, 'explicit desc');
eq(parseSort('name desc', COLS), { ok: true, sort: { column: 'name', desc: true } }, 'direction is case-insensitive');
eq(parseSort('  name   asc  ', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'extra whitespace is fine');

// The resolved spelling comes back, not what was typed — so the box can
// normalize `NAME` to `name` instead of displaying a name no column has.
eq(parseSort('NAME', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'column case is resolved');
eq(parseSort('created_AT desc', COLS), { ok: true, sort: { column: 'created_at', desc: true } }, 'resolves and keeps dir');

// Tolerated noise: the SQL keyword, quotes, a trailing separator.
eq(parseSort('ORDER BY name', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'ORDER BY prefix tolerated');
eq(parseSort('"name" DESC', COLS), { ok: true, sort: { column: 'name', desc: true } }, 'double quotes stripped');
eq(parseSort('`name`', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'backticks stripped');
eq(parseSort('name;', COLS), { ok: true, sort: { column: 'name', desc: false } }, 'trailing semicolon tolerated');

// An exact match wins over a case-insensitive one, so a table with both `Name`
// and `name` sorts by the one that was actually typed.
eq(parseSort('Name', ['name', 'Name']), { ok: true, sort: { column: 'Name', desc: false } }, 'exact match preferred');

// ── parseSort: the rejections ──────────────────────────────────────────

// The important one: an unknown column is refused, never dropped.
{
  const r = parseSort('nmae', COLS);
  eq(r.ok, false, 'unknown column is refused');
  eq(r.error.includes('nmae'), true, 'the error names what was refused');
}

{
  const r = parseSort('name sideways', COLS);
  eq(r.ok, false, 'unknown direction is refused');
  eq(r.error.includes('sideways'), true, 'the error names the bad direction');
}

// Multi-column sort is out of scope; honouring only the first silently would
// show a sort the operator did not ask for.
eq(parseSort('name, id', COLS).ok, false, 'multi-column is refused');

eq(parseSort('name asc extra', COLS).ok, false, 'trailing junk is refused');

// A SQL fragment is just an unknown column — there is nothing to inject into
// (the model carries a column name, never text), but it must still be refused.
eq(parseSort('name; DROP TABLE account', COLS).ok, false, 'sql-ish input is refused');
eq(parseSort('1', COLS).ok, false, 'ordinal positions are not supported');

if (failed) {
  console.error(`\n${failed} failing`);
  process.exit(1);
} else {
  console.log('orderby core: all tests pass');
}
