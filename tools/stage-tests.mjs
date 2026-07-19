// Headless tests for the staging buffer (static/js/db/stagecore.js).
//
//     node tools/stage-tests.mjs
//
// This buffer decides which UPDATE, DELETE and INSERT statements the server is
// asked to plan, so the cases that matter are the ones where a plausible-looking
// buffer would compile to the *wrong* statement: a row both edited and deleted,
// an edit that was typed back to its original value, a NULL primary key.

import {
  emptyStage,
  addRow,
  buildChanges,
  cellStaged,
  clearStage,
  deleteRows,
  editCell,
  isDirty,
  rowStateOf,
  stagedCount,
  undeleteRows,
  viewRows,
} from '../static/js/db/stagecore.js';

let failed = 0;

function eq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) return;
  failed++;
  console.error(`FAIL ${label}\n  expected ${b}\n  got      ${a}`);
}

const COLUMNS = ['id', 'name', 'note'];
const PK = ['id'];
const base = () => [
  ['1', 'ada', null],
  ['2', 'grace', 'hi'],
  ['3', 'alan', ''],
];
const ctx = () => ({ columns: COLUMNS, base: base(), pkColumns: PK });

// ── An empty buffer is not dirty and compiles to nothing ────────────────

{
  const s = emptyStage();
  eq(isDirty(s), false, 'a fresh buffer is clean');
  eq(stagedCount(s), 0, 'a fresh buffer counts zero');
  eq(buildChanges(s, ctx()), { ok: true, changes: [] }, 'a fresh buffer compiles to nothing');
}

// ── Editing a cell ──────────────────────────────────────────────────────

{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 1, 1, 'Grace');
  eq(stagedCount(s), 1, 'one edit, one staged change');
  eq(cellStaged(s, 3, 1, 'name'), true, 'the edited cell reads as staged');
  eq(cellStaged(s, 3, 1, 'note'), false, 'its neighbour does not');
  eq(viewRows(s, COLUMNS, c.base)[1], ['2', 'Grace', 'hi'], 'the view shows the staged value');
  eq(
    buildChanges(s, c),
    { ok: true, changes: [{ kind: 'update', pk: { id: '2' }, set: { name: 'Grace' }, values: {} }] },
    'it compiles to a PK-addressed UPDATE'
  );
}

// Typing the original value back un-stages the edit. Otherwise fixing your own
// typo still ships an UPDATE, and the badge claims work that no longer exists.
{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 1, 1, 'Grace');
  editCell(s, c, 1, 1, 'grace');
  eq(stagedCount(s), 0, 'typing the original value back clears the edit');
  eq(cellStaged(s, 3, 1, 'name'), false, 'and the cell stops reading as staged');
  eq(buildChanges(s, c).changes, [], 'and nothing compiles');
}

// NULL is a value the buffer can hold, distinct from the empty string — the two
// are different rows in the database and must stay different here.
{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 2, 2, null); // '' -> null
  eq(
    buildChanges(s, c).changes,
    [{ kind: 'update', pk: { id: '3' }, set: { note: null }, values: {} }],
    'NULL and the empty string are not the same edit'
  );
  editCell(s, c, 0, 2, null); // already null -> un-stages
  eq(stagedCount(s), 1, 'staging NULL over a NULL is a no-op');
}

// ── Deleting ────────────────────────────────────────────────────────────

{
  const s = emptyStage();
  const c = ctx();
  deleteRows(s, 3, [0, 2]);
  eq(stagedCount(s), 2, 'two rows marked for deletion');
  eq(rowStateOf(s, 3, 0), 'deleted', 'the row reads as deleted');
  eq(rowStateOf(s, 3, 1), null, 'its neighbour does not');
  eq(
    buildChanges(s, c).changes,
    [
      { kind: 'delete', pk: { id: '1' }, set: {}, values: {} },
      { kind: 'delete', pk: { id: '3' }, set: {}, values: {} },
    ],
    'deletes compile in row order'
  );
  undeleteRows(s, [0]);
  eq(stagedCount(s), 1, 'un-deleting drops the change');
}

// A row that is both edited and deleted compiles to the DELETE alone. Shipping
// the UPDATE too would run a statement against a row the same batch removes.
{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 1, 1, 'Grace');
  deleteRows(s, 3, [1]);
  eq(stagedCount(s), 1, 'the edit is absorbed by the delete');
  eq(
    buildChanges(s, c).changes,
    [{ kind: 'delete', pk: { id: '2' }, set: {}, values: {} }],
    'only the DELETE compiles'
  );
  // …and un-deleting brings the edit back rather than having discarded it.
  undeleteRows(s, [1]);
  eq(buildChanges(s, c).changes, [{ kind: 'update', pk: { id: '2' }, set: { name: 'Grace' }, values: {} }], 'the edit survived');
}

// ── Adding ──────────────────────────────────────────────────────────────

{
  const s = emptyStage();
  const c = ctx();
  addRow(s);
  eq(stagedCount(s), 1, 'an added row is one change');
  eq(viewRows(s, COLUMNS, c.base).length, 4, 'it shows up at the end of the grid');
  eq(rowStateOf(s, 3, 3), 'added', 'and reads as added');

  // Only the columns actually filled in are sent: an untouched column keeps its
  // DEFAULT, which is not the same as writing NULL into it.
  eq(buildChanges(s, c).changes, [{ kind: 'insert', pk: {}, set: {}, values: {} }], 'an untouched row sends no columns');
  editCell(s, c, 3, 1, 'linus');
  eq(
    buildChanges(s, c).changes,
    [{ kind: 'insert', pk: {}, set: {}, values: { name: 'linus' } }],
    'only the filled column is sent'
  );
  eq(cellStaged(s, 3, 3, 'name'), true, 'the filled cell reads as staged');
}

// Deleting an added row removes it outright — it has never been sent anywhere,
// so there is nothing to issue a DELETE against.
{
  const s = emptyStage();
  const c = ctx();
  addRow(s);
  addRow(s);
  editCell(s, c, 4, 1, 'second');
  deleteRows(s, 3, [3]);
  eq(stagedCount(s), 1, 'the added row is gone, not marked');
  eq(buildChanges(s, c).changes, [{ kind: 'insert', pk: {}, set: {}, values: { name: 'second' } }], 'the survivor kept its value');
}

// ── Ordering ────────────────────────────────────────────────────────────

// UPDATEs, then DELETEs, then INSERTs — so a new row may reuse a key the same
// batch frees.
{
  const s = emptyStage();
  const c = ctx();
  addRow(s);
  editCell(s, c, 3, 0, '1');
  deleteRows(s, 3, [0]);
  editCell(s, c, 1, 1, 'Grace');
  eq(
    buildChanges(s, c).changes.map((x) => x.kind),
    ['update', 'delete', 'insert'],
    'statements compile in dependency order'
  );
}

// ── The refusals ────────────────────────────────────────────────────────

{
  const s = emptyStage();
  editCell(s, { columns: COLUMNS, base: base() }, 0, 1, 'x');
  const r = buildChanges(s, { columns: COLUMNS, base: base(), pkColumns: [] });
  eq(r.ok, false, 'a table with no primary key is refused');
  eq(r.error.includes('primary key'), true, 'and says why');
}

// Editing a PK column is refused here as it is in edit.rs: moving a row's
// address while using it as the address is the stale-PK hazard itself.
{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 0, 0, '99');
  const r = buildChanges(s, c);
  eq(r.ok, false, 'editing the primary key is refused');
  eq(r.error.includes('id'), true, 'and names the column');
}

// A row whose key is NULL addresses nothing, so it cannot be updated or deleted.
{
  const s = emptyStage();
  const c = { columns: COLUMNS, base: [[null, 'ghost', null]], pkColumns: PK };
  deleteRows(s, 1, [0]);
  eq(buildChanges(s, c).ok, false, 'a NULL primary key is refused');
}

// ── Clearing ────────────────────────────────────────────────────────────

{
  const s = emptyStage();
  const c = ctx();
  editCell(s, c, 0, 1, 'x');
  deleteRows(s, 3, [1]);
  addRow(s);
  eq(stagedCount(s), 3, 'three pending changes');
  clearStage(s);
  eq(stagedCount(s), 0, 'discard empties the buffer');
  eq(viewRows(s, COLUMNS, c.base), base(), 'and the grid shows the untouched rows again');
}

if (failed) {
  console.error(`\n${failed} failing`);
  process.exit(1);
} else {
  console.log('stage core: all tests pass');
}
