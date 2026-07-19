/* The staging buffer — DB Studio Phase 5, the browser half (plan D15).
 *
 * Editing a cell here changes *nothing*. Every gesture in the grid lands in
 * this structure, and the only thing that ever leaves the browser is the
 * change list `buildChanges` produces, sent to `/database/preview` (which shows
 * you the statements) or `/database/apply` (which runs them, behind danger mode
 * and a sudo window). That separation is the point: an operator can stage a
 * dozen edits, look at exactly what they compile to, and throw them away.
 *
 * Rows are addressed by their **index in the loaded page**, which is only valid
 * for as long as that page is the page. Any reload — filter, sort, refresh,
 * fetching another 500 rows — invalidates every index in here, so the page
 * discards the whole buffer on reload rather than trying to rebase it. A
 * staging buffer that silently re-pointed at different rows after a sort is a
 * far worse failure than one that makes you re-type four edits.
 *
 * No DOM in this file: the interesting parts (does typing the original value
 * back un-stage the edit? does a deleted-then-edited row still compile to a
 * DELETE?) are exercised headlessly by `tools/stage-tests.mjs`.
 */

/** A fresh, empty buffer. */
export function emptyStage() {
  return { edits: new Map(), deleted: new Set(), added: [], seq: 0 };
}

export function isDirty(stage) {
  return stagedCount(stage) > 0;
}

/** How many statements this buffer would compile to — the toolbar's badge. */
export function stagedCount(stage) {
  // A deleted row's pending cell edits do not count: the row is going away, so
  // the UPDATE is dropped (see buildChanges). Counting it would put a number in
  // the badge that the review drawer then contradicts.
  let updates = 0;
  for (const [r, cells] of stage.edits) {
    if (!stage.deleted.has(r) && cells.size) updates++;
  }
  return updates + stage.deleted.size + stage.added.length;
}

/* ── The view model ─────────────────────────────────────────────────────── */

/** The rows the grid should show: base rows with staged edits painted over
 *  them, then any added rows, in the order they were added. */
export function viewRows(stage, columns, base) {
  const out = base.map((row, r) => {
    const cells = stage.edits.get(r);
    if (!cells || !cells.size) return row;
    return columns.map((name, c) => (cells.has(name) ? cells.get(name) : row[c]));
  });
  for (const add of stage.added) {
    out.push(columns.map((name) => (add.values.has(name) ? add.values.get(name) : null)));
  }
  return out;
}

/** `'added' | 'deleted' | null` for a view row index. */
export function rowStateOf(stage, baseCount, r) {
  if (r >= baseCount) return 'added';
  return stage.deleted.has(r) ? 'deleted' : null;
}

/** Has this cell been touched? Drives the amber tint. */
export function cellStaged(stage, baseCount, r, column) {
  if (r >= baseCount) return stage.added[r - baseCount]?.values.has(column) ?? false;
  return stage.edits.get(r)?.has(column) ?? false;
}

/* ── Mutations ──────────────────────────────────────────────────────────── */

/**
 * Stages one cell. `value` is a string, or `null` for SQL NULL.
 *
 * Typing the original value back removes the staged edit rather than recording
 * a no-op assignment — otherwise an operator who fixed their own typo would
 * still ship an UPDATE, and the badge would insist there was something pending
 * when there was not.
 */
export function editCell(stage, { columns, base }, r, c, value) {
  const column = columns[c];
  if (column === undefined) return;
  const baseCount = base.length;

  if (r >= baseCount) {
    const add = stage.added[r - baseCount];
    if (add) add.values.set(column, value);
    return;
  }

  let cells = stage.edits.get(r);
  if (base[r]?.[c] === value) {
    cells?.delete(column);
    if (cells && !cells.size) stage.edits.delete(r);
    return;
  }
  if (!cells) {
    cells = new Map();
    stage.edits.set(r, cells);
  }
  cells.set(column, value);
}

/** Marks base rows for deletion; drops added rows outright.
 *  An added row has never been sent anywhere, so there is nothing to delete —
 *  removing it is the honest reading of "delete this row". */
export function deleteRows(stage, baseCount, indices) {
  const adds = [];
  for (const r of indices) {
    if (r >= baseCount) adds.push(r - baseCount);
    else stage.deleted.add(r);
  }
  // Descending, so earlier splices do not shift the indices still to come.
  for (const i of adds.sort((a, b) => b - a)) stage.added.splice(i, 1);
}

/** Un-deletes base rows (the same toolbar button toggles). */
export function undeleteRows(stage, indices) {
  for (const r of indices) stage.deleted.delete(r);
}

/** Appends an empty row. Every column starts NULL — including the primary key,
 *  which the operator must fill in unless the column has a default the server
 *  will supply. */
export function addRow(stage) {
  stage.added.push({ id: ++stage.seq, values: new Map() });
}

/** Throws the whole buffer away. */
export function clearStage(stage) {
  stage.edits.clear();
  stage.deleted.clear();
  stage.added.length = 0;
}

/* ── Compilation ────────────────────────────────────────────────────────── */

/**
 * Compiles the buffer into the `ChangeSpec[]` the server plans from.
 *
 * These checks duplicate ones `edit.rs` makes — deliberately. The server's are
 * the guarantee; these exist so the operator hears "this table has no primary
 * key" before staging twelve edits, rather than after.
 *
 * @returns {{ok: true, changes: object[]} | {ok: false, error: string}}
 */
export function buildChanges(stage, { columns, base, pkColumns }) {
  if (!pkColumns.length) {
    return {
      ok: false,
      error: 'This table has no primary key, so a row cannot be addressed unambiguously. Edit it with a SQL statement instead.',
    };
  }

  const pkOf = (r) => {
    const pk = {};
    for (const name of pkColumns) {
      const c = columns.indexOf(name);
      const v = base[r][c];
      if (v === null) return null; // a NULL key addresses nothing
      pk[name] = v;
    }
    return pk;
  };

  const changes = [];

  // UPDATEs first, then DELETEs, then INSERTs. Updating a row this batch also
  // deletes would be wasted work; inserting last means a new row can reuse a
  // key the same batch frees.
  for (const [r, cells] of [...stage.edits].sort((a, b) => a[0] - b[0])) {
    if (stage.deleted.has(r) || !cells.size) continue;
    const set = {};
    for (const [name, value] of cells) {
      if (pkColumns.includes(name)) {
        return {
          ok: false,
          error: `${name} is part of the primary key. Changing a row's key while using it as the row's address is the one edit this console refuses — delete the row and insert the replacement.`,
        };
      }
      set[name] = value;
    }
    const pk = pkOf(r);
    if (!pk) return { ok: false, error: `Row ${r + 1} has a NULL primary key, so it cannot be addressed.` };
    changes.push({ kind: 'update', pk, set, values: {} });
  }

  for (const r of [...stage.deleted].sort((a, b) => a - b)) {
    const pk = pkOf(r);
    if (!pk) return { ok: false, error: `Row ${r + 1} has a NULL primary key, so it cannot be addressed.` };
    changes.push({ kind: 'delete', pk, set: {}, values: {} });
  }

  for (const add of stage.added) {
    const values = {};
    // Only columns the operator actually filled in are sent. An untouched
    // column is left to its DEFAULT, which is not the same as writing NULL
    // into it — and picking the wrong one of those silently is how an INSERT
    // ends up overriding a default the schema author meant to apply.
    for (const [name, value] of add.values) values[name] = value;
    changes.push({ kind: 'insert', pk: {}, set: {}, values });
  }

  return { ok: true, changes };
}
