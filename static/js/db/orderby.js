/* The ORDER BY box: text ⇄ sort model.
 *
 * Pure and DOM-free so it can be exercised headlessly (`node
 * tools/orderby-tests.mjs`), like gridcore/jumpcore. It is input validation,
 * which is exactly the code that should not need a browser to test.
 *
 * The column is resolved against the *known columns* of the table, and the
 * resolved spelling is what goes back out — so typing `NAME` sorts by `name`
 * and the box then says `name`. Nothing here builds SQL: the result is the
 * same `{column, desc}` model a header click produces, and the server
 * re-validates the column against introspection regardless (browse.rs `plan`).
 */

/** Render a sort model as the text shown in the box. */
export function formatSort(sort) {
  if (!sort) return '';
  return `${sort.column} ${sort.desc ? 'DESC' : 'ASC'}`;
}

/**
 * Parse what the operator typed.
 *
 * @param {string} text
 * @param {string[]} columns  the table's real column names
 * @returns {{ok: true, sort: null | {column: string, desc: boolean}} | {ok: false, error: string}}
 */
export function parseSort(text, columns) {
  const trimmed = text.trim().replace(/[,;]+$/, '');
  if (!trimmed) return { ok: true, sort: null };

  // Optional `ORDER BY` prefix: the label already says it, but typing it is a
  // reflex worth tolerating rather than rejecting.
  const body = trimmed.replace(/^order\s+by\s+/i, '').trim();
  if (!body) return { ok: true, sort: null };

  // One key only. Multi-column sort is not in scope (plan §6), and silently
  // honouring the first of three would be a worse answer than saying so.
  if (body.includes(',')) {
    return { ok: false, error: 'One sort column at a time — remove the comma.' };
  }

  const parts = body.split(/\s+/);
  if (parts.length > 2) {
    return { ok: false, error: `Expected "column" or "column DESC", got "${body}".` };
  }

  const [rawCol, rawDir] = parts;
  // Quoted identifiers are how you would write it in SQL, so accept them —
  // but the quotes are stripped for matching, never passed along.
  const wanted = rawCol.replace(/^["'`[]|["'`\]]$/g, '');

  const column = columns.find((c) => c === wanted) ?? columns.find((c) => c.toLowerCase() === wanted.toLowerCase());
  if (!column) {
    return { ok: false, error: `No column named "${wanted}" in this table.` };
  }

  let desc = false;
  if (rawDir !== undefined) {
    const dir = rawDir.toLowerCase();
    if (dir === 'desc') desc = true;
    else if (dir === 'asc') desc = false;
    else return { ok: false, error: `Expected ASC or DESC, got "${rawDir}".` };
  }

  return { ok: true, sort: { column, desc } };
}
