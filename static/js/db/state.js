/* Shared state for the database console.
 *
 * The one fact every request on this page hangs off is the active source id —
 * which database the console is currently addressing. It lives here so the
 * page orchestrator and the studio modules that arrive in later phases (tree,
 * tabs, grid — see DB_STUDIO_PLAN.md §4) can share it without reaching into
 * each other's DOM. This module holds no DOM references: the page wires its
 * controls to these setters and reads state back through the getters.
 *
 * Grows tab/selection state and sessionStorage persistence in Phase 2.
 */

/** Every database the server offered, by source id. */
let sources = new Map();

/** The source id every request on this page is addressed to. */
let currentId = '';

/** @param {Array<{id: string}>} list — the `/database/sources` response. */
export function setSources(list) {
  sources = new Map(list.map((d) => [d.id, d]));
}

export function hasSource(id) {
  return sources.has(id);
}

/** The catalog entries, in the order the server listed them. */
export function allSources() {
  return [...sources.values()];
}

export function setCurrent(id) {
  currentId = id;
}

export function current() {
  return currentId;
}

export function currentInfo() {
  return sources.get(currentId);
}

export function isPostgres() {
  return currentInfo()?.kind === 'postgres';
}

/** A human name for the active source, for prose (confirmations, the banner). */
export function currentLabel() {
  const info = currentInfo();
  if (!info) return 'this database';
  return info.kind === 'postgres' ? `${info.name} (PostgreSQL)` : `${info.name}.db`;
}

/* ── Schema overviews ─────────────────────────────────────────────────
   The tree stashes each source's /database/schema response here so other
   modules (the browser's footer, for one) can answer "roughly how many rows"
   without refetching. */

const overviews = new Map();

export function setOverview(source, overview) {
  overviews.set(source, overview);
}

/** The row estimate introspection reported for one table, or null. */
export function tableEstimate(source, schema, name) {
  const o = overviews.get(source);
  const t = o?.tables.find((t) => t.schema === schema && t.name === name);
  return t ? t.row_estimate : null;
}

export function getOverview(source) {
  return overviews.get(source);
}
