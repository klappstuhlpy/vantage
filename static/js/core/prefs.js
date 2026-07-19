/* Per-account preference persistence.
 *
 * The server stores a single JSON blob per account at /account/prefs. This
 * module syncs it in both directions:
 *
 *  1. On page load, fetch the server blob and push any keys the browser hasn't
 *     seen (a fresh device gets the remote state immediately). If the server is
 *     unreachable (network issue, session expired) it degrades silently —
 *     localStorage is always the fast path and the page is never blocked.
 *
 *  2. On any local preference write (theme/accent/density/sidebar/widgets),
 *     the caller hands us a partial object and we merge it into a local
 *     snapshot, then flush to the server debounced so a burst of changes
 *     compresses into one request.
 */

import { put, get as apiGet } from './api.js';

const ENDPOINT = '/account/prefs';
const DEBOUNCE_MS = 1500;

let timer = null;
let snapshot = {};

function schedule() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(flush, DEBOUNCE_MS);
}

async function flush() {
  timer = null;
  const payload = { ...snapshot };
  try {
    await put(ENDPOINT, payload);
  } catch {
    // Best-effort: localStorage is authoritative, the server is a mirror.
  }
}

/** Merge partial preferences into the local snapshot and flush to server. */
export function save(partial) {
  Object.assign(snapshot, partial);
  schedule();
}

/** Fetch remote prefs and seed the local snapshot. Returns the blob or null. */
export async function load() {
  try {
    const remote = await apiGet(ENDPOINT);
    if (remote && typeof remote === 'object') {
      snapshot = { ...remote };
    }
    return remote;
  } catch {
    return null;
  }
}
