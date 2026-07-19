/* The pure core of jump-to-table (Ctrl+P) — matching / ranking, no DOM.
 *
 * Split out for the same reason `gridcore.js` is: this is the part where a
 * wrong comparison quietly hides the table you were looking for, so it is
 * testable headlessly (`node tools/jump-tests.mjs`). `jump.js` owns the dialog.
 */

/** Cost of matching a character at `pos`, given it does not continue a run. */
function stepCost(hay, pos) {
  return pos === 0 || '_.-'.includes(hay[pos - 1]) ? 1 : 3; // word boundary vs mid-word
}

/** Subsequence match with a score, the usual fuzzy-finder contract.
 *
 * Returns null when `q` is not a subsequence of `text` at all — that is the
 * "no match" signal, and it is distinct from a score of 0 (an empty query),
 * which is why callers must check for null rather than falsiness.
 *
 * Lower is better: continuing a run is free, starting one at a word boundary
 * (the string start, or after `_`/`.`/`-`) is cheap, and starting one
 * mid-word is expensive.
 *
 * This scores the *best* alignment, not the first one — a greedy left-to-right
 * scan is what makes a finder feel broken. Greedily, "sr" matches `script_run`
 * by taking the `r` of "sc-r-ipt", scoring it mid-word and ranking it below
 * `session_read`; the intended reading (`script` + `run`, both boundaries) is
 * one the greedy scan can never reach, because it consumed the wrong `r` before
 * it knew a better one existed. So: a small O(len(q) × len(text)) DP where
 * `dp[i][j]` is the cheapest way to match the first `i` query chars with the
 * `i`-th landing exactly at position `j-1`. Names are short and the result list
 * is capped, so this is imperceptible.
 */
export function fuzzy(text, q) {
  if (!q) return 0;
  const hay = text.toLowerCase();
  const needle = q.toLowerCase();
  const n = needle.length;
  const m = hay.length;
  if (n > m) return null;

  // dp[0][j] = 0: nothing matched yet, and that state can be extended from
  // anywhere, so every position is an equally free starting point.
  let prev = new Array(m + 1).fill(0);

  for (let i = 1; i <= n; i++) {
    const cur = new Array(m + 1).fill(Infinity);
    // Running minimum of dp[i-1][0..j-1] — the cheapest way to have matched
    // the previous char somewhere strictly before the current position.
    let best = Infinity;
    for (let j = 1; j <= m; j++) {
      if (prev[j - 1] < best) best = prev[j - 1];
      if (hay[j - 1] !== needle[i - 1]) continue;

      let cost = Infinity;
      // Continue a run: the previous char matched at j-2, immediately before.
      // Only from i >= 2 — the first query char has no run to continue, and
      // dp[0][*] = 0 would otherwise make it free.
      if (i >= 2 && prev[j - 1] < Infinity) cost = prev[j - 1];
      // Or start a run here, from any earlier prefix.
      if (best < Infinity) cost = Math.min(cost, best + stepCost(hay, j - 1));
      cur[j] = cost;
    }
    prev = cur;
  }

  const score = Math.min(...prev.slice(1));
  if (!Number.isFinite(score)) return null;
  // Shorter names win ties: "user" should outrank "user_alert_delivery". The
  // /100 keeps length a tiebreaker rather than a factor that can outweigh a
  // genuinely better match position.
  return score + text.length / 100;
}

/** How many rows the dialog will show. Beyond this you should type more. */
export const MAX_RESULTS = 50;

/** Rank entries (each `{qualified}`) against a query, best first. */
export function rank(entries, q) {
  return entries
    .map((e) => ({ e, s: fuzzy(e.qualified, q) }))
    .filter((r) => r.s !== null)
    .sort((a, b) => a.s - b.s)
    .slice(0, MAX_RESULTS)
    .map((r) => r.e);
}
