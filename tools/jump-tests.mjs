// Headless tests for jump-to-table's pure core (static/js/db/jumpcore.js).
//
// No framework, no build step — run with:
//
//     node tools/jump-tests.mjs
//
// These cover the matching rules a user notices immediately when they are
// wrong: a table that should match and doesn't, or the right table ranked
// below a worse one.

import { fuzzy, rank, MAX_RESULTS } from '../static/js/db/jumpcore.js';

let failed = 0;

function eq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) return;
  failed++;
  console.error(`FAIL ${label}\n  expected ${b}\n  got      ${a}`);
}

// ── fuzzy ──────────────────────────────────────────────────────────────

// An empty query matches everything equally — the dialog opens listing all.
eq(fuzzy('account', ''), 0, 'empty query scores 0');

// Non-subsequence is null, not a large score: callers branch on null.
eq(fuzzy('account', 'zz'), null, 'no match is null');
eq(fuzzy('account', 'tnuocca'), null, 'order matters');

// Matching is case-insensitive in both directions.
eq(fuzzy('Account', 'acc') !== null, true, 'query case ignored');
eq(fuzzy('account', 'ACC') !== null, true, 'text case ignored');

// A contiguous prefix is the cheapest possible non-empty match.
eq(fuzzy('account', 'acc') < fuzzy('account', 'act'), true, 'contiguous beats scattered');

// Word-boundary matches beat mid-word ones. Both candidates break the run
// after `a`, so this isolates boundary vs mid-word: in `a_log` the `l` follows
// a separator, in `axlog` it sits inside the word.
eq(fuzzy('a_log', 'al') < fuzzy('axlog', 'al'), true, 'boundary beats mid-word');

// But an unbroken run beats both — `al` in `alert` is contiguous.
eq(fuzzy('alert', 'al') < fuzzy('a_log', 'al'), true, 'contiguous beats a boundary restart');

// Scoring finds the *best* alignment, not the first. A greedy scan matches
// "sr" against `script_run` by taking the `r` of "sc-r-ipt" (mid-word, +3) and
// never discovers `script`+`run` (two boundaries, +2) — which ranked
// `script_run` below `session_read`. This is that regression.
eq(fuzzy('script_run', 'sr') < fuzzy('session_read', 'sr'), true, 'best alignment, not the first');

// Length is a tiebreaker: same match shape, shorter name first.
eq(fuzzy('user', 'user') < fuzzy('user_alert_delivery', 'user'), true, 'shorter wins ties');

// ── rank ───────────────────────────────────────────────────────────────

const entries = [
  { qualified: 'session_read' },
  { qualified: 'script_run' },
  { qualified: 'account' },
  { qualified: 'audit_log' },
];

// Non-matches are dropped entirely, not sorted to the bottom.
eq(rank(entries, 'zzz'), [], 'no matches yields nothing');

// The boundary match leads.
eq(rank(entries, 'sr')[0].qualified, 'script_run', 'sr finds script_run first');

// An exact name outranks a longer one that also contains it.
eq(rank(entries, 'account')[0].qualified, 'account', 'exact name leads');

// An empty query keeps every entry, in input order (all score 0, sort stable).
eq(
  rank(entries, '').map((e) => e.qualified),
  entries.map((e) => e.qualified),
  'empty query preserves order'
);

// The result list is capped — a 5000-table Postgres source must not paint
// 5000 rows into the dialog.
{
  const many = Array.from({ length: 5000 }, (_, i) => ({ qualified: `table_${i}` }));
  eq(rank(many, '').length, MAX_RESULTS, 'results are capped');
}

if (failed) {
  console.error(`\n${failed} failing`);
  process.exit(1);
} else {
  console.log('jump core: all tests pass');
}
