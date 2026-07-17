/* Formatting — every number, byte count, duration and timestamp in the UI.
 *
 * One rule underpins this file: a control plane must never lie about precision.
 * "2 minutes ago" is friendlier than an ISO string, so relative time is the
 * default — but the exact UTC timestamp is always one hover away, because when
 * you are reading an incident timeline "2 minutes ago" is not evidence.
 */

const NBSP = ' ';

/** Bytes → human units. Binary (KiB) because every source here is /proc or Docker. */
export function bytes(n, digits = 1) {
  if (n == null || Number.isNaN(n)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const sign = n < 0 ? '-' : '';
  // Whole bytes never need a decimal point; a "1.0 B" reads like a bug.
  const d = i === 0 ? 0 : digits;
  return `${sign}${v.toFixed(d)}${NBSP}${units[i]}`;
}

/** Bytes per second → human rate. */
export function rate(n, digits = 1) {
  if (n == null || Number.isNaN(n)) return '—';
  return `${bytes(n, digits)}/s`;
}

/** 0–100 → "61.4 %". Pass fraction=true for 0–1 inputs. */
export function percent(n, { digits = 1, fraction = false } = {}) {
  if (n == null || Number.isNaN(n)) return '—';
  const v = fraction ? n * 100 : n;
  return `${v.toFixed(digits)}${NBSP}%`;
}

/** Thousands separators, locale-aware. */
export function num(n, digits = 0) {
  if (n == null || Number.isNaN(n)) return '—';
  return n.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

/** Seconds → compact duration ("3d 4h", "12m 08s"). */
export function duration(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return '—';
  const s = Math.floor(Math.abs(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d) return `${d}d${NBSP}${h}h`;
  if (h) return `${h}h${NBSP}${String(m).padStart(2, '0')}m`;
  if (m) return `${m}m${NBSP}${String(sec).padStart(2, '0')}s`;
  return `${sec}s`;
}

/** Milliseconds → latency ("41 ms", "1.24 s"). */
export function latency(ms) {
  if (ms == null || Number.isNaN(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)}${NBSP}ms`;
  return `${(ms / 1000).toFixed(2)}${NBSP}s`;
}

function toDate(value) {
  if (value == null) return null;
  if (value instanceof Date) return value;
  // Unix seconds vs milliseconds: anything below ~1e11 can't be a sane ms date.
  if (typeof value === 'number') return new Date(value < 1e11 ? value * 1000 : value);
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Absolute local timestamp, e.g. "17 Jul 2026, 04:12:09". */
export function absolute(value) {
  const d = toDate(value);
  if (!d) return '—';
  return d.toLocaleString(undefined, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Clock only, e.g. "04:12:09" — for log lines and dense tables. */
export function clock(value) {
  const d = toDate(value);
  if (!d) return '—';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

/** The unambiguous form, for tooltips and evidence. */
export function iso(value) {
  const d = toDate(value);
  return d ? d.toISOString().replace('.000', '') : '—';
}

/** "just now" · "4 m ago" · "in 9 d". */
export function relative(value) {
  const d = toDate(value);
  if (!d) return '—';
  const diff = (d.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff <= 0 ? 'just now' : 'in a moment';

  const steps = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [86400 * 7, 'day', 86400],
    [86400 * 30, 'week', 86400 * 7],
    [86400 * 365, 'month', 86400 * 30],
    [Infinity, 'year', 86400 * 365],
  ];
  const [, unit, div] = steps.find(([limit]) => abs < limit);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });
  return rtf.format(Math.round(diff / div), unit);
}

/**
 * Hydrate every <time class="js-ts" datetime="..."> in `root`.
 *
 * The server renders a machine-readable ISO string; the browser is the only
 * party that knows the viewer's timezone and locale, so it owns the display
 * form. The exact instant always survives in the title attribute.
 *
 * @param {ParentNode} root
 * @param {{mode?: 'relative'|'absolute'|'clock'}} opts
 */
export function hydrateTimestamps(root = document, { mode = 'relative' } = {}) {
  const fmt = { relative, absolute, clock }[mode] ?? relative;
  for (const el of root.querySelectorAll('time.js-ts')) {
    const raw = el.getAttribute('datetime') || el.dataset.ts;
    if (!raw) continue;
    const m = el.dataset.tsMode || mode;
    el.textContent = ({ relative, absolute, clock }[m] ?? fmt)(raw);
    if (!el.title) el.title = `${absolute(raw)} · ${iso(raw)}`;
  }
}

let ticking = null;

/**
 * Keep relative timestamps honest as the page sits open. A dashboard left on a
 * second monitor for an hour must not still claim an incident was "2 m ago".
 * Ticks once a minute — cheap, and aligned with the coarsest unit we show.
 */
export function startTimestampTicker(root = document) {
  if (ticking) return;
  ticking = setInterval(() => {
    for (const el of root.querySelectorAll('time.js-ts')) {
      const mode = el.dataset.tsMode || 'relative';
      if (mode !== 'relative') continue;
      const raw = el.getAttribute('datetime') || el.dataset.ts;
      if (raw) el.textContent = relative(raw);
    }
  }, 60_000);
}

/** Short git-style id for hashes and container ids. */
export function shortId(id, len = 12) {
  if (!id) return '—';
  const s = String(id).replace(/^sha256:/, '');
  return s.length > len ? s.slice(0, len) : s;
}

/** Title-case a machine token ("geo_block" → "Geo block"). */
export function humanize(s) {
  if (!s) return '—';
  const t = String(s).replace(/[_-]+/g, ' ').trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
}
