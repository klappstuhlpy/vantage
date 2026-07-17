/* Security — rejected requests, where they came from, and why.
 *
 * This page had never once run: security.html overrode `extra_head`/`body_end`,
 * blocks the old layout didn't define, so neither its CSS nor its JS ever
 * reached the browser. Everything here is therefore new rather than ported, and
 * a few things the old markup implied are deliberately done differently:
 *
 *   - The timeline drew "Failed logins", "Rate limited" AND "Bad requests" as
 *     three peers. But bad_requests counts *every* 4xx, so it already contains
 *     the other two — the chart would double-count itself visually. We plot the
 *     three disjoint parts instead, and the total is the tile.
 *
 *   - The server caps its scan at 5000 rows (security.rs). At the cap the
 *     totals are a floor, not a total, so they are rendered as "5,000+" with a
 *     note rather than as a precise number we cannot stand behind.
 */

import { get, withQuery, ApiError } from '../core/api.js';
import { h, icon, render, pill, emptyRow, emptyState, skeletonRows, reportError, wireSegmented } from '../core/ui.js';
import { num, bytes, absolute, relative, startTimestampTicker } from '../core/format.js';
import { createChart, destroyChart } from '../core/chart.js';

/** Mirrors pick_bucket() in src/security.rs — the x grid must match the server's. */
const ROW_CAP = 5000;

function bucketSecs(rangeSecs) {
  if (rangeSecs <= 3600) return 60;
  if (rangeSecs <= 6 * 3600) return 5 * 60;
  if (rangeSecs <= 24 * 3600) return 15 * 60;
  if (rangeSecs <= 7 * 86400) return 3600;
  return 6 * 3600;
}

const RANGE_SECS = { '1h': 3600, '6h': 6 * 3600, '24h': 24 * 3600, '7d': 7 * 86400, '30d': 30 * 86400 };

const page = document.getElementById('page');
const GEOIP = page.dataset.geoip === 'true';
const CLOUDFLARE = page.dataset.cloudflare === 'true';

const tilesEl = document.getElementById('tiles');
const timelineEl = document.getElementById('chart-timeline');
const topIpsBody = document.getElementById('top-ips-body');
const ipCountEl = document.getElementById('ip-count');
const reasonsEl = document.getElementById('reasons');
const countriesEl = document.getElementById('countries');
const recentBody = document.getElementById('recent-body');

let range = '24h';
let timelineChart = null;
let cfChart = null;
let seq = 0;

/* =======================================================================
   Tiles
   ======================================================================= */

function tile(label, value, sub, status, iconName) {
  return h(
    'div',
    { class: `stat${status ? ` ${status}` : ''}` },
    h('span', { class: 'stat-key' }, icon(iconName), label),
    h('span', { class: 'stat-value' }, value),
    h('span', { class: 'stat-sub' }, sub)
  );
}

function renderTiles(t) {
  // At the cap we are reporting the size of our sample, not of reality.
  const capped = t.bad_requests >= ROW_CAP;
  const count = (n) => (capped ? `${num(n)}+` : num(n));
  const sub = capped ? 'in the newest 5,000 rejected' : 'in this range';

  render(
    tilesEl,
    tile('Rejected requests', count(t.bad_requests), capped ? 'scan limit reached' : 'in this range', t.bad_requests ? 'warn' : 'ok', 'ban'),
    tile('Failed logins', count(t.failed_logins), sub, t.failed_logins ? 'down' : 'ok', 'fingerprint'),
    tile('Rate limited', count(t.rate_limited), sub, t.rate_limited ? 'warn' : null, 'gauge'),
    tile('Unique addresses', num(t.unique_ips), 'sent at least one', null, 'globe')
  );
}

/* =======================================================================
   Timeline
   ======================================================================= */

/**
 * The server only emits buckets that contain something. For rejected requests
 * an absent bucket is not missing data — it is a genuine zero, and drawing it
 * as one is the honest reading. (Contrast with metrics, where a gap means the
 * collector missed a sample and the line must break.)
 */
function zeroFill(buckets, rangeSecs) {
  const step = bucketSecs(rangeSecs);
  const now = Math.floor(Date.now() / 1000);
  const end = now - (now % step);
  const start = end - rangeSecs;

  const byTs = new Map(buckets.map((b) => [b.ts, b]));
  const xs = [];
  const failed = [];
  const limited = [];
  const other = [];

  for (let ts = start; ts <= end; ts += step) {
    const b = byTs.get(ts);
    xs.push(ts);
    failed.push(b ? b.failed_logins : 0);
    limited.push(b ? b.rate_limited : 0);
    // The disjoint remainder: every other 4xx reason.
    other.push(b ? Math.max(0, b.bad_requests - b.failed_logins - b.rate_limited) : 0);
  }
  return [xs, failed, limited, other];
}

function renderTimeline(data, rangeSecs) {
  if (timelineChart) {
    destroyChart(timelineChart);
    timelineChart = null;
  }
  timelineEl.previousElementSibling?.remove(); // stale legend from the last render
  render(timelineEl);

  if (!data.length) {
    render(
      timelineEl.parentElement,
      emptyState({
        icon: 'shield',
        title: 'Nothing was rejected in this range',
        sub: 'Every request that reached Vantage was served.',
      })
    );
    return;
  }

  timelineChart = createChart(timelineEl, {
    labels: ['Failed logins', 'Rate limited', 'Other 4xx'],
    data: zeroFill(data, rangeSecs),
    format: (v) => num(v),
    height: 240,
  });
}

/* =======================================================================
   Bar lists — reasons, countries
   ======================================================================= */

/**
 * A ranked bar list. Bars are proportional to the largest row, so the shape
 * reads as "relative to the worst offender" rather than as a share of a total —
 * the counts are always printed beside them either way.
 */
function renderBars(host, rows, { emptyTitle, emptySub }) {
  if (!rows.length) {
    render(host, emptyState({ icon: 'inbox', title: emptyTitle, sub: emptySub }));
    return;
  }

  const max = Math.max(...rows.map((r) => r.count)) || 1;
  render(
    host,
    ...rows.map((r) =>
      h(
        'div',
        { class: 'bar-row' },
        h('span', { class: 'bar-label' }, r.label),
        h('span', { class: 'bar-track' }, h('span', { class: 'bar-fill', style: { width: `${(r.count / max) * 100}%` } })),
        h('span', { class: 'bar-value' }, num(r.count))
      )
    )
  );
}

/* =======================================================================
   Tables
   ======================================================================= */

/** A country as flag + name; the code alone is not a location to most readers. */
function place(code, country, city) {
  if (!code) return h('span', { class: 'dim' }, 'Unknown');
  const label = [city, country || code].filter(Boolean).join(', ');
  return h('span', { class: 'place' }, flag(code), h('span', {}, label));
}

/**
 * Regional-indicator flag. It is decorative — the name always sits beside it —
 * so it is hidden from assistive tech rather than announced as a country twice.
 */
function flag(code) {
  const cc = String(code || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return h('span', {});
  const emoji = String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  return h('span', { class: 'flag', 'aria-hidden': 'true' }, emoji);
}

function renderTopIps(rows) {
  ipCountEl.textContent = num(rows.length);
  const cols = GEOIP ? 3 : 2;
  if (!rows.length) {
    render(topIpsBody, emptyRow(cols, 'No address was rejected in this range.'));
    return;
  }

  render(
    topIpsBody,
    ...rows.map((r) =>
      h(
        'tr',
        {},
        h('td', { class: 'mono' }, r.ip),
        GEOIP ? h('td', {}, place(r.country_code, r.country, r.city)) : null,
        h('td', { class: 'num mono' }, num(r.count))
      )
    )
  );
}

const REASON_TONE = { 'Incorrect Login': 'down', 'Rate Limited': 'warn' };

function renderRecent(rows) {
  if (!rows.length) {
    render(recentBody, emptyRow(5, 'No rejected requests in this range.'));
    return;
  }

  render(
    recentBody,
    ...rows.map((r) =>
      h(
        'tr',
        {},
        h('td', {}, h('time', { class: 'js-ts', datetime: new Date(r.ts * 1000).toISOString(), title: absolute(r.ts) }, relative(r.ts))),
        h('td', { class: 'mono' }, r.ip ? [GEOIP ? flag(r.country_code) : null, r.ip] : h('span', { class: 'dim' }, 'unknown')),
        h('td', { class: 'mono' }, r.status_code),
        h('td', {}, pill(REASON_TONE[r.reason] || 'idle', r.reason)),
        // A path is attacker-controlled text. h() assigns it via textContent, so
        // it cannot become markup — this is the row that made innerHTML unsafe.
        h('td', { class: 'mono path', title: r.path }, r.path)
      )
    )
  );
}

/* =======================================================================
   Cloudflare
   ======================================================================= */

function renderCloudflare(d) {
  const tiles = document.getElementById('cf-tiles');
  const stateEl = document.getElementById('cf-state');
  const s = d.summary;

  const cachedPct = s.total_requests ? (s.cached_requests / s.total_requests) * 100 : 0;

  stateEl.textContent = 'Connected';
  stateEl.className = 'chip acc';

  render(
    tiles,
    tile('Requests', num(s.total_requests), 'through Cloudflare', null, 'globe'),
    tile('Cached', `${cachedPct.toFixed(1)} %`, `${num(s.cached_requests)} served from cache`, null, 'zap'),
    tile('Threats', num(s.threats), 'blocked at the edge', s.threats ? 'warn' : 'ok', 'shield'),
    tile('Transferred', bytes(s.bytes), 'total egress', null, 'network')
  );

  const host = document.getElementById('chart-cf');
  if (cfChart) {
    destroyChart(cfChart);
    cfChart = null;
  }
  host.previousElementSibling?.remove();
  render(host);

  if (!s.series?.length) {
    render(host.parentElement, emptyState({ icon: 'activity', title: 'Cloudflare returned no traffic for this range' }));
  } else {
    cfChart = createChart(host, {
      labels: ['Requests', 'Threats'],
      data: [s.series.map((b) => b.ts), s.series.map((b) => b.requests), s.series.map((b) => b.threats)],
      format: (v) => num(v),
      height: 220,
    });
  }

  const body = document.getElementById('cf-events-body');
  if (!d.events?.length) {
    render(body, emptyRow(5, 'No firewall events — either nothing was challenged, or this zone has no WAF rules.'));
    return;
  }

  render(
    body,
    ...d.events.map((e) =>
      h(
        'tr',
        {},
        h('td', {}, h('time', { class: 'js-ts', datetime: new Date(e.ts * 1000).toISOString(), title: absolute(e.ts) }, relative(e.ts))),
        h('td', {}, pill(e.action === 'block' || e.action === 'drop' ? 'down' : 'warn', e.action)),
        h('td', { class: 'mono dim', title: e.rule_id }, e.source || e.rule_id || '—'),
        h('td', { class: 'mono' }, e.country ? [flag(e.country), e.client_ip] : e.client_ip),
        h('td', { class: 'mono path', title: e.uri }, e.uri)
      )
    )
  );
}

/**
 * Cloudflare is a third party over the network: it is slow, it rate-limits, and
 * it fails independently of this host. So it loads on its own and its failure
 * degrades one section instead of taking the page down with it.
 */
async function loadCloudflare(mySeq) {
  const stateEl = document.getElementById('cf-state');
  stateEl.textContent = 'Loading…';
  stateEl.className = 'chip';

  try {
    const d = await get(withQuery('/security/cloudflare', { range }));
    if (mySeq !== seq) return;
    renderCloudflare(d);
  } catch (e) {
    if (mySeq !== seq) return;
    stateEl.textContent = e instanceof ApiError && e.status === 502 ? "Cloudflare didn't answer" : 'Unavailable';
    stateEl.className = 'chip';
    render(
      document.getElementById('cf-tiles'),
      emptyState({
        degraded: true,
        title: "Couldn't reach Cloudflare",
        sub: e?.message || 'The API did not respond. Your own traffic figures above are unaffected.',
      })
    );
  }
}

/* =======================================================================
   Load
   ======================================================================= */

function showLoading() {
  render(tilesEl, ...Array.from({ length: 4 }, () => h('div', { class: 'stat' }, h('div', { class: 'skel skel-text' }))));
  render(topIpsBody, ...skeletonRows(GEOIP ? 3 : 2));
  render(recentBody, ...skeletonRows(5));
}

async function load() {
  const mySeq = ++seq;
  showLoading();

  try {
    const d = await get(withQuery('/security/data', { range }));
    // A slow range can land after a faster one the user asked for since.
    if (mySeq !== seq) return;

    renderTiles(d.totals);
    renderTimeline(d.timeline, RANGE_SECS[range]);
    renderTopIps(d.top_ips);
    renderBars(
      reasonsEl,
      d.reason_breakdown.map((r) => ({ label: r.reason, count: r.count })),
      { emptyTitle: 'Nothing to explain', emptySub: 'No request was rejected in this range.' }
    );
    if (GEOIP && countriesEl) {
      renderBars(
        countriesEl,
        d.country_distribution.map((c) => ({ label: c.country || c.country_code, count: c.count })),
        { emptyTitle: 'No locations resolved', emptySub: 'Requests came from addresses the database has no entry for.' }
      );
    }
    renderRecent(d.recent);
  } catch (e) {
    if (mySeq !== seq) return;
    reportError(e, "Couldn't load security data");
    render(tilesEl, emptyState({ degraded: true, title: "Couldn't load security data", sub: e?.message }));
    render(topIpsBody, emptyRow(GEOIP ? 3 : 2, 'Unavailable.'));
    render(recentBody, emptyRow(5, 'Unavailable.'));
  }

  if (CLOUDFLARE) loadCloudflare(mySeq);
}

wireSegmented(document.getElementById('range'), (v) => {
  range = v;
  load();
});

startTimestampTicker();
load();
