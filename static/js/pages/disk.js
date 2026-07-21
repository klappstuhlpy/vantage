/* Disk: mounted filesystems (df) and a top-level directory breakdown (du).
 *
 * Read-only. Nothing here has an action — the page reports, it does not delete.
 * The server sorts filesystems fullest-first, sorts each breakdown largest-first,
 * and computes every bar's tone and width; this file only formats bytes, sums
 * the totals for the tiles, and paints.
 */

import { get } from '../core/api.js';
import { bytes, percent } from '../core/format.js';
import { h, icon, render, emptyRow, reportError } from '../core/ui.js';

const tilesEl = document.getElementById('tiles');
const fsBody = document.getElementById('fs-body');
const breakdownEl = document.getElementById('breakdown');

/* A filled bar, reusing metrics' `.usage`/`.usage-val` markup: the `.progress`
 * wrapper carries the tone class and the inner bar carries the width. `label`
 * overrides the trailing text (a breakdown bar shows bytes, not a percent). */
function meter(pct, tone, label) {
  return h('div', { class: 'usage' }, [
    h('div', { class: `progress ${tone}` }, h('div', { class: 'progress-bar', style: { width: `${Math.min(100, pct)}%` } })),
    h('span', { class: 'usage-val' }, label ?? `${pct}%`),
  ]);
}

/* =======================================================================
   Tiles — capacity totals across the real filesystems
   ======================================================================= */

function tile(label, iconName, value, sub, status) {
  return h(
    'div',
    { class: `stat${status ? ` ${status}` : ''}` },
    h('span', { class: 'stat-key' }, icon(iconName), label),
    h('span', { class: 'stat-value' }, value),
    h('span', { class: 'stat-sub' }, sub)
  );
}

function renderTiles(filesystems) {
  const real = filesystems.filter((f) => f.real);
  const size = real.reduce((a, f) => a + f.size, 0);
  const used = real.reduce((a, f) => a + f.used, 0);
  const avail = real.reduce((a, f) => a + f.avail, 0);
  const pct = size ? (used / size) * 100 : 0;
  const status = pct >= 95 ? 'down' : pct >= 80 ? 'warn' : null;
  const fullest = real[0]; // server sorts fullest-first

  render(tilesEl, [
    tile('Capacity', 'hard-drive', bytes(size), `${real.length} filesystem${real.length === 1 ? '' : 's'}`),
    tile('Used', 'database', bytes(used), percent(pct), status),
    tile('Free', 'circle-check', bytes(avail), 'across all disks'),
    tile(
      'Fullest',
      'triangle-alert',
      fullest ? `${fullest.use_pct}%` : '—',
      fullest ? fullest.mount : 'no real disk',
      fullest ? (fullest.tone === 'ok' ? null : fullest.tone) : null
    ),
  ]);
}

/* =======================================================================
   Filesystems table
   ======================================================================= */

function fsRow(f) {
  // A pseudo filesystem has no inode accounting worth showing; leave the cell
  // empty rather than paint a fake zero-bar.
  const inodes = f.inode_pct == null ? h('span', { class: 'muted' }, '—') : meter(f.inode_pct, f.inode_tone);
  return h('tr', {}, [
    h('td', {}, h('code', {}, f.source)),
    h('td', {}, h('span', { class: 'muted' }, f.fstype)),
    h('td', {}, h('code', {}, f.mount)),
    h('td', { class: 'num' }, bytes(f.size)),
    h('td', { class: 'num' }, bytes(f.used)),
    h('td', { class: 'num' }, bytes(f.avail)),
    h('td', {}, meter(f.use_pct, f.tone)),
    h('td', {}, inodes),
  ]);
}

/* =======================================================================
   Breakdown — one card per real filesystem, directories as bars
   ======================================================================= */

function dirRow(d) {
  return h('div', { class: 'du-row' }, [
    h('code', { class: 'du-path' }, d.path),
    h('div', { class: 'du-bar' }, h('div', { class: 'progress' }, h('div', { class: 'progress-bar', style: { width: `${d.pct}%` } }))),
    h('span', { class: 'du-size' }, bytes(d.bytes)),
  ]);
}

function breakdownCard(b) {
  let body;
  if (b.note) {
    body = h('p', { class: 'muted du-empty' }, b.note);
  } else if (!b.entries.length) {
    body = h('p', { class: 'muted du-empty' }, 'Nothing to measure.');
  } else {
    body = h('div', { class: 'du-list' }, b.entries.map(dirRow));
  }
  return h('section', { class: 'card du-card' }, [
    h('div', { class: 'card-header' }, h('h3', {}, h('code', {}, b.mount))),
    h('div', { class: 'card-body' }, body),
  ]);
}

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  try {
    const { filesystems, breakdowns } = await get('/disk/data');
    renderTiles(filesystems);
    render(fsBody, filesystems.length ? filesystems.map(fsRow) : [emptyRow(8, 'No filesystems reported.')]);
    render(
      breakdownEl,
      breakdowns.length ? breakdowns.map(breakdownCard) : [h('p', { class: 'muted' }, 'No real filesystems to break down.')]
    );
  } catch (e) {
    reportError(e, 'Could not read disk usage.');
  }
}

load();
