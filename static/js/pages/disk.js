/* Disk: mounted filesystems (df) and watched directory sizes (du).
 *
 * Read-only. Neither table has an action — the page reports, it does not delete.
 * The server already sorts filesystems fullest-first and computes each bar's
 * tone, so this file only formats bytes and paints.
 */

import { get } from '../core/api.js';
import { bytes } from '../core/format.js';
import { h, render, emptyRow, reportError } from '../core/ui.js';

const fsBody = document.getElementById('fs-body');
// The directories card is absent entirely when none are configured (the
// template renders a callout instead), so this may legitimately be null.
const dirsBody = document.getElementById('dirs-body');

/* A filled bar, reusing metrics' `.usage`/`.usage-val` markup: the `.progress`
 * wrapper carries the tone class (empty for a healthy disk) and the inner bar
 * carries the width. */
function meter(pct, tone) {
  const cls = tone === 'ok' ? 'progress' : `progress ${tone}`;
  return h('div', { class: 'usage' }, [
    h('div', { class: cls }, h('div', { class: 'progress-bar', style: { width: `${Math.min(100, pct)}%` } })),
    h('span', { class: 'usage-val' }, `${pct}%`),
  ]);
}

function fsRow(f) {
  return h('tr', {}, [
    h('td', {}, h('code', {}, f.source)),
    h('td', {}, h('code', {}, f.mount)),
    h('td', { class: 'num' }, bytes(f.size)),
    h('td', { class: 'num' }, bytes(f.used)),
    h('td', { class: 'num' }, bytes(f.avail)),
    h('td', {}, meter(f.use_pct, f.tone)),
  ]);
}

function dirRow(d) {
  // A path du could not measure shows why in the size column rather than a size
  // — a vanished or unreadable watched directory is the point of watching it.
  const size = d.bytes == null ? h('span', { class: 'muted' }, d.note || 'unavailable') : bytes(d.bytes);
  return h('tr', {}, [h('td', {}, h('code', {}, d.path)), h('td', { class: 'num' }, size)]);
}

async function load() {
  try {
    const { filesystems, directories } = await get('/disk/data');
    render(fsBody, filesystems.length ? filesystems.map(fsRow) : [emptyRow(6, 'No filesystems reported.')]);
    if (dirsBody) {
      render(dirsBody, directories.length ? directories.map(dirRow) : [emptyRow(2, 'No directories watched.')]);
    }
  } catch (e) {
    reportError(e, 'Could not read disk usage.');
  }
}

load();
