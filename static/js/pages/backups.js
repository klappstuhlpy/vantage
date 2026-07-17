/* Backups — delete and off-site upload for the server-rendered snapshot list.
 *
 * The page renders on the server and works without this file: "Back up now" is
 * a real form, and Download is a real link. This adds the two actions that
 * genuinely need scripting, replacing an inline <script> that:
 *
 *   - deleted a backup with no confirmation at all — one stray click and the
 *     snapshot was gone, which for a backup is the whole ballgame;
 *   - reported failures with alert(), a modal the browser draws and we can't
 *     style, that blocks the page and says "localhost says:" above the message;
 *   - reloaded the whole page after every action.
 */

import { post } from '../core/api.js';
import { render, confirm, reportError, toastOk, withLoading, pill } from '../core/ui.js';
import { hydrateTimestamps, startTimestampTicker } from '../core/format.js';

const table = document.getElementById('backups');

hydrateTimestamps(document);
startTimestampTicker();

if (table) {
  table.addEventListener('click', async (e) => {
    const del = e.target.closest('[data-delete]');
    if (del) return remove(del);

    const up = e.target.closest('[data-upload]');
    if (up) return sendOffsite(up);
  });
}

/* =======================================================================
   Delete
   ======================================================================= */

async function remove(btn) {
  const name = btn.dataset.delete;
  const row = btn.closest('tr');
  const offsite = row.querySelector('.pill')?.textContent.trim();

  // Deleting the only copy is materially different from deleting one of two,
  // and the operator is the only one who can weigh that — so say which it is.
  const message =
    offsite === 'stored'
      ? `${name} will be deleted from this host. The off-site copy is not touched, so it will remain in your remote store.`
      : `${name} will be deleted from this host, and there is no off-site copy of it. This cannot be undone.`;

  const ok = await confirm({
    title: 'Delete this snapshot?',
    message,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await post(`/backups/${encodeURIComponent(name)}/delete`);
    toastOk('Snapshot deleted', name);
    // The row is the only thing that changed — drop it in place rather than
    // reloading the page and throwing away the operator's scroll position.
    row.remove();
    refreshCounts();
  });
}

/* =======================================================================
   Off-site upload
   ======================================================================= */

async function sendOffsite(btn) {
  const name = btn.dataset.upload;
  const row = btn.closest('tr');

  try {
    await withLoading(btn, async () => {
      // This endpoint answers 200 with {status:"error"} for a failed upload
      // rather than a failing status code, so the body is the only thing that
      // tells the truth — a bare `if (res.ok)` here would report every failure
      // as a success.
      const r = await post(`/backups/${encodeURIComponent(name)}/upload`);
      if (r.status !== 'success') throw new Error(r.message || 'The off-site upload failed.');

      toastOk('Sent off-site', r.message);

      const cell = row.querySelector('.pill')?.parentElement;
      if (cell) render(cell, pill('ok', 'stored'));
      refreshCounts();
    });
  } catch (e) {
    reportError(e, "Couldn't send that off-site");
  }
}

/* =======================================================================
   Counts
   ======================================================================= */

/**
 * Keep the header counts honest after an action. These are server-rendered, so
 * without this a deleted snapshot leaves "Snapshots 7" over a table of 6 —
 * which is the sort of small lie that makes an operator stop trusting a page.
 */
function refreshCounts() {
  const rows = [...table.querySelectorAll('tbody tr')];
  const total = rows.length;
  const stored = rows.filter((r) => r.querySelector('.pill')?.textContent.trim() === 'stored').length;

  for (const badge of document.querySelectorAll('.count-badge')) badge.textContent = String(total);

  const snapshotStat = [...document.querySelectorAll('.stat')].find((s) => s.querySelector('.stat-key')?.textContent.includes('Snapshots'));
  if (snapshotStat) snapshotStat.querySelector('.stat-value').textContent = String(total);

  const offsiteStat = [...document.querySelectorAll('.stat')].find((s) => s.querySelector('.stat-key')?.textContent.includes('Off-site'));
  const offsiteValue = offsiteStat?.querySelector('.stat-value');
  // Only touch it when it is showing a ratio: "Off" and "Unreachable" are
  // states about the remote itself and have nothing to do with these counts.
  if (offsiteValue && offsiteValue.textContent.includes('/')) {
    offsiteValue.textContent = `${stored} / ${total}`;
    offsiteStat.classList.toggle('warn', stored < total);
  }

  if (!total) window.location.reload(); // let the server draw its empty state
}
