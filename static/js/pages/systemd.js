/* Units: the systemd units this host was told to watch.
 *
 * The page can start, stop and restart them. It cannot add one — the list is
 * config.json's, and the UI never pretends otherwise. Stop and restart are
 * confirmed, because both take a service down and this page is usually open
 * precisely when something already is.
 */

import { get, post } from '../core/api.js';
import { h, pill, render, emptyRow, reportError, toastOk, toastErr, confirm } from '../core/ui.js';

const body = document.getElementById('units-body');

/* systemd reports "n/a" for a unit that has never started; a dash is clearer
 * than that verbatim, which reads as a failed lookup. */
function since(value) {
  if (!value || value === 'n/a') return '—';
  return value;
}

function actionButton(unit, verb, label, danger) {
  const btn = h('button', { class: `btn btn-sm${danger ? ' btn-danger' : ''}`, type: 'button' }, label);
  btn.addEventListener('click', () => act(unit, verb, label));
  return btn;
}

function row(u) {
  const state = `${u.active_state}${u.sub_state ? ` (${u.sub_state})` : ''}`;
  return h('tr', {}, [
    h('td', {}, [h('code', {}, u.unit), h('div', { class: 'cell-sub' }, u.description)]),
    h('td', {}, pill(u.tone, state)),
    h('td', {}, u.file_state || '—'),
    h('td', {}, since(u.since)),
    h('td', { class: 'actions' }, h('div', { class: 'btn-row pinned' }, [
      actionButton(u.unit, 'start', 'Start', false),
      actionButton(u.unit, 'restart', 'Restart', false),
      actionButton(u.unit, 'stop', 'Stop', true),
    ])),
  ]);
}

async function load() {
  try {
    const { units } = await get('/systemd/data');
    render(body, units.length ? units.map(row) : [emptyRow(5, 'No units configured.')]);
  } catch (e) {
    reportError(e, 'Could not read unit state.');
  }
}

async function act(unit, verb, label) {
  // Start is additive; the other two take something down. Only confirm those —
  // a prompt on every button is a prompt nobody reads on the one that matters.
  if (verb !== 'start') {
    const ok = await confirm({
      title: `${label} ${unit}?`,
      message:
        verb === 'stop'
          ? 'The unit stops now and stays down until it is started again or the host reboots.'
          : 'The unit goes down and comes back. Anything it serves drops for the duration.',
      confirmLabel: label,
      danger: true,
    });
    if (!ok) return;
  }

  try {
    await post(`/systemd/${encodeURIComponent(unit)}/${verb}`);
    toastOk(`${label} ${unit}`, 'Done.');
  } catch (e) {
    // The server passes systemctl's own stderr through, which says far more than
    // "action failed" — surface it rather than a generic message.
    toastErr(`Could not ${verb} ${unit}`, e.message);
  }
  // Reload either way: a failed restart still leaves the unit somewhere, and
  // that somewhere is what the operator needs to see.
  await load();
}

load();
