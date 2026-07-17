/* Container snapshots.
 *
 * Data: GET /docker/snapshots/data, POST /docker/snapshots (JSON),
 * POST /docker/snapshots/:id/restore (JSON), DELETE /docker/snapshots/:id.
 *
 * The container picker comes from /docker/graph, which is the only endpoint
 * exposing a container's full id — /docker/services/data has short ids and only
 * covers configured services, while a snapshot can target any container.
 */

import { get, post, del } from '../core/api.js';
import {
  h,
  icon,
  render,
  emptyRow,
  skeletonRows,
  reportError,
  toast,
  confirm,
  openModal,
  closeModal,
  withLoading,
  emptyState,
  copyText,
} from '../core/ui.js';
import { relative, num, shortId } from '../core/format.js';

const body = document.getElementById('snap-body');
const tilesEl = document.getElementById('tiles');
const captureModal = document.getElementById('capture-modal');
const restoreModal = document.getElementById('restore-modal');
const $ = (id) => document.getElementById(id);

let restoring = null;

/* =======================================================================
   Render
   ======================================================================= */

function renderTiles(snaps) {
  const oldest = snaps.length ? snaps[snaps.length - 1].created_at : null;
  const containers = new Set(snaps.map((s) => s.container_name)).size;

  render(
    tilesEl,
    h(
      'div',
      { class: 'stat' },
      h('span', { class: 'stat-key' }, icon('camera'), 'Snapshots'),
      h('span', { class: 'stat-value' }, num(snaps.length)),
      h('span', { class: 'stat-sub' }, `across ${containers} container${containers === 1 ? '' : 's'}`)
    ),
    h(
      'div',
      { class: 'stat' },
      h('span', { class: 'stat-key' }, icon('clock'), 'Oldest'),
      h('span', { class: 'stat-value' }, oldest ? relative(oldest) : '—'),
      h('span', { class: 'stat-sub' }, oldest ? 'snapshot images use disk — prune what you no longer need' : 'nothing captured yet')
    )
  );
}

function renderRows(snaps) {
  $('snap-count').textContent = num(snaps.length);

  if (!snaps.length) {
    render(
      body,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 6 },
          emptyState({
            icon: 'camera',
            title: 'No snapshots yet',
            sub: 'Capture one before an upgrade and you can put the container back exactly as it was.',
            action: h('button', { class: 'btn sm', onclick: openCapture }, 'Capture snapshot'),
          })
        )
      )
    );
    return;
  }

  render(
    body,
    ...snaps.map((s) =>
      h(
        'tr',
        {},
        h('td', { class: 'mono' }, s.container_name),
        h(
          'td',
          {},
          h(
            'button',
            { class: 'tag-btn', 'data-tip': 'Copy tag', onclick: () => copyText(s.snapshot_tag, 'Tag copied') },
            h('span', { class: 'chip' }, s.snapshot_tag),
            icon('copy')
          )
        ),
        // Older rows can carry an empty image: the previous UI read the field
        // from the wrong level of the graph payload and stored "" for every
        // snapshot. Say so rather than render a blank cell.
        h('td', { class: 'mono truncate', style: { maxWidth: '200px' }, title: s.original_image || '' }, s.original_image || h('span', { class: 'faint' }, 'not recorded')),
        h('td', { class: 'truncate', style: { maxWidth: '240px' }, title: s.description || '' }, s.description || '—'),
        h('td', {}, h('time', { class: 'js-ts', datetime: s.created_at, title: s.created_at }, relative(s.created_at))),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Restore', 'aria-label': `Restore ${s.snapshot_tag}`, onclick: () => openRestore(s) }, icon('rotate-ccw')),
            h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Delete', 'aria-label': `Delete ${s.snapshot_tag}`, onclick: () => remove(s) }, icon('trash-2'))
          )
        )
      )
    )
  );
}

/* =======================================================================
   Capture
   ======================================================================= */

async function openCapture() {
  $('capture-form').reset();
  $('c-hint').textContent = '';
  const sel = $('c-container');
  render(sel, h('option', { value: '' }, 'Loading containers…'));
  openModal(captureModal);

  try {
    const graph = await get('/docker/graph');
    const containers = (graph.nodes || []).filter((n) => n.kind === 'container');

    if (!containers.length) {
      render(sel, h('option', { value: '' }, 'No containers found'));
      return;
    }

    render(
      sel,
      ...containers.map((c) =>
        h(
          'option',
          {
            value: c.data?.full_id || c.id.replace(/^container:/, ''),
            dataset: { name: c.label, image: c.data?.image || '' },
          },
          `${c.label}${c.data?.state ? ` · ${c.data.state}` : ''}`
        )
      )
    );
    syncHint();
  } catch (e) {
    render(sel, h('option', { value: '' }, "Couldn't load containers"));
    reportError(e, "Couldn't load containers");
  }
}

function syncHint() {
  const opt = $('c-container').selectedOptions[0];
  $('c-hint').textContent = opt?.dataset.image ? `Image: ${opt.dataset.image}` : '';
}

$('c-container').addEventListener('change', syncHint);
document.getElementById('new-btn').addEventListener('click', openCapture);

$('capture-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const opt = $('c-container').selectedOptions[0];
  if (!opt?.value) {
    toast('warn', 'Pick a container first');
    return;
  }

  await withLoading($('capture-save'), async () => {
    const res = await post('/docker/snapshots', {
      container_id: opt.value,
      container_name: opt.dataset.name,
      image: opt.dataset.image || '',
      description: $('c-desc').value.trim() || null,
    });
    closeModal(captureModal);
    toast('ok', `Snapshot captured`, res.snapshot_tag);
    await load();
  }, { errorTitle: "Couldn't capture the snapshot" });
});

/* =======================================================================
   Restore
   ======================================================================= */

function openRestore(s) {
  restoring = s;
  $('restore-form').reset();
  $('restore-desc').textContent = `${s.snapshot_tag} — captured from ${s.container_name} ${relative(s.created_at)}.`;
  $('r-name').value = `${s.container_name}-restored`;
  openModal(restoreModal);
}

$('restore-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('r-name').value.trim();
  if (!name) return;

  await withLoading($('restore-save'), async () => {
    const res = await post(`/docker/snapshots/${restoring.id}/restore`, { name });
    closeModal(restoreModal);
    toast('ok', `Restored as ${name}`, res.container_id ? `Container ${shortId(res.container_id)}` : undefined);
  }, { errorTitle: "Couldn't restore the snapshot" });
});

/* =======================================================================
   Delete
   ======================================================================= */

async function remove(s) {
  const ok = await confirm({
    title: 'Delete this snapshot?',
    message: `${s.snapshot_tag} and its image are removed from the host. Containers already restored from it are unaffected.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;
  try {
    await del(`/docker/snapshots/${s.id}`);
    toast('ok', 'Snapshot deleted');
    await load();
  } catch (e) {
    reportError(e, "Couldn't delete the snapshot");
  }
}

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  try {
    const data = await get('/docker/snapshots/data');
    const snaps = data.snapshots || [];
    renderTiles(snaps);
    renderRows(snaps);
  } catch (e) {
    reportError(e, "Couldn't load snapshots");
    render(body, emptyRow(6, 'Failed to load.'));
  }
}

render(body, ...skeletonRows(6, 3));
load();
