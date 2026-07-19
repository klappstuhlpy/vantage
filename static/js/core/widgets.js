/* The home dashboard's widget runtime.
 *
 * A widget is a self-contained card that owns its own data. It declares what it
 * needs; the runtime owns the grid, edit mode, sizing and persistence, and no
 * widget ever knows about another. That separation is what makes the dashboard
 * modular rather than a page that happens to have boxes on it.
 *
 * Contract — a widget definition:
 *   {
 *     id:    'cpu',                       stable; it is the persistence key
 *     title: 'CPU',
 *     icon:  'cpu',
 *     size:  's' | 'm' | 'l',             default span
 *     sizes: ['s','m'],                   sizes this widget supports
 *     load:  async (ctx) => data,         fetch; throw ApiError to signal failure
 *     render:(el, data, ctx) => void,     paint into the card body
 *     topic: 'metrics',                   optional live topic; re-renders on push
 *     needs: 'docker',                    optional capability gate (see CAPS)
 *   }
 *
 * Layout is dual-persisted: localStorage for instant load, server for
 * cross-device sync. The server blob carries a `widgets` key whose shape is the
 * same versioned format localStorage uses.
 */

import { h, icon, render, emptyState, toast } from './ui.js';
import { ApiError } from './api.js';
import * as live from './live.js';
import * as prefs from './prefs.js';

const STORE_KEY = 'vantage.dashboard.v1';
const SIZES = { s: 3, m: 6, l: 12 };

const registry = new Map();
let layout = [];
let editing = false;
let dragging = false;
let gridEl, ctx;

/* =======================================================================
   Persistence
   ======================================================================= */

function loadLayout(defaults) {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return structuredClone(defaults);
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.widgets)) return structuredClone(defaults);
    // Drop widgets that no longer exist in the build — a stale layout must
    // never be able to break the page after an upgrade.
    return parsed.widgets.filter((w) => registry.has(w.id));
  } catch {
    return structuredClone(defaults);
  }
}

function saveLayout() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ v: 1, widgets: layout }));
  } catch {
    toast('warn', "Couldn't save your layout", 'Browser storage is unavailable, so this arrangement lasts until you reload.');
  }
  prefs.save({ widgets: layout });
}

/* =======================================================================
   Card rendering
   ======================================================================= */

function cardFor(entry) {
  const def = registry.get(entry.id);
  const body = h('div', { class: 'widget-body' });

  const card = h(
    'article',
    {
      class: 'widget card',
      dataset: { id: entry.id, size: entry.size || def.size || 'm' },
      'aria-labelledby': `w-${entry.id}-title`,
    },
    h(
      'header',
      { class: 'widget-head' },
      icon(def.icon || 'grid-2x2'),
      h('h2', { class: 'widget-title', id: `w-${entry.id}-title` }, def.title),
      h('div', { class: 'widget-tools' })
    ),
    body
  );

  const tools = card.querySelector('.widget-tools');

  if (def.href) {
    tools.append(
      h('a', { class: 'btn sm ghost icon-only', href: def.href, 'aria-label': `Open ${def.title}`, 'data-tip': 'Open page' }, icon('arrow-right'))
    );
  }

  // Edit-mode controls. Built once and hidden, rather than rebuilt on every
  // mode switch — the drag handle must survive a re-render mid-drag.
  const sizes = def.sizes || ['s', 'm', 'l'];
  const editTools = h(
    'div',
    { class: 'widget-edit-tools' },
    sizes.length > 1
      ? h(
          'div',
          { class: 'segmented', role: 'group', 'aria-label': `${def.title} size` },
          ...sizes.map((s) =>
            h(
              'button',
              {
                'data-value': s,
                'aria-selected': String((entry.size || def.size) === s),
                onclick: () => {
                  entry.size = s;
                  card.dataset.size = s;
                  for (const b of card.querySelectorAll('.widget-edit-tools .segmented button')) {
                    b.setAttribute('aria-selected', String(b.dataset.value === s));
                  }
                  saveLayout();
                },
              },
              s.toUpperCase()
            )
          )
        )
      : null,
    h(
      'button',
      {
        class: 'btn sm ghost icon-only',
        'aria-label': `Remove ${def.title}`,
        'data-tip': 'Remove',
        onclick: () => removeWidget(entry.id),
      },
      icon('x')
    ),
    h('span', { class: 'widget-grip', 'aria-hidden': 'true', title: 'Drag to reorder' }, icon('grip-vertical'))
  );
  card.querySelector('.widget-head').append(editTools);

  paint(card, body, def, entry);
  return card;
}

async function paint(card, body, def, entry) {
  // Skeleton first: a widget that fetches must never render as an empty box.
  render(body, h('div', { class: 'skel skel-line', style: { width: '60%' } }), h('div', { class: 'skel skel-line', style: { width: '85%', marginTop: '8px' } }));

  if (def.needs && !ctx.caps[def.needs]) {
    render(body, emptyState({ title: CAP_LABEL[def.needs] || 'Unavailable', sub: CAP_SUB[def.needs], degraded: true }));
    return;
  }

  try {
    const data = await def.load(ctx);
    render(body);
    def.render(body, data, ctx);
  } catch (e) {
    // A capability that isn't there is a degraded state, not an error: the
    // backend answering 503 for "no Docker socket" is it working correctly.
    if (e instanceof ApiError && e.isUnavailable) {
      render(body, emptyState({ title: 'Not available', sub: e.message, degraded: true }));
    } else {
      render(
        body,
        emptyState({
          icon: 'circle-alert',
          title: "Couldn't load",
          sub: e?.message || String(e),
          action: h('button', { class: 'btn sm quiet', onclick: () => paint(card, body, def, entry) }, 'Retry'),
        })
      );
    }
  }
}

const CAP_LABEL = { docker: "Docker isn't reachable", firewall: 'No firewall backend', cloudflare: 'Cloudflare not configured' };
const CAP_SUB = {
  docker: 'The Docker socket did not answer, so container widgets have nothing to show.',
  firewall: 'Vantage did not detect nftables, ufw or iptables on this host.',
  cloudflare: 'Set cloudflare.api_token and cloudflare.zone_id in config.json to enable zone analytics.',
};

/* =======================================================================
   Grid
   ======================================================================= */

function renderGrid() {
  // Never re-render into a stuck drag state. `is-sorting` suppresses the wiggle
  // (it frees the transform channel for the FLIP), so if a drag ever ended
  // without clearing it, every widget would render frozen — which is exactly
  // what a Reset mid-edit surfaced. Clearing it here makes a re-render the
  // guaranteed way back to a clean, wiggling grid.
  gridEl.classList.remove('is-sorting');
  dragging = false;
  render(gridEl);
  if (!layout.length) {
    gridEl.append(
      emptyState({
        icon: 'layout-grid',
        title: 'Your dashboard is empty',
        sub: 'Add widgets to build the view you want to land on.',
        action: h('button', { class: 'btn', onclick: openGallery }, 'Add widgets'),
      })
    );
    return;
  }
  for (const entry of layout) {
    if (!registry.has(entry.id)) continue;
    gridEl.append(cardFor(entry));
  }
  wireDrag();
}

function removeWidget(id) {
  layout = layout.filter((w) => w.id !== id);
  saveLayout();
  renderGrid();
}

function addWidget(id) {
  if (layout.some((w) => w.id === id)) return;
  const def = registry.get(id);
  layout.push({ id, size: def.size || 'm' });
  saveLayout();
  renderGrid();
  gridEl.querySelector(`[data-id="${id}"]`)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* =======================================================================
   Drag to reorder — pointer events, no library
   -----------------------------------------------------------------------
   The card is lifted and tracks the pointer directly (translate recomputed
   every frame against its live layout box, so a reorder mid-drag never makes
   it jump). It stays in flow, leaving a moving gap where it belongs; the
   siblings slide into their new places with a FLIP animation rather than
   snapping. On release it eases from the pointer back into its slot.
   ======================================================================= */

const DRAG_EASE = 'cubic-bezier(0.2, 0.9, 0.3, 1)';

function wireDrag() {
  if (!editing) return;

  for (const card of gridEl.querySelectorAll('.widget')) {
    const grip = card.querySelector('.widget-grip');
    if (!grip) continue;
    grip.addEventListener('pointerdown', (e) => startDrag(e, card, grip));
  }
}

function startDrag(e, card, grip) {
  if (e.button > 0) return; // primary button / touch / pen only
  if (dragging) return; // ignore a second pointer landing mid-drag
  e.preventDefault();

  dragging = true;
  const startIndex = [...gridEl.children].indexOf(card);
  const rect = card.getBoundingClientRect();
  // Where inside the card the grab landed, so the card doesn't snap its corner
  // to the pointer.
  const offX = e.clientX - rect.left;
  const offY = e.clientY - rect.top;

  let lastX = e.clientX;
  let lastY = e.clientY;
  let raf = 0;
  let done = false;

  card.classList.add('is-dragging');
  // Turn the whole grid's wiggle off for the duration: the wiggle drives
  // `transform`, and the FLIP below needs `transform` free to animate.
  gridEl.classList.add('is-sorting');
  // The lifted card is not a hit target for the whole drag. This used to be
  // toggled off and on around each `elementFromPoint` call — two style writes
  // and a forced hit-test rebuild on *every pointermove*, which on a 1000Hz
  // mouse is dozens per frame. Pointer capture keeps delivering move/up to the
  // grip regardless of `pointer-events`, so setting it once is equivalent.
  card.style.pointerEvents = 'none';
  grip.setPointerCapture(e.pointerId);

  /* Decide where the card belongs for a pointer at (x, y), and move it there.
     Which side of `over` to land on is read in grid order: above its row → in
     front; on its row → the nearer horizontal half. The insert goes against a
     *stable reference node* and bails when the card is already there — without
     that bail the pointer sitting on `over` flips the answer every frame and
     the widgets vibrate in place. */
  const reorder = (x, y) => {
    const over = document.elementFromPoint(x, y)?.closest('.widget');
    if (!over || over === card || over.parentElement !== gridEl) return;

    const r = over.getBoundingClientRect();
    let before;
    if (y < r.top) before = true;
    else if (y > r.bottom) before = false;
    else before = x < r.left + r.width / 2;

    const ref = before ? over : over.nextElementSibling;
    if (ref === card || ref === card.nextElementSibling) return; // already in place

    flipSiblings(card, () => gridEl.insertBefore(card, ref));
  };

  /* One frame does the whole job: reorder against the latest pointer position,
     then re-seat the card under it. Everything that reads layout is confined to
     this callback, so a burst of pointermove events costs one layout pass
     instead of one per event — pointermove itself now only records coordinates. */
  const frame = () => {
    raf = 0;
    if (done) return;
    reorder(lastX, lastY);
    // Measured with its own transform cleared, so the offset is always against
    // its real slot — that is what keeps it glued to the cursor even as
    // reordering shifts that slot.
    card.style.transform = 'none';
    const base = card.getBoundingClientRect();
    const tx = lastX - offX - base.left;
    const ty = lastY - offY - base.top;
    card.style.transform = `translate(${tx}px, ${ty}px) scale(1.03)`;
  };

  const onMove = (ev) => {
    lastX = ev.clientX;
    lastY = ev.clientY;
    if (!raf) raf = requestAnimationFrame(frame);
  };

  /* Idempotent, and reachable from four events. A drag that ends without this
     running leaves `dragging` true and `is-sorting` on the grid — the grid then
     refuses every later drag and renders frozen, which is what "randomly gets
     stuck" looked like. `lostpointercapture` is the one that closes the gap:
     it fires whenever the capture goes away for a reason we did not initiate
     (the grip being removed from the DOM, the browser revoking it), where
     pointerup/pointercancel never arrive at all. */
  const finish = () => {
    if (done) return;
    done = true;
    grip.removeEventListener('pointermove', onMove);
    grip.removeEventListener('pointerup', finish);
    grip.removeEventListener('pointercancel', finish);
    grip.removeEventListener('lostpointercapture', finish);
    if (raf) cancelAnimationFrame(raf);

    settleDropped(card);

    const endIndex = [...gridEl.children].indexOf(card);
    if (endIndex !== startIndex) {
      layout = [...gridEl.children].map((el) => layout.find((w) => w.id === el.dataset.id)).filter(Boolean);
      saveLayout();
    }
  };

  grip.addEventListener('pointermove', onMove);
  grip.addEventListener('pointerup', finish);
  grip.addEventListener('pointercancel', finish);
  grip.addEventListener('lostpointercapture', finish);
}

/** FLIP: record where the siblings are, let `mutate` reorder the DOM, then
 *  animate each one from its old box to its new one so it slides. The dragged
 *  card is excluded — it is following the pointer, not the grid. */
function flipSiblings(dragged, mutate) {
  const sibs = [...gridEl.children].filter((el) => el !== dragged);
  // "First" is where each card *looks* right now, so an in-flight slide is
  // measured mid-flight and continues smoothly from there.
  const first = new Map(sibs.map((el) => [el, el.getBoundingClientRect()]));

  mutate();

  // "Last" must be the new slot with no transform applied. Reading it while a
  // previous FLIP was still animating (which is what this did) folded that
  // leftover transform into the delta, so every reorder during a slide
  // compounded the error and cards drifted away from their slots and sat there
  // looking stuck. Clearing is one write pass and reading is one read pass, so
  // the whole reorder costs a single layout instead of one per card.
  for (const el of sibs) {
    el.style.transition = 'none';
    el.style.transform = 'none';
  }
  const last = new Map(sibs.map((el) => [el, el.getBoundingClientRect()]));

  const moved = [];
  for (const el of sibs) {
    const a = first.get(el);
    const b = last.get(el);
    const dx = a.left - b.left;
    const dy = a.top - b.top;
    if (!dx && !dy) {
      el.style.transform = '';
      continue;
    }
    el.style.transform = `translate(${dx}px, ${dy}px)`;
    moved.push(el);
  }

  if (!moved.length) return;
  gridEl.offsetWidth; // one flush for the whole batch, not one per card
  for (const el of moved) {
    el.style.transition = `transform var(--dur-mid) ${DRAG_EASE}`;
    el.style.transform = '';
  }
}

/** Ease the lifted card from wherever the pointer left it back into its slot. */
function settleDropped(card) {
  card.style.transition = `transform var(--dur-mid) ${DRAG_EASE}`;
  card.style.transform = 'translate(0px, 0px) scale(1)';

  const cleanup = (ev) => {
    // `transitionend` bubbles: a child finishing any transition would otherwise
    // end the settle early and snap the card home mid-flight.
    if (ev && ev.target !== card) return;
    card.removeEventListener('transitionend', cleanup);
    card.classList.remove('is-dragging');
    gridEl.classList.remove('is-sorting'); // wiggle resumes
    dragging = false;
    card.style.transition = '';
    card.style.transform = '';
    card.style.pointerEvents = '';
  };
  card.addEventListener('transitionend', cleanup);
  // Belt and braces: if the card was already home there is no transition to end.
  setTimeout(cleanup, 320);
}

/* =======================================================================
   Edit mode + gallery
   ======================================================================= */

function setEditing(on) {
  editing = on;
  document.body.classList.toggle('is-editing-dashboard', on);
  document.getElementById('edit-toggle')?.setAttribute('aria-pressed', String(on));
  const label = document.getElementById('edit-toggle-label');
  if (label) label.textContent = on ? 'Done' : 'Edit layout';
  document.getElementById('gallery-btn')?.toggleAttribute('hidden', !on);
  document.getElementById('reset-btn')?.toggleAttribute('hidden', !on);
  renderGrid();
}

function openGallery() {
  const list = h('div', { class: 'gallery-list' });

  for (const [id, def] of registry) {
    const on = layout.some((w) => w.id === id);
    list.append(
      h(
        'button',
        {
          class: `gallery-item${on ? ' is-added' : ''}`,
          onclick: (e) => {
            if (layout.some((w) => w.id === id)) removeWidget(id);
            else addWidget(id);
            const btn = e.currentTarget;
            const nowOn = layout.some((w) => w.id === id);
            btn.classList.toggle('is-added', nowOn);
            btn.querySelector('.gallery-check').replaceChildren(icon(nowOn ? 'check' : 'plus'));
          },
        },
        h('span', { class: 'gallery-icon' }, icon(def.icon || 'grid-2x2')),
        h('span', { class: 'gallery-text' }, h('span', { class: 'gallery-title' }, def.title), def.blurb ? h('span', { class: 'gallery-blurb' }, def.blurb) : null),
        h('span', { class: 'gallery-check' }, icon(on ? 'check' : 'plus'))
      )
    );
  }

  const dialog = h(
    'dialog',
    { class: 'modal' },
    h('div', { class: 'modal-header' }, h('span', { class: 'modal-title' }, 'Widgets'), h('button', { class: 'btn sm ghost icon-only', 'data-close': '', 'aria-label': 'Close' }, icon('x'))),
    h('div', { class: 'modal-body' }, list),
    h('div', { class: 'modal-footer' }, h('button', { class: 'btn quiet', 'data-close': '' }, 'Done'))
  );

  document.body.append(dialog);
  import('./ui.js').then(({ openModal }) => openModal(dialog, { onClose: () => dialog.remove() }));
}

/* =======================================================================
   Public API
   ======================================================================= */

export function register(def) {
  registry.set(def.id, def);
}

/**
 * @param {object} o
 * @param {HTMLElement} o.grid
 * @param {Array<{id: string, size?: string}>} o.defaults
 * @param {object} o.caps  capability flags from the server (docker, firewall, …)
 */
export function start({ grid, defaults, caps = {} }) {
  gridEl = grid;
  ctx = { caps };
  layout = loadLayout(defaults);
  renderGrid();

  prefs.load().then((remote) => {
    if (!remote?.widgets || !Array.isArray(remote.widgets)) return;
    const remoteValid = remote.widgets.filter((w) => registry.has(w.id));
    if (JSON.stringify(remoteValid) === JSON.stringify(layout)) return;
    layout = remoteValid;
    try { localStorage.setItem(STORE_KEY, JSON.stringify({ v: 1, widgets: layout })); } catch {}
    renderGrid();
  });

  document.getElementById('edit-toggle')?.addEventListener('click', () => setEditing(!editing));
  document.getElementById('gallery-btn')?.addEventListener('click', openGallery);
  document.getElementById('reset-btn')?.addEventListener('click', () => {
    layout = structuredClone(defaults);
    saveLayout();
    renderGrid();
    toast('ok', 'Layout reset');
  });

  // Live topics: one subscription per topic, re-painting only the widgets that
  // asked for it. A widget never opens its own socket.
  const topics = new Set([...registry.values()].filter((d) => d.topic).map((d) => d.topic));
  for (const topic of topics) {
    live.subscribe(topic, (data) => {
      for (const entry of layout) {
        const def = registry.get(entry.id);
        if (def?.topic !== topic || !def.onLive) continue;
        const card = gridEl.querySelector(`[data-id="${entry.id}"] .widget-body`);
        if (card) {
          try {
            def.onLive(card, data, ctx);
          } catch (e) {
            console.error(`widget "${entry.id}" live update failed`, e);
          }
        }
      }
    });
  }
}
