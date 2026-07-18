/* Component behaviour — toasts, modals, drawers, menus, confirm, tabs.
 *
 * Pairs with components.css; the class names are the contract between them.
 *
 * The `h()` helper here exists for a security reason, not a convenience one.
 * The old frontend built rows by concatenating API strings into innerHTML —
 * container names, image tags, log lines, firewall comments. That is an XSS
 * sink fed by anything that can get a string into the Docker daemon or the
 * database. Everything in the rewrite builds DOM through h(), which assigns
 * text via textContent, so escaping is structural rather than remembered.
 */

import { ApiError } from './api.js';

/* =======================================================================
   DOM construction
   ======================================================================= */

/**
 * Create an element.
 *   h('div', { class: 'card' }, h('h2', {}, 'Title'), 'text')
 *
 * Strings become text nodes — never markup. Attributes starting with "on" are
 * bound as listeners; `dataset` and `style` accept objects.
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') applyStyle(el, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  return el;
}

/**
 * Apply a style object.
 *
 * Custom properties have to go through setProperty: a CSSStyleDeclaration is
 * not a plain object, and `style['--x'] = v` (which is what Object.assign does)
 * is silently dropped — no error, no warning, no style. That bug shipped in the
 * accent picker, where every swatch set `--swatch` this way and therefore fell
 * back to the current accent, so all five swatches rendered the same colour.
 */
function applyStyle(el, styles) {
  for (const [prop, value] of Object.entries(styles)) {
    if (value == null) continue;
    if (prop.startsWith('--')) el.style.setProperty(prop, String(value));
    else el.style[prop] = value;
  }
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** An icon from the sprite. Always aria-hidden: name the *control*, not the glyph. */
export function icon(name, { size = 16, cls = '' } = {}) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `icon${size === 20 ? ' icon-20' : size === 24 ? ' icon-24' : ''}${cls ? ` ${cls}` : ''}`);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `/static/icons/sprite.svg#${name}`);
  svg.append(use);
  return svg;
}

/** Replace an element's children in one shot. */
export function render(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

/** A status pill. `status` is one of ok/warn/down/idle/info/acc. */
export function pill(status, label, { pulse = false } = {}) {
  const cls = ['pill', status, pulse ? 'pulse' : ''].filter(Boolean).join(' ');
  return h('span', { class: cls }, label);
}

/* =======================================================================
   Toasts
   ======================================================================= */

let toastStack = null;

function stack() {
  if (!toastStack) {
    toastStack = document.querySelector('.toast-stack');
    if (!toastStack) {
      // aria-live so a screen reader hears the outcome of an action it can't see.
      toastStack = h('div', { class: 'toast-stack', role: 'status', 'aria-live': 'polite' });
      document.body.append(toastStack);
    }
  }
  return toastStack;
}

const TOAST_ICON = { ok: 'circle-check', error: 'circle-x', warn: 'triangle-alert', info: 'info' };

/**
 * @param {'ok'|'error'|'warn'|'info'} kind
 * @param {string} title
 * @param {string} [message]
 */
export function toast(kind, title, message, { timeout } = {}) {
  const el = h(
    'div',
    { class: `toast ${kind}` },
    icon(TOAST_ICON[kind] || 'info', { cls: 'toast-icon' }),
    h('div', { class: 'toast-content' }, h('div', { class: 'toast-title' }, title), message ? h('div', { class: 'toast-msg' }, message) : null),
    h('button', { class: 'toast-close icon-btn', 'aria-label': 'Dismiss', onclick: () => close() }, icon('x'))
  );

  let timer;
  function close() {
    if (!el.isConnected) return;
    clearTimeout(timer);
    el.classList.add('is-closing');
    el.addEventListener('animationend', () => el.remove(), { once: true });
    // Reduced motion kills the animation, so animationend may never fire.
    setTimeout(() => el.remove(), 400);
  }

  stack().append(el);
  // Errors stay until dismissed: an operator who looked away must not lose the
  // only account of what went wrong. Successes are self-evident and expire.
  const ms = timeout ?? (kind === 'error' ? 0 : 4500);
  if (ms > 0) timer = setTimeout(close, ms);
  return close;
}

export const toastOk = (t, m) => toast('ok', t, m);
export const toastErr = (t, m) => toast('error', t, m);

/**
 * Report a thrown error to the user. Keeps every catch block one line, and
 * routes "capability absent" away from the red-alarm treatment.
 */
export function reportError(err, fallbackTitle = "That didn't work") {
  if (err instanceof ApiError) {
    if (err.isAuth) return; // we are already navigating to /login
    toast(err.isUnavailable ? 'warn' : 'error', fallbackTitle, err.message);
  } else {
    console.error(err);
    toast('error', fallbackTitle, err?.message || String(err));
  }
}

/* =======================================================================
   Button loading state
   ======================================================================= */

export function setLoading(btn, on) {
  if (!btn) return;
  btn.classList.toggle('is-loading', !!on);
  btn.disabled = !!on;
}

/**
 * Run an async action with the button spinning and errors reported.
 * Guarantees the button is re-enabled even if the action throws.
 */
export async function withLoading(btn, fn, { errorTitle } = {}) {
  setLoading(btn, true);
  try {
    return await fn();
  } catch (e) {
    reportError(e, errorTitle);
    throw e;
  } finally {
    setLoading(btn, false);
  }
}

/* =======================================================================
   Scroll lock — freeze the page behind an overlay

   The app's scrollport is `.main`, not the document (see shell.css). A native
   modal <dialog> and a drawer both leave that scrollport free to scroll, so the
   page slides behind the overlay and exposes the empty space below the content.
   Every overlay locks `.main` while it is open; the count keeps nested overlays
   (a confirm on top of a drawer) from unlocking early.
   ======================================================================= */

let scrollLocks = 0;
let savedPadRight = '';

/* `.main` on a shell page; the document elsewhere. The standalone pages (login,
   status) have no `.main`, so locking used to be a no-op there and their modals
   scrolled the page behind them. */
const scrollport = () => document.querySelector('.main') || document.documentElement;

export function lockScroll() {
  const el = scrollport();
  if (!el) return;
  if (scrollLocks === 0) {
    // Reserve the width the scrollbar occupied so the content doesn't jump right
    // when it disappears.
    const gutter = el.offsetWidth - el.clientWidth;
    savedPadRight = el.style.paddingRight;
    if (gutter > 0) el.style.paddingRight = `${gutter}px`;
    el.style.overflow = 'hidden';
  }
  scrollLocks++;
}

export function unlockScroll() {
  const el = scrollport();
  if (!el) return;
  scrollLocks = Math.max(0, scrollLocks - 1);
  if (scrollLocks === 0) {
    el.style.overflow = '';
    el.style.paddingRight = savedPadRight;
  }
}

/* =======================================================================
   Modal — thin wrapper over <dialog>
   ======================================================================= */

/**
 * Open a <dialog class="modal">. The platform gives us the top layer, focus
 * trap, focus restore and Escape; we add the exit animation and a backdrop
 * click, and that is all this needs to be.
 */
export function openModal(dialog, { onClose } = {}) {
  if (!dialog.dataset.wired) {
    dialog.dataset.wired = '1';

    dialog.addEventListener('click', (e) => {
      // A click on the dialog element itself is the backdrop: the content sits
      // in children, so this never fires for clicks inside the panel.
      if (e.target === dialog) closeModal(dialog);
    });

    dialog.addEventListener('cancel', (e) => {
      e.preventDefault(); // take over so Escape gets the same exit animation
      closeModal(dialog);
    });

    for (const btn of dialog.querySelectorAll('[data-close]')) {
      btn.addEventListener('click', () => closeModal(dialog));
    }
  }

  dialog._onClose = onClose;
  dialog.classList.remove('is-closing');
  if (!dialog.open) {
    dialog.showModal();
    lockScroll();
  }

  // Focus the first meaningful control, not the close button.
  const target = dialog.querySelector('[data-autofocus]') || dialog.querySelector('.modal-body input, .modal-body select, .modal-body textarea');
  target?.focus();
  return dialog;
}

export function closeModal(dialog) {
  if (!dialog?.open) return;
  dialog.classList.add('is-closing');
  const done = () => {
    dialog.classList.remove('is-closing');
    dialog.close();
    unlockScroll();
    dialog._onClose?.();
  };
  let fired = false;
  dialog.addEventListener(
    'animationend',
    () => {
      if (!fired) {
        fired = true;
        done();
      }
    },
    { once: true }
  );
  setTimeout(() => {
    if (!fired) {
      fired = true;
      done();
    }
  }, 300);
}

/**
 * A promise-based confirm dialog. Destructive actions get `danger: true`,
 * which colors the confirm button and is the only visual difference — the
 * wording is what should carry the weight.
 *
 * `detail` is an optional node rendered under the message, for when the thing
 * being confirmed has an exact form worth reading before you agree to it (a
 * command line, a path). It sits outside the `<p>` so it can be block content.
 *
 * @returns {Promise<boolean>}
 */
export function confirm({ title, message, detail = null, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
      closeModal(dialog);
      setTimeout(() => dialog.remove(), 400);
    };

    const confirmBtn = h('button', { class: `btn ${danger ? 'danger' : ''}`, 'data-autofocus': '', onclick: () => finish(true) }, confirmLabel);

    const dialog = h(
      'dialog',
      { class: 'modal', style: { width: 'min(440px, calc(100vw - 32px))' } },
      h('div', { class: 'modal-header' }, h('span', { class: 'modal-title' }, title)),
      h('div', { class: 'modal-body' }, h('p', { class: 'modal-desc' }, message), detail),
      h('div', { class: 'modal-footer' }, h('button', { class: 'btn quiet', onclick: () => finish(false) }, cancelLabel), confirmBtn)
    );

    document.body.append(dialog);
    openModal(dialog, { onClose: () => finish(false) });
    confirmBtn.focus();
  });
}

/* =======================================================================
   Drawer
   ======================================================================= */

export function openDrawer(drawer) {
  const wasOpen = drawer.classList.contains('is-open');
  let scrim = drawer.previousElementSibling;
  if (!scrim?.classList.contains('drawer-scrim')) {
    scrim = h('div', { class: 'drawer-scrim', onclick: () => closeDrawer(drawer) });
    drawer.before(scrim);
  }
  drawer.classList.add('is-open');
  scrim.classList.add('is-open');
  drawer.setAttribute('aria-hidden', 'false');

  drawer._onKey = (e) => {
    if (e.key === 'Escape') closeDrawer(drawer);
  };
  document.addEventListener('keydown', drawer._onKey);

  // Remember who opened it so focus can go home on close.
  drawer._restore = document.activeElement;
  (drawer.querySelector('[data-autofocus]') || drawer.querySelector('.drawer-header button') || drawer).focus?.();

  if (!wasOpen) lockScroll();
}

export function closeDrawer(drawer) {
  const wasOpen = drawer.classList.contains('is-open');
  drawer.classList.remove('is-open');
  drawer.previousElementSibling?.classList.remove('is-open');
  drawer.setAttribute('aria-hidden', 'true');
  if (drawer._onKey) document.removeEventListener('keydown', drawer._onKey);
  drawer._restore?.focus?.();
  if (wasOpen) unlockScroll();
}

/* =======================================================================
   Menu (dropdown)
   ======================================================================= */

let openMenu = null;

/**
 * Wire a trigger button to a .menu element.
 * The menu is positioned in the viewport by the caller's CSS or, by default,
 * anchored under the trigger.
 */
export function wireMenu(trigger, menu, { align = 'start', placement = 'bottom' } = {}) {
  trigger.setAttribute('aria-expanded', 'false');
  trigger.setAttribute('aria-haspopup', 'true');

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    if (menu.classList.contains('is-open')) hideMenu(menu, trigger);
    else showMenu(menu, trigger, { align, placement });
  });

  menu.addEventListener('click', (e) => {
    // Any command closes the menu; a disabled item is not a command.
    if (e.target.closest('.menu-item:not(:disabled)')) hideMenu(menu, trigger);
  });

  menu.addEventListener('keydown', (e) => {
    const items = [...menu.querySelectorAll('.menu-item:not(:disabled)')];
    const i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      items[(i + 1) % items.length]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      items[(i - 1 + items.length) % items.length]?.focus();
    } else if (e.key === 'Escape') {
      hideMenu(menu, trigger);
      trigger.focus();
    }
  });
}

export function showMenu(menu, trigger, { align = 'start', placement = 'bottom' } = {}) {
  if (openMenu) hideMenu(openMenu.menu, openMenu.trigger);

  const r = trigger.getBoundingClientRect();
  menu.style.position = 'fixed';
  menu.classList.add('is-open');

  // Measure after showing, then flip if we'd overflow the viewport.
  const m = menu.getBoundingClientRect();
  let top = placement === 'top' ? r.top - m.height - 6 : r.bottom + 6;
  if (top + m.height > window.innerHeight - 8) top = r.top - m.height - 6;
  if (top < 8) top = 8;

  let left = align === 'end' ? r.right - m.width : r.left;
  left = Math.min(Math.max(8, left), window.innerWidth - m.width - 8);

  menu.style.top = `${top}px`;
  menu.style.left = `${left}px`;

  trigger.setAttribute('aria-expanded', 'true');
  openMenu = { menu, trigger };
  menu.querySelector('.menu-item:not(:disabled)')?.focus();
}

export function hideMenu(menu, trigger) {
  menu.classList.remove('is-open');
  trigger?.setAttribute('aria-expanded', 'false');
  if (openMenu?.menu === menu) openMenu = null;
}

document.addEventListener('click', () => {
  if (openMenu) hideMenu(openMenu.menu, openMenu.trigger);
});

window.addEventListener('resize', () => {
  if (openMenu) hideMenu(openMenu.menu, openMenu.trigger);
});

/* =======================================================================
   Segmented control / tabs
   ======================================================================= */

/**
 * Wire a .segmented or .tabs group. Buttons carry `data-value`; the handler
 * gets the selected value. Arrow keys move between options (they are a single
 * control, so they take one tab stop).
 *
 * @returns {{value: () => string, select: (v: string) => void}}
 */
export function wireSegmented(root, onSelect) {
  const buttons = () => [...root.querySelectorAll('button')];

  function select(value, fire = true) {
    for (const b of buttons()) {
      const on = b.dataset.value === value;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
    }
    if (fire) onSelect?.(value);
  }

  root.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (b && b.dataset.value !== current()) select(b.dataset.value);
  });

  root.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const bs = buttons();
    const i = bs.findIndex((b) => b.getAttribute('aria-selected') === 'true');
    const next = bs[(i + (e.key === 'ArrowRight' ? 1 : -1) + bs.length) % bs.length];
    select(next.dataset.value);
    next.focus();
  });

  function current() {
    return root.querySelector('[aria-selected="true"]')?.dataset.value;
  }

  for (const b of buttons()) b.tabIndex = b.getAttribute('aria-selected') === 'true' ? 0 : -1;
  return { value: current, select };
}

/* =======================================================================
   Empty / degraded states
   ======================================================================= */

/**
 * @param {{icon?: string, title: string, sub?: string, action?: HTMLElement, degraded?: boolean}} o
 */
export function emptyState({ icon: iconName = 'inbox', title, sub, action, degraded = false }) {
  return h(
    'div',
    { class: `empty${degraded ? ' degraded' : ''}` },
    h('span', { class: 'empty-icon' }, icon(degraded ? 'triangle-alert' : iconName, { size: 20 })),
    h('span', { class: 'empty-title' }, title),
    sub ? h('span', { class: 'empty-sub' }, sub) : null,
    action || null
  );
}

/** An empty state sized to drop into a table body. */
export function emptyRow(colspan, message) {
  return h('tr', { class: 'table-empty' }, h('td', { colspan }, message));
}

/** Skeleton rows for a table that is still loading. */
export function skeletonRows(colspan, rows = 4) {
  return Array.from({ length: rows }, () =>
    h('tr', {}, h('td', { colspan }, h('div', { class: 'skel skel-line', style: { width: `${45 + Math.random() * 45}%` } })))
  );
}

/* =======================================================================
   Diff view (§11.2)
   ======================================================================= */

/**
 * Render a server-computed line diff (see `diffutil.rs`). `lines` is an array of
 * `{ tag: 'ctx'|'add'|'del', text }`. The gutter sign and the row colour both
 * encode the tag, so meaning is never carried by colour alone.
 *
 * The server does the diffing; this only paints it — deliberately, so the browser
 * carries no diff library and the two sides cannot disagree about what changed.
 */
export function diffView(lines, { emptyLabel = 'No changes.' } = {}) {
  if (!lines || !lines.length) {
    return h('div', { class: 'diff-view is-empty' }, emptyLabel);
  }
  const SIGN = { add: '+', del: '−', ctx: ' ' };
  return h(
    'div',
    { class: 'diff-view', role: 'group', 'aria-label': 'Pending changes' },
    ...lines.map((l) =>
      h(
        'div',
        { class: `diff-line ${l.tag}` },
        h('span', { class: 'diff-sign', 'aria-hidden': 'true' }, SIGN[l.tag] ?? ' '),
        h('span', { class: 'diff-text' }, l.text)
      )
    )
  );
}

/** Copy text, with the outcome reported — a silent copy button is untrustworthy. */
export async function copyText(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast('ok', label);
  } catch {
    toast('warn', "Couldn't copy", 'Your browser blocked clipboard access. Select the text and copy it manually.');
  }
}
