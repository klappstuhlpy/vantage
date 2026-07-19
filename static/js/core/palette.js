/* The command palette (Ctrl+K / Cmd+K).
 *
 * New UI over a backend that already shipped and had no frontend at all:
 * GET /spotlight/search?q= has been returning navigation targets, containers,
 * SSH keys, firewall rules and secret findings to nobody. This is the fastest
 * path to any of them.
 *
 * Results are server-ranked; this module owns the interaction — debounce,
 * keyboard navigation, grouping, and not letting a slow response overwrite a
 * newer one.
 */

import { get, withQuery } from './api.js';
import { h, icon, render, lockScroll, unlockScroll } from './ui.js';

/* Keyed by the `kind` field `spotlight.rs` actually emits — `navigate`, `ssh`,
 * `secret`, `firewall`, `container`, `script`. Anything else falls back to a
 * generic row, so a new backend kind degrades to "findable but unlabelled"
 * rather than breaking the palette. */
const KIND = {
  navigate: { icon: 'corner-down-right', group: 'Go to' },
  container: { icon: 'container', group: 'Containers' },
  script: { icon: 'square-terminal', group: 'Scripts' },
  firewall: { icon: 'brick-wall', group: 'Firewall rules' },
  ssh: { icon: 'key-round', group: 'SSH keys' },
  secret: { icon: 'triangle-alert', group: 'Secret findings' },
  database: { icon: 'database', group: 'Databases' },
};

let dialog, input, results, footer;
let items = [];
let active = 0;
let seq = 0; // guards against an older in-flight response landing last
let debounce;

function build() {
  input = h('input', {
    class: 'palette-input',
    type: 'text',
    placeholder: 'Search containers, routes, rules, pages…',
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': 'Search',
    'aria-controls': 'palette-results',
    'aria-expanded': 'true',
    role: 'combobox',
  });

  results = h('div', { class: 'palette-results', id: 'palette-results', role: 'listbox' });

  footer = h(
    'div',
    { class: 'palette-foot' },
    h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, '↑'), h('span', { class: 'kbd' }, '↓'), ' navigate'),
    h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, '↵'), ' open'),
    h('span', { class: 'hstack' }, h('span', { class: 'kbd' }, 'esc'), ' close')
  );

  dialog = h(
    'dialog',
    { class: 'palette', 'aria-label': 'Command palette' },
    h('div', { class: 'palette-input-wrap' }, icon('search', { size: 20 }), input),
    results,
    footer
  );

  document.body.append(dialog);

  input.addEventListener('input', () => {
    clearTimeout(debounce);
    // Short enough to feel instant, long enough that typing "postgres" is one
    // request rather than eight.
    debounce = setTimeout(() => search(input.value), 120);
  });

  input.addEventListener('keydown', onKey);

  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) close();
  });

  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    close();
  });

  // Fires on every close path (close(), backdrop, Esc) so the scroll lock that
  // open() took is always released exactly once.
  dialog.addEventListener('close', () => unlockScroll());
}

function onKey(e) {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    move(1);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    move(-1);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    choose(items[active]);
  } else if (e.key === 'Home') {
    e.preventDefault();
    active = 0;
    paint();
  } else if (e.key === 'End') {
    e.preventDefault();
    active = items.length - 1;
    paint();
  }
}

function move(delta) {
  if (!items.length) return;
  active = (active + delta + items.length) % items.length;
  paint();
}

function choose(item) {
  if (!item?.url) return;
  close();
  window.location.href = item.url;
}

/** Highlight the matched span without ever putting API text into innerHTML. */
function highlight(text, query) {
  const frag = document.createDocumentFragment();
  const q = query.trim();
  if (!q) {
    frag.append(text);
    return frag;
  }
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) {
    frag.append(text);
    return frag;
  }
  frag.append(text.slice(0, i), h('mark', {}, text.slice(i, i + q.length)), text.slice(i + q.length));
  return frag;
}

function paint() {
  const q = input.value;
  render(results);

  if (!items.length) {
    results.append(
      h(
        'div',
        { class: 'empty', style: { padding: 'var(--sp-6) var(--sp-4)' } },
        h('span', { class: 'empty-icon' }, icon('search', { size: 20 })),
        h('span', { class: 'empty-title' }, q.trim() ? 'Nothing matches' : 'Start typing'),
        h(
          'span',
          { class: 'empty-sub' },
          q.trim() ? `No container, route, rule or page matches “${q.trim()}”.` : 'Search across containers, proxy routes, firewall rules, SSH keys and every page.'
        )
      )
    );
    return;
  }

  let lastGroup = null;
  items.forEach((item, i) => {
    const meta = KIND[item.kind] || { icon: 'circle-dashed', group: 'Results' };
    if (meta.group !== lastGroup) {
      lastGroup = meta.group;
      results.append(h('div', { class: 'palette-group' }, meta.group));
    }

    const row = h(
      'button',
      {
        class: 'palette-item',
        role: 'option',
        'aria-selected': String(i === active),
        onclick: () => choose(item),
        onmousemove: () => {
          if (active !== i) {
            active = i;
            for (const [j, el] of [...results.querySelectorAll('.palette-item')].entries()) {
              el.setAttribute('aria-selected', String(j === active));
            }
          }
        },
      },
      h('span', { class: 'palette-item-icon' }, icon(meta.icon)),
      h(
        'span',
        { class: 'palette-item-text' },
        h('span', { class: 'palette-item-title' }, highlight(item.title || '', q)),
        item.subtitle ? h('span', { class: 'palette-item-sub' }, item.subtitle) : null
      ),
      i === active ? h('span', { class: 'kbd' }, '↵') : null
    );
    results.append(row);
  });

  results.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
}

async function search(q) {
  const mine = ++seq;
  try {
    const data = await get(withQuery('/spotlight/search', { q }));
    // A slower earlier request must not clobber a newer result set.
    if (mine !== seq) return;
    items = data?.items || [];
    active = 0;
    paint();
  } catch (e) {
    if (mine !== seq) return;
    items = [];
    paint();
    console.error('spotlight search failed', e);
  }
}

export function open(initial = '') {
  if (!dialog) build();
  if (dialog.open) return;
  input.value = initial;
  items = [];
  active = 0;
  paint();
  dialog.showModal();
  lockScroll();
  input.focus();
  // An empty query returns the nav targets — the palette is useful before you
  // type anything, which is what makes it a launcher and not just a search box.
  search(initial);
}

export function close() {
  if (!dialog?.open) return;
  dialog.close();
}

/** Global shortcuts. Ctrl/Cmd+K anywhere; "/" only outside a text field. */
export function install() {
  document.addEventListener('keydown', (e) => {
    const k = e.key.toLowerCase();
    if ((e.ctrlKey || e.metaKey) && k === 'k') {
      e.preventDefault();
      open();
      return;
    }
    if (k === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const t = e.target;
      const typing = t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName);
      if (!typing) {
        e.preventDefault();
        open();
      }
    }
  });
}
