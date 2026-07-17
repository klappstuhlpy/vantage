/* The app shell: sidebar, mobile drawer, live indicator, appearance popover.
 *
 * Loaded by layout.html on every page. Everything here is chrome — a page
 * module never has to think about it.
 */

import * as theme from './theme.js';
import * as live from './live.js';
import * as palette from './palette.js';
import * as safemode from './safemode.js';
import { h, wireMenu, wireSegmented } from './ui.js';
import { hydrateTimestamps, startTimestampTicker } from './format.js';

const root = document.documentElement;

/* =======================================================================
   Live indicator
   ======================================================================= */

/**
 * The scope sweeps and the badge reads "live" only while the socket is really
 * connected. That honesty is the point: a dashboard that always looks live is
 * worse than one that admits it lost the server.
 *
 * The shell subscribes to `metrics` purely to hold the connection open — it is
 * the one topic every Vantage host publishes. Without a subscription the
 * socket would close and the indicator would report offline while the app is
 * perfectly healthy.
 */
function wireLive() {
  live.onStateChange((state) => root.setAttribute('data-live', state));
  live.subscribe('metrics', () => {});
}

/* =======================================================================
   Sidebar
   ======================================================================= */

function wireSidebar() {
  const sidebar = document.getElementById('sidebar');
  const collapse = document.querySelector('.sidebar-collapse');
  const toggle = document.querySelector('.nav-toggle');
  if (!sidebar) return;

  collapse?.addEventListener('click', () => {
    const next = theme.toggleSidebar();
    collapse.setAttribute('aria-label', next === 'rail' ? 'Expand sidebar' : 'Collapse sidebar');
    collapse.setAttribute('aria-expanded', String(next !== 'rail'));
  });

  // Mobile: the sidebar becomes an off-canvas drawer.
  let scrim;
  const openNav = () => {
    sidebar.classList.add('is-open');
    toggle?.setAttribute('aria-expanded', 'true');
    if (!scrim) {
      scrim = h('div', { class: 'drawer-scrim', onclick: closeNav });
      document.body.append(scrim);
    }
    scrim.classList.add('is-open');
    sidebar.querySelector('.nav-item')?.focus();
  };
  const closeNav = () => {
    sidebar.classList.remove('is-open');
    toggle?.setAttribute('aria-expanded', 'false');
    scrim?.classList.remove('is-open');
  };

  toggle?.addEventListener('click', () => {
    sidebar.classList.contains('is-open') ? closeNav() : openNav();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sidebar.classList.contains('is-open')) {
      closeNav();
      toggle?.focus();
    }
  });

  // Navigating within the drawer should close it — the destination is the point.
  sidebar.addEventListener('click', (e) => {
    if (e.target.closest('.nav-item') && sidebar.classList.contains('is-open')) closeNav();
  });

  // Leaving the drawer breakpoint must not strand an open drawer.
  window.matchMedia('(min-width: 721px)').addEventListener('change', (e) => {
    if (e.matches) closeNav();
  });
}

/* =======================================================================
   Appearance popover
   ======================================================================= */

function buildAppearance() {
  const prefs = theme.get();

  const themeSeg = h(
    'div',
    { class: 'segmented', role: 'group', 'aria-label': 'Theme' },
    h('button', { 'data-value': 'light', 'aria-selected': String(prefs.theme === 'light') }, 'Light'),
    h('button', { 'data-value': 'dark', 'aria-selected': String(prefs.theme === 'dark') }, 'Dark'),
    h('button', { 'data-value': 'system', 'aria-selected': String(prefs.theme === 'system') }, 'Auto')
  );
  wireSegmented(themeSeg, (v) => theme.setTheme(v));

  const densitySeg = h(
    'div',
    { class: 'segmented', role: 'group', 'aria-label': 'Density' },
    h('button', { 'data-value': 'comfortable', 'aria-selected': String(prefs.density !== 'compact') }, 'Cosy'),
    h('button', { 'data-value': 'compact', 'aria-selected': String(prefs.density === 'compact') }, 'Compact')
  );
  wireSegmented(densitySeg, (v) => theme.setDensity(v));

  const swatches = h(
    'div',
    { class: 'accent-swatches', role: 'group', 'aria-label': 'Accent colour' },
    ...theme.ACCENTS.map((a) =>
      h('button', {
        class: 'swatch',
        style: { '--swatch': a.hex },
        'aria-pressed': String(prefs.accent === a.id),
        'aria-label': a.label,
        title: a.label,
        onclick: (e) => {
          theme.setAccent(a.id);
          for (const s of swatches.children) s.setAttribute('aria-pressed', String(s === e.currentTarget));
        },
      })
    )
  );

  return h(
    'div',
    { class: 'menu appearance', id: 'appearance-menu' },
    h('div', { class: 'appearance-row' }, h('span', { class: 'eyebrow' }, 'Theme'), themeSeg),
    h('div', { class: 'appearance-row' }, h('span', { class: 'eyebrow' }, 'Accent'), swatches),
    h('div', { class: 'appearance-row' }, h('span', { class: 'eyebrow' }, 'Density'), densitySeg)
  );
}

function wireAppearance() {
  const trigger = document.getElementById('appearance-btn');
  if (!trigger) return;
  const menu = buildAppearance();
  document.body.append(menu);
  wireMenu(trigger, menu, { align: 'end' });
}

/* =======================================================================
   Account menu
   ======================================================================= */

function wireAccount() {
  const trigger = document.getElementById('account-btn');
  const menu = document.getElementById('account-menu');
  if (trigger && menu) wireMenu(trigger, menu, { align: 'start', placement: 'top' });
}

/* =======================================================================
   Search
   ======================================================================= */

function wireSearch() {
  palette.install();
  document.getElementById('search-btn')?.addEventListener('click', () => palette.open());
}

/* =======================================================================
   Boot
   ======================================================================= */

function init() {
  wireSidebar();
  wireAppearance();
  wireAccount();
  wireSearch();
  wireLive();
  // Reflect global safe mode: banner, disabled destructive controls, the toggle.
  safemode.install();

  // Server-rendered timestamps carry an ISO string; only the browser knows the
  // viewer's timezone, so hydration happens here for every page at once.
  hydrateTimestamps(document);
  startTimestampTicker(document);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
