/* Theme, accent, density and sidebar preferences.
 *
 * The pre-paint half of this lives in theme-init.js (a blocking classic script
 * — see the comment there for why). This module is the ESM API over the same
 * state: it reuses the bootstrap's keys and apply() rather than restating them,
 * so there is exactly one definition of what "compact" means.
 *
 * Preferences are per-browser (localStorage). Per-account server persistence is
 * a listed stretch goal; nothing here assumes a backend.
 */

const boot = window.__vantage_theme;

// If theme-init.js somehow didn't run (asset 404, script blocked), degrade to a
// no-op store rather than throwing on every page.
const KEYS = boot?.KEYS ?? { theme: 'vantage.theme', accent: 'vantage.accent', density: 'vantage.density', sidebar: 'vantage.sidebar' };
const state = boot?.state ?? { theme: 'system', accent: 'radar', density: 'comfortable', sidebar: 'full' };

const listeners = new Set();

function write(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable (private mode, disabled cookies). The choice
    // still applies to this page; it just won't survive a reload.
  }
}

function apply() {
  boot?.apply?.(state);
  for (const fn of listeners) {
    try {
      fn(state);
    } catch (e) {
      console.error('theme listener failed', e);
    }
  }
}

/** Current preferences (a copy — mutate through the setters). */
export function get() {
  return { ...state };
}

/** The theme actually in effect, with "system" resolved. */
export function effectiveTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

/** @param {'dark'|'light'|'system'} pref */
export function setTheme(pref) {
  state.theme = pref;
  write(KEYS.theme, pref);
  apply();
}

/** @param {'radar'|'phosphor'|'amber'|'ion'|'ember'} name */
export function setAccent(name) {
  state.accent = name;
  write(KEYS.accent, name);
  apply();
}

/** @param {'comfortable'|'compact'} value */
export function setDensity(value) {
  state.density = value;
  write(KEYS.density, value);
  apply();
}

/** @param {'full'|'rail'} value */
export function setSidebar(value) {
  state.sidebar = value;
  write(KEYS.sidebar, value);
  apply();
}

export function toggleSidebar() {
  setSidebar(state.sidebar === 'rail' ? 'full' : 'rail');
  return state.sidebar;
}

/**
 * Subscribe to preference changes. Charts use this to re-read their colors
 * from the token layer when the theme flips — canvas can't inherit CSS.
 * @returns {() => void} unsubscribe
 */
export function onChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Read a resolved design token, e.g. token('--acc'). Charts need real values. */
export function token(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// While the preference is "system", keep following the OS instead of freezing
// whatever it was at load. Someone on a sunset-triggered auto theme should see
// the dashboard follow along.
if (window.matchMedia) {
  const mq = window.matchMedia('(prefers-color-scheme: light)');
  const onOsChange = () => {
    if (state.theme === 'system') apply();
  };
  mq.addEventListener?.('change', onOsChange);
}

export const ACCENTS = [
  { id: 'radar', label: 'Radar', hex: '#2AC3DE' },
  { id: 'phosphor', label: 'Phosphor', hex: '#3ECF8E' },
  { id: 'amber', label: 'Amber', hex: '#FDB022' },
  { id: 'ion', label: 'Ion', hex: '#A78BFA' },
  { id: 'ember', label: 'Ember', hex: '#F97066' },
];
