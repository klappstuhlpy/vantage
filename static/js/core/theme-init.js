/* Theme bootstrap — the only render-blocking script in the app.
 *
 * This runs in <head> as a classic (non-module, non-defer) script so the theme
 * attributes are on <html> before the first paint. ES modules are deferred by
 * spec, so theme.js cannot do this job: without this file you get a flash of
 * dark UI on a light-themed browser.
 *
 * It is a separate FILE rather than an inline <script> on purpose. The obvious
 * way to avoid the flash is an inline snippet, but Vantage keeps the whole app
 * free of inline JS so a strict Content-Security-Policy can be turned on
 * without a nonce pipeline (the login page already held this line — see
 * main.rs). Keep it tiny, dependency-free, and exception-safe: a throw here
 * would block the page.
 *
 * The applied state is published on `window.__vantage_theme` so theme.js can
 * offer an ESM API over the same storage keys without duplicating them.
 */
(function () {
  var KEYS = { theme: 'vantage.theme', accent: 'vantage.accent', density: 'vantage.density', sidebar: 'vantage.sidebar' };
  var root = document.documentElement;

  function read(key, fallback) {
    try {
      return localStorage.getItem(key) || fallback;
    } catch (e) {
      // Private mode / storage disabled. Defaults are still a working product.
      return fallback;
    }
  }

  // "system" resolves against the OS now, and keeps resolving: see theme.js,
  // which re-applies on change while the preference is still "system".
  function resolveTheme(pref) {
    if (pref === 'light' || pref === 'dark') return pref;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function apply(state) {
    root.setAttribute('data-theme', resolveTheme(state.theme));
    // Radar is the built-in default and carries no attribute, so the token
    // file's :root block stays the single source of the default accent.
    if (state.accent && state.accent !== 'radar') root.setAttribute('data-accent', state.accent);
    else root.removeAttribute('data-accent');
    if (state.density === 'compact') root.setAttribute('data-density', 'compact');
    else root.removeAttribute('data-density');
    if (state.sidebar === 'rail') root.setAttribute('data-sidebar', 'rail');
    else root.removeAttribute('data-sidebar');
  }

  var state = {
    theme: read(KEYS.theme, 'system'),
    accent: read(KEYS.accent, 'radar'),
    density: read(KEYS.density, 'comfortable'),
    sidebar: read(KEYS.sidebar, 'full'),
  };

  try {
    apply(state);
  } catch (e) {
    /* never let theming break the page */
  }

  window.__vantage_theme = { KEYS: KEYS, state: state, apply: apply, resolveTheme: resolveTheme };
})();
