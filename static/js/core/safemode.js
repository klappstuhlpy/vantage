/* Global safe mode — the shell-side half of §11.3.
 *
 * The server is the authority: while safe mode is engaged its middleware answers
 * 423 to every destructive request, whatever the browser believes. This module
 * is the honest reflection of that state, and nothing here is trusted to *hold*
 * it — it only stops the operator bothering to try:
 *
 *   - a persistent amber banner under the topbar,
 *   - `body.is-safe-mode`, which the CSS uses to disable every `.btn.danger`
 *     and `[data-destructive]` control at once (including ones a page renders
 *     later — that is the whole reason it is a body class and a CSS rule rather
 *     than a per-button toggle),
 *   - the topbar button, which reflects the state and toggles it.
 *
 * Toggling is a sudo-gated POST; core/api.js handles the reauth prompt and retry
 * transparently, so there is nothing special to do here for it.
 */

import { get, post } from './api.js';
import { h, icon, confirm, reportError, toast } from './ui.js';

let engaged = false;

function applyState() {
  document.body.classList.toggle('is-safe-mode', engaged);

  const btn = document.getElementById('safemode-btn');
  if (btn) {
    btn.classList.toggle('is-on', engaged);
    btn.setAttribute('aria-pressed', String(engaged));
    btn.setAttribute('data-tip', engaged ? 'Safe mode: host changes frozen' : 'Safe mode: host changes allowed');
    const use = btn.querySelector('use');
    use?.setAttribute('href', `/static/icons/sprite.svg#${engaged ? 'lock' : 'lock-open'}`);
  }

  let banner = document.getElementById('safemode-banner');
  if (!engaged) {
    banner?.remove();
    return;
  }
  if (banner) return;

  banner = h(
    'div',
    { class: 'safemode-banner', id: 'safemode-banner', role: 'status' },
    icon('lock', { size: 16 }),
    h(
      'span',
      { class: 'safemode-banner-text' },
      h('strong', {}, 'Safe mode is on.'),
      ' Host changes are frozen — firewall, proxy, containers, scripts and backups are read-only until you turn it off.'
    ),
    h('button', { class: 'btn sm', type: 'button', onclick: () => toggle() }, 'Turn off')
  );
  // Under the topbar, above the page content, so it is impossible to miss.
  document.querySelector('.topbar')?.after(banner);
}

/** Flip safe mode, confirming first — this freezes (or thaws) the whole box. */
async function toggle() {
  const next = !engaged;
  const ok = await confirm(
    next
      ? {
          title: 'Turn on safe mode?',
          message: 'Every host change — firewall, proxy, containers, scripts, backups — is refused until you turn it back off. Reads keep working.',
          confirmLabel: 'Freeze changes',
        }
      : {
          title: 'Turn off safe mode?',
          message: 'Destructive host actions will be allowed again.',
          confirmLabel: 'Resume changes',
        }
  );
  if (!ok) return;

  try {
    const res = await post('/safe-mode', { engaged: next });
    engaged = !!res.engaged;
    applyState();
    toast('ok', engaged ? 'Safe mode on' : 'Safe mode off', engaged ? 'Host changes are frozen.' : 'Host changes are allowed again.');
  } catch (e) {
    reportError(e, "Couldn't change safe mode");
  }
}

/** Read the live state once and wire the toggle. Called by the shell on boot. */
export async function install() {
  const btn = document.getElementById('safemode-btn');
  btn?.addEventListener('click', () => toggle());

  try {
    const res = await get('/safe-mode');
    engaged = !!res.engaged;
  } catch {
    // A shell that can't read the flag assumes the safe default: not engaged, so
    // the operator is never falsely told the box is frozen. The server still
    // enforces the truth on every request regardless of what we render.
    engaged = false;
  }
  applyState();
}

export const isEngaged = () => engaged;
