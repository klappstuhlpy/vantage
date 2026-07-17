/* The revert countdown (§11.1) — the UI half of an armed apply.
 *
 * After an arming apply, the operator has a fixed window to confirm the change or
 * it rolls itself back. This builds the panel that runs that window: a draining
 * bar, a ticking readout, and the two buttons that end it. The server is the one
 * that actually reverts on timeout (a background task, so it fires even if this
 * tab is gone) — this only shows the clock and sends the confirm.
 *
 * The bar drains with a single CSS width transition rather than a per-frame
 * rewrite; the numeric readout is the honest fallback under reduced motion, where
 * the sweep is disabled but the seconds still tick.
 */

import { h, icon } from './ui.js';

/**
 * @param {object} o
 * @param {number} o.seconds        window length (fallback if no expiry given)
 * @param {number} [o.expiresUnix]  server deadline (unix seconds) — preferred, so
 *                                   the clock matches the server's own timer
 * @param {() => Promise<void>} o.onConfirm  keep the change
 * @param {() => Promise<void>} o.onRevert   roll back now
 * @param {() => void} o.onTimeout   the window closed unconfirmed (server reverts)
 * @returns {{ node: HTMLElement, destroy: () => void }}
 */
export function countdownConfirm({ seconds, expiresUnix, onConfirm, onRevert, onTimeout }) {
  const totalMs = Math.max(1000, expiresUnix ? expiresUnix * 1000 - Date.now() : seconds * 1000);

  const remaining = h('span', { class: 'countdown-remaining' }, `${Math.ceil(totalMs / 1000)}s`);
  const bar = h('div', { class: 'countdown-bar' });
  const track = h('div', { class: 'countdown-track' }, bar);

  const confirmBtn = h('button', { class: 'btn', 'data-autofocus': '' }, icon('circle-check'), ' Confirm & keep');
  const revertBtn = h('button', { class: 'btn quiet' }, icon('rotate-ccw'), ' Revert now');

  const node = h(
    'div',
    { class: 'countdown', role: 'timer', 'aria-live': 'off' },
    h('div', { class: 'countdown-head' }, h('strong', {}, 'Confirm to keep these changes'), remaining),
    track,
    h(
      'p',
      { class: 'modal-desc' },
      "If you don't confirm in time, the change reverts itself — a ruleset that cut off your own session undoes automatically."
    ),
    h('div', { class: 'countdown-actions' }, revertBtn, confirmBtn)
  );

  let done = false;
  let ticker = null;
  const destroy = () => {
    done = true;
    if (ticker) clearInterval(ticker);
  };

  // Drain the bar over the window with one transition (CSS gates it behind
  // prefers-reduced-motion; when disabled the readout below is the signal).
  requestAnimationFrame(() => {
    bar.classList.add('is-draining');
    bar.style.transitionDuration = `${totalMs}ms`;
    bar.style.width = '0%';
  });

  const deadline = Date.now() + totalMs;
  ticker = setInterval(() => {
    if (done) return;
    const left = deadline - Date.now();
    if (left <= 0) {
      remaining.textContent = '0s';
      destroy();
      onTimeout?.();
      return;
    }
    remaining.textContent = `${Math.ceil(left / 1000)}s`;
  }, 250);

  // The buttons disable themselves the moment they are pressed — a double-click
  // on "Confirm" must not fire two requests at the tail of the window.
  const guard = (btn, fn) => async () => {
    if (done) return;
    destroy();
    confirmBtn.disabled = true;
    revertBtn.disabled = true;
    await fn();
  };
  confirmBtn.addEventListener('click', guard(confirmBtn, () => onConfirm?.()));
  revertBtn.addEventListener('click', guard(revertBtn, () => onRevert?.()));

  return { node, destroy };
}
