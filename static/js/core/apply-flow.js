/* The "Preview changes → Apply → confirm-or-revert" flow shared by firewall and
 * proxy (§11.1–11.2).
 *
 * A destructive apply against an external engine — a packet filter, a reverse
 * proxy — is exactly the kind of change an operator should read before it is
 * live, and be able to take back after. So Apply is a three-beat modal:
 *
 *   1. a server-computed dry-run diff (§11.2), so nothing goes live unseen;
 *   2. the apply itself, which arms a self-revert on the server (§11.1);
 *   3. a countdown that keeps the change only if confirmed — a ruleset that cut
 *      off the operator's own session reverts itself when they can't.
 *
 * The modal is built here (not in a template) so any page gets the whole flow by
 * calling one function and providing the four verbs (preview, apply, confirm,
 * revert) as closures against its own endpoints.
 */

import { h, icon, openModal, closeModal, withLoading, reportError, emptyState } from './ui.js';
import { countdownConfirm } from './countdown-confirm.js';

/**
 * @param {object} o
 * @param {string} o.title
 * @param {string} [o.applyLabel]
 * @param {() => Promise<{node: Node, empty?: boolean}>} o.loadPreview
 * @param {() => Promise<{token: string, revert_secs: number, expires_unix?: number} | null | void>} o.apply
 *        performs the mutation; returns the arm descriptor when a revert timer was
 *        armed, or a falsy value when there is nothing to confirm (no backend,
 *        partial apply) — in which case the flow just closes.
 * @param {(token: string) => Promise<void>} [o.confirm]  keep the armed change
 * @param {(token: string) => Promise<void>} [o.revert]   roll the armed change back now
 * @param {() => void} [o.onDone]  reload page data once the flow settles
 */
export function previewAndApply({ title, applyLabel = 'Apply', loadPreview, apply, confirm, revert, onDone }) {
  const titleEl = h('span', { class: 'modal-title' }, title);
  const body = h('div', { class: 'modal-body' }, h('div', { class: 'diff-view is-empty' }, 'Loading preview…'));
  const applyBtn = h('button', { class: 'btn', 'data-autofocus': '', disabled: true }, applyLabel);
  const footer = h(
    'div',
    { class: 'modal-footer' },
    h('button', { class: 'btn quiet', 'data-close': '' }, 'Cancel'),
    applyBtn
  );

  const dialog = h(
    'dialog',
    { class: 'modal', style: { width: 'min(720px, calc(100vw - 32px))' } },
    h(
      'div',
      { class: 'modal-header' },
      titleEl,
      h('button', { class: 'icon-btn', 'data-close': '', 'aria-label': 'Close' }, icon('x'))
    ),
    body,
    footer
  );

  // Settle exactly once — whether by confirm, revert, timeout, or the operator
  // dismissing the modal (which leaves the server's timer to do the reverting).
  let settled = false;
  let counter = null;
  const settle = () => {
    if (settled) return;
    settled = true;
    counter?.destroy();
    closeModal(dialog);
    setTimeout(() => dialog.remove(), 400);
    onDone?.();
  };

  applyBtn.addEventListener('click', () =>
    withLoading(applyBtn, async () => {
      const arm = await apply();
      if (!arm || !arm.token) {
        settle();
        return;
      }
      enterCountdown(arm);
    })
  );

  function enterCountdown(arm) {
    titleEl.textContent = 'Confirm the change';
    counter = countdownConfirm({
      seconds: arm.revert_secs,
      expiresUnix: arm.expires_unix,
      onConfirm: async () => {
        try {
          await confirm?.(arm.token);
        } catch (e) {
          reportError(e, "Couldn't confirm — the change may revert");
        }
        settle();
      },
      onRevert: async () => {
        try {
          await revert?.(arm.token);
        } catch (e) {
          reportError(e, "Couldn't revert");
        }
        settle();
      },
      // The server reverts on its own timer; here we just reflect it and close.
      onTimeout: () => {
        body.replaceChildren(
          emptyState({ icon: 'rotate-ccw', title: 'Reverted', sub: 'You did not confirm in time — the change was rolled back.' })
        );
        setTimeout(settle, 1600);
      },
    });
    // The countdown owns its own buttons, so the standard footer steps aside.
    footer.replaceChildren();
    body.replaceChildren(counter.node);
  }

  document.body.append(dialog);
  // Dismissing the modal (backdrop / Escape / close) still settles the flow.
  openModal(dialog, { onClose: settle });

  loadPreview()
    .then(({ node, empty }) => {
      body.replaceChildren(node);
      applyBtn.disabled = !!empty;
    })
    .catch((e) => {
      body.replaceChildren(emptyState({ degraded: true, title: "Couldn't build the preview", sub: e?.message }));
      reportError(e, "Couldn't preview the changes");
    });

  return { dialog };
}
