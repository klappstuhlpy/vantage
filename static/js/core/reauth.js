/* Sudo mode: proving it's still you before something irreversible.
 *
 * The server side of this is `account::routes::Sudo` — an extractor the
 * destructive routes take instead of a plain session. When a session's
 * re-authentication has gone stale it answers 403 with
 * `{"reauth_required": true}` rather than a generic refusal, and core/api.js
 * turns that marker into a call to `requestReauth()` below, then retries the
 * original request once. So a page never has to know sudo exists: it POSTs, the
 * modal appears, the POST goes through. That is the whole design — a rule that
 * has to be remembered at every call site is a rule that will be forgotten at
 * one of them.
 *
 * This module is imported dynamically by api.js (api → reauth → api is a cycle,
 * and a dynamic import is the cheapest honest way out of it, with the bonus that
 * pages which never trip a 403 never load it).
 */

import { post, get } from './api.js';
import { h, openModal, closeModal } from './ui.js';

/** The modal currently up, if any — so two parallel 403s share one prompt. */
let pending = null;

/**
 * Ask the operator to re-authenticate.
 *
 * @param {string} [reason] What the server said it wants confirmation for.
 * @returns {Promise<boolean>} Whether the sudo window is now open.
 */
export function requestReauth(reason) {
  // Two requests failing at once (a page saving two sections, say) must not
  // stack two dialogs on top of each other. The second waits on the first, and
  // if that one succeeds it is already authorised.
  if (pending) return pending;
  pending = prompt(reason).finally(() => {
    pending = null;
  });
  return pending;
}

async function prompt(reason) {
  // Ask what this account actually needs before drawing the form: an account
  // without a second factor must not be shown a code field it cannot fill.
  let methods;
  try {
    methods = await get('/account/reauth');
  } catch {
    // If we cannot even ask, do not guess — a form that demands a code from an
    // account that has none is unanswerable, and one that omits a required code
    // just fails on submit.
    return false;
  }
  if (methods.active) return true;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
      closeModal(dialog);
      setTimeout(() => dialog.remove(), 400);
    };

    const password = h('input', {
      class: 'input',
      type: 'password',
      id: 'reauth-password',
      required: '',
      autocomplete: 'current-password',
      'data-autofocus': '',
    });

    const code = methods.totp
      ? h('input', {
          class: 'input code-input',
          id: 'reauth-code',
          required: '',
          inputmode: 'numeric',
          autocomplete: 'one-time-code',
          maxlength: '11',
          placeholder: '000000',
          spellcheck: 'false',
        })
      : null;

    const error = h('span', { class: 'field-error', hidden: '' });
    const submit = h('button', { class: 'btn', type: 'submit' }, 'Confirm');

    const fields = [
      h(
        'div',
        { class: 'field' },
        h('label', { for: 'reauth-password' }, 'Password'),
        password
      ),
    ];
    if (code) {
      fields.push(
        h(
          'div',
          { class: 'field' },
          h('label', { for: 'reauth-code' }, 'Authenticator code'),
          code,
          h('span', { class: 'field-hint' }, 'Or one of your recovery codes.')
        )
      );
    }
    fields.push(error);

    const form = h(
      'form',
      {
        autocomplete: 'off',
        onsubmit: async (e) => {
          e.preventDefault();
          error.hidden = true;
          submit.disabled = true;
          try {
            // Deliberately not through the retrying `post` wrapper's reauth
            // path: a 401 here means "wrong password", which is this form's
            // business to display, not a reason to raise a second modal.
            await post('/account/reauth', {
              password: password.value,
              code: code ? code.value.trim() : undefined,
            });
            finish(true);
          } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
            password.select();
          } finally {
            submit.disabled = false;
          }
        },
      },
      h(
        'div',
        { class: 'modal-header' },
        h('span', { class: 'modal-title' }, 'Confirm it’s you')
      ),
      h(
        'div',
        { class: 'modal-body' },
        h('p', { class: 'modal-desc' }, reason || 'This action needs your password.'),
        ...fields
      ),
      h(
        'div',
        { class: 'modal-footer' },
        h('button', { class: 'btn quiet', type: 'button', onclick: () => finish(false) }, 'Cancel'),
        submit
      )
    );

    const dialog = h('dialog', { class: 'modal', style: { width: 'min(420px, calc(100vw - 32px))' } }, form);
    document.body.append(dialog);
    openModal(dialog, { onClose: () => finish(false) });
  });
}
