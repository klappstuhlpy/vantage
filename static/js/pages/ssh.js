/* SSH — authorized keys and access tokens.
 *
 * Another page that never ran: ssh.html shipped a <div id="ssh-app"> saying
 * "Loading SSH key management..." and a script tag that 404'd, so it said
 * Loading forever. All of this is new.
 *
 * Two things this page is careful about, because it hands out access:
 *
 *   - A revoked key is kept and shown, not hidden. "This key used to be able to
 *     log in, and stopped on the 3rd" is exactly what you want during an
 *     incident; a UI that filters revoked keys away by default hides the
 *     history you came for.
 *
 *   - An issued token is displayed once, because only its hash is stored. That
 *     moment gets a dedicated modal that cannot be dismissed by a stray click
 *     on the backdrop, rather than a toast that auto-expires while you're
 *     switching windows to paste it.
 */

import { get, post, del, ApiError } from '../core/api.js';
import { h, icon, render, pill, emptyRow, emptyState, skeletonRows, reportError, confirm, toastOk, withLoading, openModal, closeModal, copyText } from '../core/ui.js';
import { num, shortId, relative, absolute, startTimestampTicker } from '../core/format.js';

const tilesEl = document.getElementById('tiles');
const keysBody = document.getElementById('keys-body');
const tokensBody = document.getElementById('tokens-body');
const keyCount = document.getElementById('key-count');
const tokenCount = document.getElementById('token-count');

const keyEditor = document.getElementById('key-editor');
const keyForm = document.getElementById('key-form');
const tokenEditor = document.getElementById('token-editor');
const tokenForm = document.getElementById('token-form');
const tokenReveal = document.getElementById('token-reveal');

/* =======================================================================
   Tiles
   ======================================================================= */

function tile(label, value, sub, status, iconName) {
  return h(
    'div',
    { class: `stat${status ? ` ${status}` : ''}` },
    h('span', { class: 'stat-key' }, icon(iconName), label),
    h('span', { class: 'stat-value' }, value),
    h('span', { class: 'stat-sub' }, sub)
  );
}

function renderTiles(keys, tokens) {
  // "Not synced" is a real state the model calls out: a legacy key with no
  // target_user is in the database but was never written to any
  // authorized_keys file, so it grants nothing. That gap deserves a tile.
  const unsynced = keys.keys.filter((k) => !k.target_user && !k.revoked_at).length;

  render(
    tilesEl,
    tile('Keys', num(keys.active), keys.revoked ? `${num(keys.revoked)} revoked` : 'all active', null, 'key-round'),
    tile('Not synced', num(unsynced), unsynced ? 'in the database, not on the host' : 'every active key is on the host', unsynced ? 'warn' : 'ok', 'triangle-alert'),
    tile('Tokens', num(tokens.active), `${num(tokens.total - tokens.active)} inactive`, null, 'fingerprint'),
    tile('Audit', 'View', 'every auth event and token use', null, 'history')
  );

  // The audit tile is a link, not a statistic — make the whole thing clickable.
  const auditTile = tilesEl.lastElementChild;
  auditTile.classList.add('stat-link');
  auditTile.addEventListener('click', () => (window.location.href = '/ssh/audit'));
}

/* =======================================================================
   Keys
   ======================================================================= */

function keyState(k) {
  if (k.revoked_at) return pill('down', 'revoked');
  if (!k.target_user) return pill('warn', 'not synced');
  return pill('ok', 'active');
}

function renderKeys(d) {
  keyCount.textContent = num(d.total);

  if (!d.keys.length) {
    render(
      keysBody,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 6 },
          emptyState({
            icon: 'key-round',
            title: 'No keys yet',
            sub: 'Add a public key to let it log into this host.',
            action: h('button', { class: 'btn sm', onclick: () => openKeyEditor() }, 'Add key'),
          })
        )
      )
    );
    return;
  }

  render(
    keysBody,
    ...d.keys.map((k) =>
      h(
        'tr',
        { class: k.revoked_at ? 'is-revoked' : '' },
        h('td', {}, h('div', { class: 'key-name' }, k.name), k.comment ? h('div', { class: 'sub mono' }, k.comment) : null),
        h(
          'td',
          {},
          h(
            'button',
            {
              class: 'fp-btn mono',
              type: 'button',
              title: `${k.fingerprint}\nClick to copy`,
              onclick: () => copyText(k.fingerprint, 'Fingerprint copied'),
            },
            shortId(k.fingerprint.replace(/^SHA256:/, ''), 16)
          ),
          h('span', { class: 'algo' }, k.algo)
        ),
        h(
          'td',
          { class: 'mono' },
          k.target_user
            ? k.target_user
            : h('span', { class: 'muted', title: 'This key has no comment, so Vantage cannot tell which host account it belongs to. It is not written to any authorized_keys file.' }, 'unknown')
        ),
        h(
          'td',
          {},
          k.last_used_at
            ? h('time', { class: 'js-ts', datetime: k.last_used_at, title: absolute(k.last_used_at) }, relative(k.last_used_at))
            : h('span', { class: 'muted' }, 'never')
        ),
        h('td', {}, keyState(k)),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            k.revoked_at
              ? null
              : h(
                  'button',
                  { class: 'btn sm quiet', type: 'button', onclick: (e) => revokeKey(k, e.currentTarget) },
                  'Revoke'
                ),
            h(
              'button',
              { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': `Delete ${k.name}`, onclick: (e) => deleteKey(k, e.currentTarget) },
              icon('trash-2')
            )
          )
        )
      )
    )
  );
}

async function revokeKey(k, btn) {
  const ok = await confirm({
    title: `Revoke ${k.name}?`,
    message: `This key stops being able to log in as ${k.target_user || 'its host user'} immediately. The key stays listed here so the audit trail keeps making sense — delete it separately if you want it gone.`,
    confirmLabel: 'Revoke',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await post(`/ssh/keys/${k.id}/revoke`);
    toastOk('Key revoked', k.name);
    load();
  });
}

async function deleteKey(k, btn) {
  const ok = await confirm({
    title: `Delete ${k.name}?`,
    message: k.revoked_at
      ? `${k.name} will be removed from the list. It is already revoked, so this changes no access.`
      : `${k.name} will be removed and can no longer log in. Deleting also drops it from the list, so the audit log will reference a key you can't look up. Revoking instead keeps that trail intact.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await del(`/ssh/keys/${k.id}`);
    toastOk('Key deleted', k.name);
    load();
  });
}

/* =======================================================================
   Tokens
   ======================================================================= */

function tokenState(t) {
  if (t.revoked_at) return pill('down', 'revoked');
  if (t.expires_at && new Date(t.expires_at) < new Date()) return pill('idle', 'expired');
  return pill('ok', 'active');
}

function renderTokens(d) {
  tokenCount.textContent = num(d.total);

  if (!d.tokens.length) {
    render(
      tokensBody,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 6 },
          emptyState({
            icon: 'fingerprint',
            title: 'No tokens',
            sub: 'Issue one to let a script or CI job talk to Vantage.',
            action: h('button', { class: 'btn sm', onclick: () => openModal(tokenEditor) }, 'Issue token'),
          })
        )
      )
    );
    return;
  }

  render(
    tokensBody,
    ...d.tokens.map((t) => {
      const expired = t.expires_at && new Date(t.expires_at) < new Date();
      return h(
        'tr',
        { class: t.revoked_at || expired ? 'is-revoked' : '' },
        h('td', {}, t.label),
        // An empty scope string means full access. That is the most permissive
        // thing on the page, so it must not render as an empty cell.
        h('td', {}, t.scopes ? h('div', { class: 'pill-row' }, ...t.scopes.split(',').map((s) => pill('info', s.trim()))) : pill('warn', 'full access')),
        h(
          'td',
          {},
          t.expires_at
            ? h('time', { class: 'js-ts', datetime: t.expires_at, title: absolute(t.expires_at) }, relative(t.expires_at))
            : h('span', { class: 'muted' }, 'never')
        ),
        h(
          'td',
          {},
          t.used_at
            ? h('time', { class: 'js-ts', datetime: t.used_at, title: absolute(t.used_at) }, relative(t.used_at))
            : h('span', { class: 'muted' }, 'never')
        ),
        h('td', {}, tokenState(t)),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            t.revoked_at ? null : h('button', { class: 'btn sm quiet', type: 'button', onclick: (e) => revokeToken(t, e.currentTarget) }, 'Revoke'),
            h(
              'button',
              { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': `Delete ${t.label}`, onclick: (e) => deleteToken(t, e.currentTarget) },
              icon('trash-2')
            )
          )
        )
      );
    })
  );
}

async function revokeToken(t, btn) {
  const ok = await confirm({
    title: `Revoke ${t.label}?`,
    message: 'Anything still using this token starts failing immediately. This cannot be undone — you would have to issue a new token and update whatever uses it.',
    confirmLabel: 'Revoke',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await post(`/ssh/tokens/${t.id}/revoke`);
    toastOk('Token revoked', t.label);
    load();
  });
}

async function deleteToken(t, btn) {
  const ok = await confirm({
    title: `Delete ${t.label}?`,
    message: 'The token record is removed entirely, including from this list.',
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await del(`/ssh/tokens/${t.id}`);
    toastOk('Token deleted', t.label);
    load();
  });
}

/* =======================================================================
   Editors
   ======================================================================= */

function openKeyEditor() {
  keyForm.reset();
  document.getElementById('k-error').hidden = true;
  document.getElementById('k-key').closest('.field').classList.remove('has-error');
  openModal(keyEditor);
}

document.getElementById('add-key-btn').addEventListener('click', openKeyEditor);
document.getElementById('issue-token-btn').addEventListener('click', () => {
  tokenForm.reset();
  openModal(tokenEditor);
});

keyForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('k-error');
  const field = document.getElementById('k-key').closest('.field');
  errEl.hidden = true;
  field.classList.remove('has-error');

  const payload = {
    name: document.getElementById('k-name').value.trim(),
    public_key: document.getElementById('k-key').value.trim(),
  };

  try {
    await withLoading(document.getElementById('key-save'), async () => {
      const r = await post('/ssh/keys', payload);
      toastOk('Key added', `${r.algo} · authorizes ${r.target_user || 'no host user'}`);
      closeModal(keyEditor);
      load();
    });
  } catch (err) {
    // 422 is the interesting one: a malformed key, or a key with no comment so
    // the host user can't be derived. The server's message is specific and
    // actionable, so it belongs against the field rather than in a toast.
    if (err instanceof ApiError && err.status === 422) {
      errEl.textContent = err.body?.error || err.message;
      errEl.hidden = false;
      field.classList.add('has-error');
    }
  }
});

tokenForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const hours = Number(document.getElementById('t-expiry').value);
  const payload = {
    label: document.getElementById('t-label').value.trim(),
    scopes: document.getElementById('t-scopes').value.trim(),
    expires_in_hours: hours || null,
  };

  await withLoading(document.getElementById('token-save'), async () => {
    const r = await post('/ssh/tokens', payload);
    closeModal(tokenEditor);

    document.getElementById('token-value').textContent = r.token;
    document.getElementById('token-copy').onclick = () => copyText(r.token, 'Token copied');
    openModal(tokenReveal);
    load();
  });
});

// This is the only chance to copy the token, so a misclick on the backdrop must
// not throw it away. openModal wires backdrop-dismiss for every modal; this one
// opts out by swallowing the click before it reaches that handler.
tokenReveal.addEventListener(
  'click',
  (e) => {
    if (e.target === tokenReveal) e.stopPropagation();
  },
  true
);

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  render(keysBody, ...skeletonRows(6));
  render(tokensBody, ...skeletonRows(6));

  try {
    // Both panels are on one page; fetch them together rather than serially.
    const [keys, tokens] = await Promise.all([get('/ssh/data'), get('/ssh/tokens')]);
    renderTiles(keys, tokens);
    renderKeys(keys);
    renderTokens(tokens);
  } catch (e) {
    reportError(e, "Couldn't load your SSH keys");
    render(tilesEl, emptyState({ degraded: true, title: "Couldn't load SSH data", sub: e?.message }));
    render(keysBody, emptyRow(6, 'Unavailable.'));
    render(tokensBody, emptyRow(6, 'Unavailable.'));
  }
}

startTimestampTicker();
load();
