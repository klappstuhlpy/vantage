/* Account & security.
 *
 * Three surfaces: the password form, the second factor (enroll / disable /
 * recovery codes), and the session list.
 *
 * Nothing here asks for the current password or handles a 403. Every route this
 * page calls is sudo-gated server-side, and core/api.js turns that into the
 * reauth modal and a retry — so these handlers are written as if the request
 * simply succeeds, which is also what they look like when it does.
 */

import { get, post, del, request } from '../core/api.js';
import { relative, absolute } from '../core/format.js';
import {
  h,
  icon,
  render,
  confirm,
  copyText,
  emptyRow,
  openModal,
  closeModal,
  reportError,
  toastOk,
  withLoading,
} from '../core/ui.js';

const $ = (id) => document.getElementById(id);

// ─── Sessions ────────────────────────────────────────────────────────────────

const body = $('sessions-body');
const count = $('session-count');

/**
 * A human name for a User-Agent string.
 *
 * Deliberately shallow: this exists so you can tell *your* rows apart, which
 * needs "Firefox on Windows", not a version matrix. Order matters — every
 * Chromium browser also says "Safari", and Edge also says "Chrome", so the more
 * specific brands have to be tested first.
 */
function describeAgent(ua) {
  if (!ua) return null;
  const browser =
    [
      ['Edg/', 'Edge'],
      ['OPR/', 'Opera'],
      ['Firefox/', 'Firefox'],
      ['Chrome/', 'Chrome'],
      ['Safari/', 'Safari'],
      ['curl/', 'curl'],
    ].find(([token]) => ua.includes(token))?.[1] || null;

  const os =
    [
      ['Windows', 'Windows'],
      ['Android', 'Android'],
      ['iPhone', 'iOS'],
      ['iPad', 'iPadOS'],
      ['Mac OS X', 'macOS'],
      ['Linux', 'Linux'],
    ].find(([token]) => ua.includes(token))?.[1] || null;

  if (browser && os) return `${browser} on ${os}`;
  return browser || os;
}

function sessionRow(session) {
  const name = describeAgent(session.user_agent);
  const revoke = h(
    'button',
    {
      class: 'btn sm danger',
      type: 'button',
      onclick: (e) => revokeSession(e.currentTarget, session),
    },
    'Revoke'
  );

  return h(
    'tr',
    { class: session.current ? 'is-current' : '' },
    h(
      'td',
      {},
      h(
        'div',
        { class: 'device' },
        icon(session.current ? 'monitor' : 'globe'),
        h(
          'div',
          {},
          h('div', { class: 'device-name' }, name || 'Unknown device'),
          // The raw UA when we could not name it — better than a shrug, and it
          // is the only thing that distinguishes two unknown rows.
          h(
            'div',
            { class: 'device-sub' },
            session.current ? 'This browser' : name ? session.user_agent || '' : session.user_agent || 'No device recorded'
          )
        )
      )
    ),
    h('td', { class: 'mono' }, session.ip || '—'),
    h('td', { title: absolute(session.created_at) }, relative(session.created_at)),
    h(
      'td',
      { title: session.last_seen_at ? absolute(session.last_seen_at) : '' },
      session.last_seen_at ? relative(session.last_seen_at) : '—'
    ),
    // The current session has no Revoke: it is the one you are using, and
    // "sign out" is what that is called — it is in the sidebar menu, already.
    h('td', { class: 'actions' }, session.current ? h('span', { class: 'faint' }, 'current') : revoke)
  );
}

async function loadSessions() {
  try {
    const data = await get('/account/sessions');
    const sessions = data.sessions || [];
    count.textContent = String(sessions.length);
    if (!sessions.length) {
      // Not reachable in practice — reading this page requires a session — but
      // an empty table with no explanation is never the right fallback.
      render(body, emptyRow(5, 'No sessions.'));
      return;
    }
    render(body, ...sessions.map(sessionRow));
  } catch (err) {
    reportError(err, 'Could not load your sessions');
    render(body, emptyRow(5, 'Could not load sessions.'));
  }
}

async function revokeSession(btn, session) {
  const name = describeAgent(session.user_agent) || 'that device';
  const ok = await confirm({
    title: 'Revoke this session?',
    message: `The next request from ${name} lands on the sign-in page. If that is you, you'll need to sign in again.`,
    confirmLabel: 'Revoke',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await del(`/account/sessions/${encodeURIComponent(session.id)}`);
    toastOk('Session revoked');
    await loadSessions();
  }, { errorTitle: 'Could not revoke that session' });
}

$('revoke-all').addEventListener('click', async (e) => {
  const ok = await confirm({
    title: 'Sign out everywhere else?',
    message: 'Every other browser signed in as you is signed out immediately. This one stays.',
    confirmLabel: 'Sign out everywhere else',
    danger: true,
  });
  if (!ok) return;

  await withLoading(e.currentTarget, async () => {
    const { revoked } = await post('/account/sessions/revoke-all', {});
    toastOk(
      revoked ? `Signed out ${revoked} ${revoked === 1 ? 'session' : 'sessions'}` : 'Nothing else was signed in'
    );
    await loadSessions();
  }, { errorTitle: 'Could not sign the other sessions out' });
});

// ─── Password ────────────────────────────────────────────────────────────────

const passwordForm = $('password-form');
const newPassword = $('new-password');
const confirmPassword = $('confirm-password');
const passwordError = $('password-error');

passwordForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  passwordError.hidden = true;

  // Checked here as well as by the server, because "the two don't match" is not
  // something the server can tell you — it only ever sees one of them.
  if (newPassword.value !== confirmPassword.value) {
    passwordError.textContent = "Those don't match.";
    passwordError.hidden = false;
    confirmPassword.focus();
    return;
  }

  await withLoading($('password-save'), async () => {
    const { revoked } = await post('/account/password', { new_password: newPassword.value });
    passwordForm.reset();
    toastOk(
      'Password changed',
      revoked ? `${revoked} other ${revoked === 1 ? 'session was' : 'sessions were'} signed out.` : undefined
    );
  }, { errorTitle: 'Could not change your password' });
});

// ─── Two-factor ──────────────────────────────────────────────────────────────

const enrollDialog = $('totp-enroll');

/** Draws a QR module matrix as one SVG path, in the current ink colour. */
function drawQr(target, { width, modules }) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${width}`);
  // The container already carries role="img" and the label; this svg would
  // otherwise be announced a second time, and it holds nothing a screen-reader
  // user can act on anyway — the same secret is readable under "Can't scan it?".
  svg.setAttribute('aria-hidden', 'true');
  // Modules are integer-aligned squares; without this the browser antialiases
  // every edge and a phone camera has a measurably worse time locking on.
  svg.setAttribute('shape-rendering', 'crispEdges');

  let d = '';
  for (let i = 0; i < modules.length; i += 1) {
    if (modules[i] === '1') {
      d += `M${i % width} ${Math.floor(i / width)}h1v1h-1z`;
    }
  }
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', 'currentColor');
  svg.append(path);

  target.replaceChildren(svg);
}

$('totp-enable')?.addEventListener('click', async (e) => {
  await withLoading(e.currentTarget, async () => {
    const enrollment = await post('/account/totp/start', {});
    enrollDialog.dataset.token = enrollment.token;
    $('totp-secret').textContent = enrollment.secret;
    drawQr($('qr'), enrollment.qr);
    $('totp-code').value = '';
    $('totp-error').hidden = true;
    openModal(enrollDialog);
  }, { errorTitle: 'Could not start enrollment' });
});

$('secret-copy')?.addEventListener('click', () => copyText($('totp-secret').textContent, 'Secret copied'));

$('totp-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const error = $('totp-error');
  error.hidden = true;

  await withLoading($('totp-verify'), async () => {
    try {
      const { recovery_codes: codes } = await post('/account/totp/enable', {
        token: enrollDialog.dataset.token,
        code: $('totp-code').value,
      });
      closeModal(enrollDialog);
      showCodes(codes);
    } catch (err) {
      // A wrong code is the expected outcome of a two-step flow, not an
      // incident: it belongs under the field, not in a toast that covers it.
      error.textContent = err.message;
      error.hidden = false;
      $('totp-code').select();
    }
  });
});

$('totp-disable')?.addEventListener('click', async (e) => {
  const ok = await confirm({
    title: 'Turn off two-factor authentication?',
    message:
      'Your password alone will get into this host. Your recovery codes stop working, and enrolling again means scanning a new code.',
    confirmLabel: 'Turn it off',
    danger: true,
  });
  if (!ok) return;

  await withLoading(e.currentTarget, async () => {
    await post('/account/totp/disable', {});
    toastOk('Two-factor authentication is off');
    window.location.reload();
  }, { errorTitle: 'Could not turn two-factor off' });
});

$('recovery-regen')?.addEventListener('click', async (e) => {
  const ok = await confirm({
    title: 'Generate new recovery codes?',
    message: 'Your current codes stop working immediately, including any you have written down.',
    confirmLabel: 'Generate',
  });
  if (!ok) return;

  await withLoading(e.currentTarget, async () => {
    const { recovery_codes: codes } = await post('/account/recovery', {});
    showCodes(codes);
  }, { errorTitle: 'Could not generate new codes' });
});

// ─── The recovery-code reveal ────────────────────────────────────────────────

const revealDialog = $('recovery-reveal');
let revealed = [];

function showCodes(codes) {
  revealed = codes;
  render($('codes'), ...codes.map((code) => h('li', {}, code)));
  // The page's SSR'd state (the on/off pill, the codes-remaining count) is stale
  // the moment these exist, and re-deriving it in JS would be a second source of
  // truth for the same fact. Reload once they are dismissed — by which point the
  // codes are copied, saved or downloaded.
  openModal(revealDialog, { onClose: () => window.location.reload() });
}

$('codes-copy')?.addEventListener('click', () => copyText(revealed.join('\n'), 'Codes copied'));

$('codes-download')?.addEventListener('click', () => {
  const text = [
    'Vantage recovery codes',
    `Generated ${absolute(new Date().toISOString())}`,
    `Host ${window.location.host}`,
    '',
    'Each code signs you in once, in place of your authenticator app.',
    '',
    ...revealed,
    '',
  ].join('\n');

  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const link = h('a', { href: url, download: 'vantage-recovery-codes.txt' });
  link.click();
  URL.revokeObjectURL(url);
});

// ─── Profile ─────────────────────────────────────────────────────────────────

const nameForm = $('name-form');
const nameInput = $('account-name');
const nameError = $('name-error');

/* The name the page was rendered with. Kept so a rename can be told from a
 * no-op, and so the initial fallback has a letter to draw. */
const renderedName = nameInput?.value ?? '';

nameForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  nameError.hidden = true;

  const name = nameInput.value.trim();
  if (name === renderedName) return;

  await withLoading($('name-save'), async () => {
    try {
      await post('/account/name', { name });
    } catch (err) {
      // A taken name and a too-short one are both the operator's to fix, and
      // both belong beside the field rather than in a toast that outlives it.
      nameError.textContent = err.message;
      nameError.hidden = false;
      return;
    }
    // The sidebar renders the name on every page from the server-side struct,
    // so it stays stale until a reload. Same reasoning as the recovery flow.
    window.location.reload();
  }, { errorTitle: 'Could not change the name' });
});

// ─── Profile picture ─────────────────────────────────────────────────────────

const avatarInput = $('avatar-input');
const avatarPreview = $('avatar-preview');
const avatarInitial = $('avatar-initial');
const avatarRemove = $('avatar-remove');
const avatarError = $('avatar-error');

/* Which stand-in shows. The page is server-rendered without being told whether
 * an image exists, so the <img> is asked to load and its own outcome decides:
 * one request answers the question, rather than a second endpoint reporting on
 * the first. */
function showInitial() {
  avatarPreview.hidden = true;
  avatarInitial.textContent = (renderedName[0] || '?').toUpperCase();
  avatarInitial.hidden = false;
  avatarRemove.hidden = true;
}

avatarPreview?.addEventListener('load', () => {
  avatarPreview.hidden = false;
  avatarInitial.hidden = true;
  avatarRemove.hidden = false;
});
avatarPreview?.addEventListener('error', showInitial);

$('avatar-choose')?.addEventListener('click', () => avatarInput.click());

avatarInput?.addEventListener('change', async () => {
  const file = avatarInput.files?.[0];
  if (!file) return;
  avatarError.hidden = true;

  await withLoading($('avatar-choose'), async () => {
    try {
      // The raw file as the body: one field needs no multipart envelope. The
      // server sniffs the bytes and ignores this Content-Type, so it is a hint
      // for anything in between, not a claim the server acts on.
      await request('/account/avatar', {
        method: 'POST',
        body: file,
        headers: { 'Content-Type': file.type || 'application/octet-stream' },
      });
    } catch (err) {
      avatarError.textContent = err.message;
      avatarError.hidden = false;
      return;
    }
    // The URL never changes, so the ETag is what busts the cache: a plain
    // reload revalidates and picks up the new bytes.
    window.location.reload();
  }, { errorTitle: 'Could not save the picture' });

  // Let the same file be picked again after a failure.
  avatarInput.value = '';
});

avatarRemove?.addEventListener('click', async (e) => {
  const ok = await confirm({
    title: 'Remove your picture?',
    message: 'Your sidebar goes back to showing the first letter of your name.',
    confirmLabel: 'Remove',
    danger: true,
  });
  if (!ok) return;

  await withLoading(e.currentTarget, async () => {
    await del('/account/avatar');
    window.location.reload();
  }, { errorTitle: 'Could not remove the picture' });
});

loadSessions();
