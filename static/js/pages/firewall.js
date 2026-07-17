/* Firewall rules and lockouts.
 *
 * Data: GET /firewall/data; POST /firewall/rule, /firewall/rule/:id/toggle,
 * /firewall/lockout, /firewall/lockout/:id/release, /firewall/apply;
 * DELETE /firewall/rule/:id.
 *
 * Rule create and lockout create are axum `Form(...)` extractors — url-encoded,
 * not JSON. Note the server's `enabled` default is INVERTED relative to health's:
 * here an absent field means enabled, and only "false"/"0"/"off" disables. We
 * always send an explicit value rather than relying on either default.
 */

import { get, post, del, postUrlEncoded } from '../core/api.js';
import {
  h,
  icon,
  pill,
  render,
  emptyRow,
  skeletonRows,
  reportError,
  toast,
  confirm,
  openModal,
  closeModal,
  withLoading,
  emptyState,
  diffView,
} from '../core/ui.js';
import { previewAndApply } from '../core/apply-flow.js';
import { relative, num, duration } from '../core/format.js';

const tilesEl = document.getElementById('tiles');
const rulesBody = document.getElementById('rules-body');
const lockBody = document.getElementById('lockouts-body');
const ruleModal = document.getElementById('rule-modal');
const ruleForm = document.getElementById('rule-form');
const $ = (id) => document.getElementById(id);

const ACTION_PILL = { allow: 'ok', deny: 'down', rate_limit: 'warn', geo_block: 'info' };
const ACTION_LABEL = { allow: 'allow', deny: 'deny', rate_limit: 'rate limit', geo_block: 'geo block' };

/* =======================================================================
   Tiles
   ======================================================================= */

function renderTiles(d) {
  const rules = d.rules || [];
  const lockouts = d.lockouts || [];
  const active = lockouts.filter((l) => l.status === 'active');
  const enabled = rules.filter((r) => r.enabled).length;

  const stat = (label, value, sub, iconName, status) =>
    h(
      'div',
      { class: `stat${status ? ` ${status}` : ''}` },
      h('span', { class: 'stat-key' }, icon(iconName), label),
      h('span', { class: 'stat-value' }, value),
      h('span', { class: 'stat-sub' }, sub)
    );

  render(
    tilesEl,
    stat('Backend', d.backend, d.backend === 'disabled' ? 'not filtering' : 'active packet filter', 'brick-wall', d.backend === 'disabled' ? 'warn' : null),
    stat('Rules', num(rules.length), `${enabled} enabled`, 'list', null),
    stat('Lockouts', num(active.length), 'addresses blocked now', 'ban', active.length ? 'down' : null),
    stat(
      'Auto-lockout',
      `${d.auto_threshold}×`,
      // The raw seconds are meaningless at a glance; say it the way an operator
      // would: "5 fails in 15m → blocked 1h".
      `in ${duration(d.auto_window_secs)} → blocked ${duration(d.auto_lockout_secs)}`,
      'shield',
      null
    )
  );
}

/* =======================================================================
   Rules
   ======================================================================= */

function renderRules(rules) {
  $('rule-count').textContent = num(rules.length);

  if (!rules.length) {
    render(
      rulesBody,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 8 },
          emptyState({
            icon: 'brick-wall',
            title: 'No rules yet',
            sub: 'Vantage is not adding any filtering of its own. Add a rule to allow, deny, rate-limit or geo-block traffic.',
            action: h('button', { class: 'btn sm', onclick: openRuleModal }, 'New rule'),
          })
        )
      )
    );
    return;
  }

  render(
    rulesBody,
    ...rules.map((r) =>
      h(
        'tr',
        { dataset: { id: r.id } },
        h('td', {}, pill(ACTION_PILL[r.action] || 'idle', ACTION_LABEL[r.action] || r.action)),
        h('td', { class: 'mono' }, r.source || 'any'),
        h('td', { class: 'mono' }, r.port != null ? String(r.port) : 'any'),
        h('td', { class: 'mono' }, r.proto),
        h('td', { class: 'mono' }, r.country ? `${r.country} · ${r.direction}` : r.rate_per_s ? `${r.rate_per_s}/s · ${r.direction}` : r.direction),
        h('td', { class: 'truncate', style: { maxWidth: '220px' }, title: r.note || '' }, r.note || '—'),
        h(
          'td',
          {},
          h(
            'label',
            { class: 'switch' },
            h('input', {
              type: 'checkbox',
              checked: r.enabled,
              'aria-label': `Rule ${r.id} enabled`,
              'data-destructive': '',
              onchange: (e) => toggleRule(e.currentTarget, r),
            }),
            h('span', { class: 'switch-track' })
          )
        ),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Delete', 'data-destructive': '', 'aria-label': `Delete rule ${r.id}`, onclick: () => removeRule(r) }, icon('trash-2'))
          )
        )
      )
    )
  );
}

async function toggleRule(input, r) {
  input.disabled = true;
  try {
    // The handler is a `Form(TogglePayload)` with a required `enabled` field, so
    // this must be url-encoded and must carry the value. Posting an empty body
    // here answered 422 every time — the switch never worked.
    await postUrlEncoded(`/firewall/rule/${r.id}/toggle`, { enabled: input.checked });
    toast('ok', input.checked ? 'Rule enabled' : 'Rule disabled');
    await load();
  } catch (e) {
    input.checked = !input.checked; // the server said no; the switch must not lie
    reportError(e, "Couldn't toggle the rule");
  } finally {
    input.disabled = false;
  }
}

async function removeRule(r) {
  const what = [ACTION_LABEL[r.action] || r.action, r.source || 'any', r.port ? `port ${r.port}` : null].filter(Boolean).join(' · ');
  const ok = await confirm({
    // Not "on the next apply" — it goes now. And if the host won't remove it,
    // the rule stays listed here rather than vanishing from a dashboard while
    // still filtering packets.
    title: 'Delete this rule?',
    message: `${what}. Vantage removes it from the host now.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;
  try {
    await del(`/firewall/rule/${r.id}`);
    toast('ok', 'Rule deleted');
    await load();
  } catch (e) {
    reportError(e, "Couldn't delete the rule");
  }
}

/* =======================================================================
   Lockouts
   ======================================================================= */

function renderLockouts(rows) {
  $('lockout-count').textContent = num(rows.filter((l) => l.status === 'active').length);

  if (!rows.length) {
    render(lockBody, emptyRow(7, 'No addresses have been locked out.'));
    return;
  }

  render(
    lockBody,
    ...rows.map((l) =>
      h(
        'tr',
        {},
        h('td', {}, l.status === 'active' ? pill('down', 'blocked') : pill('idle', l.status)),
        h('td', { class: 'mono' }, l.ip),
        h('td', { class: 'truncate', style: { maxWidth: '220px' }, title: l.reason || '' }, l.reason || '—'),
        h('td', { class: 'num' }, num(l.hit_count)),
        h('td', {}, h('time', { class: 'js-ts', datetime: l.locked_at, title: l.locked_at }, relative(l.locked_at))),
        h('td', {}, l.expires_at ? h('time', { class: 'js-ts', datetime: l.expires_at, title: l.expires_at }, relative(l.expires_at)) : h('span', { class: 'faint' }, 'never')),
        h(
          'td',
          { class: 'actions' },
          l.status === 'active'
            ? h(
                'div',
                { class: 'btn-row' },
                h('button', { class: 'btn sm ghost icon-only', 'data-tip': 'Release', 'data-destructive': '', 'aria-label': `Release ${l.ip}`, onclick: (e) => release(e.currentTarget, l) }, icon('lock-open'))
              )
            : null
        )
      )
    )
  );
}

async function release(btn, l) {
  await withLoading(btn, async () => {
    await post(`/firewall/lockout/${l.id}/release`);
    toast('ok', `Released ${l.ip}`);
    await load();
  }, { errorTitle: `Couldn't release ${l.ip}` });
}

document.getElementById('lockout-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ip = $('lo-ip').value.trim();
  await withLoading($('lockout-submit'), async () => {
    await postUrlEncoded('/firewall/lockout', {
      ip,
      reason: $('lo-reason').value.trim() || undefined,
      duration_secs: $('lo-duration').value || undefined,
    });
    toast('ok', `Blocked ${ip}`);
    e.currentTarget.reset();
    await load();
  }, { errorTitle: `Couldn't block ${ip}` });
});

/* =======================================================================
   Rule modal
   ======================================================================= */

function syncAction() {
  const action = $('r-action').value;
  for (const el of document.querySelectorAll('.action-only')) {
    el.hidden = el.dataset.action !== action;
  }
}

function openRuleModal() {
  ruleForm.reset();
  syncAction();
  openModal(ruleModal);
}

$('r-action').addEventListener('change', syncAction);
document.getElementById('new-rule-btn').addEventListener('click', openRuleModal);

ruleForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const action = $('r-action').value;

  if (action === 'geo_block' && !$('r-country').value.trim()) {
    toast('warn', 'A geo block needs a country', 'Enter an ISO-3166 alpha-2 code, e.g. CN.');
    $('r-country').focus();
    return;
  }

  await withLoading($('rule-save'), async () => {
    await postUrlEncoded('/firewall/rule', {
      action,
      direction: $('r-direction').value,
      proto: $('r-proto').value,
      source: $('r-source').value.trim() || undefined,
      port: $('r-port').value || undefined,
      country: action === 'geo_block' ? $('r-country').value.trim() : undefined,
      rate_per_s: action === 'rate_limit' ? $('r-rate').value || undefined : undefined,
      note: $('r-note').value.trim() || undefined,
      enabled: $('r-enabled').checked, // explicit: the server's default is "enabled"
    });
    closeModal(ruleModal);
    toast('ok', 'Rule created');
    await load();
  }, { errorTitle: "Couldn't create the rule" });
});

/* =======================================================================
   Re-apply
   ======================================================================= */

/**
 * The apply POST + result reporting. Requests a 60-second armed revert; returns
 * the arm descriptor (so the flow can run the countdown) or null when there was
 * nothing to arm.
 */
async function runApply() {
  const res = await post('/firewall/apply?revert=60');
  if (res.skipped) {
    toast('warn', 'Nothing applied', 'No firewall backend is configured on this host.');
    return null;
  }
  const errors = res.errors || [];
  if (errors.length) {
    // Report the first failure verbatim — a firewall that half-applied is
    // exactly when an operator needs the raw command and its stderr.
    toast('error', `Applied ${res.applied}, ${errors.length} failed`, errors[0]);
    console.error('firewall apply errors:', errors);
  } else {
    toast('ok', `Applied ${res.applied} rule${res.applied === 1 ? '' : 's'}`);
  }
  return res.revert || null;
}

// Re-apply opens a dry-run first: the operator reads the exact commands about to
// hit the packet filter — a ruleset that would lock them out is visible here,
// before it is live — then applies, then has a countdown to confirm before it
// reverts itself.
document.getElementById('reapply-btn').addEventListener('click', () => {
  previewAndApply({
    title: 'Re-apply firewall rules',
    applyLabel: 'Apply to host',
    loadPreview: async () => {
      const res = await get('/firewall/preview');
      const lines = res.lines || [];
      const summary =
        res.backend === 'disabled'
          ? h('p', { class: 'modal-desc' }, 'No firewall backend on this host — there is nothing to apply.')
          : h(
              'p',
              { class: 'modal-desc' },
              `${num(res.to_apply)} to apply · ${num(res.already_live)} already live · backend `,
              h('span', { class: 'mono' }, res.backend)
            );
      const node = h(
        'div',
        {},
        summary,
        diffView(lines, { emptyLabel: 'Every enabled rule is already live — nothing to apply.' })
      );
      return { node, empty: res.to_apply === 0 };
    },
    apply: runApply,
    confirm: async (token) => {
      await post('/firewall/apply/confirm', { token });
      toast('ok', 'Changes kept', 'The firewall rules are staying.');
    },
    revert: async (token) => {
      await post('/firewall/apply/revert', { token });
      toast('warn', 'Reverted', 'The applied rules were rolled back.');
    },
    onDone: load,
  });
});

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  try {
    const d = await get('/firewall/data');
    renderTiles(d);
    renderRules(d.rules || []);
    renderLockouts(d.lockouts || []);
  } catch (e) {
    reportError(e, "Couldn't load the firewall");
    render(rulesBody, emptyRow(8, 'Failed to load.'));
    render(lockBody, emptyRow(7, 'Failed to load.'));
  }
}

render(rulesBody, ...skeletonRows(8, 3));
render(lockBody, ...skeletonRows(7, 2));
load();
