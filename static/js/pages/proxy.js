/* Proxy — the route manager.
 *
 * This file did not exist. proxy.html has always shipped with an empty
 * <div id="proxy-app"> and a script tag pointing at a 404, so the page rendered
 * a heading, two dead buttons and nothing else. Every endpoint below has been
 * sitting there fully implemented and unreachable.
 *
 * Two details of the backend contract shape the UI:
 *
 *   - The password hash is never serialised back (only `has_auth`), and the
 *     UPDATE COALESCEs it. So a blank password field on an edit means "keep the
 *     current one" — it cannot mean "remove it", and the UI must not imply it
 *     does. Removing auth is done by clearing the username, because has_auth is
 *     `user AND hash`.
 *
 *   - Saving regenerates the config files but does NOT reload the proxy. That
 *     is what Apply does. A route can therefore be saved and live in the
 *     database while the running proxy has never heard of it, which is a real
 *     state an operator has to be able to see — hence the pending banner.
 */

import { get, post, del, postUrlEncoded, ApiError } from '../core/api.js';
import { h, icon, render, pill, emptyRow, emptyState, skeletonRows, reportError, confirm, toast, toastOk, withLoading, openModal, closeModal, copyText, diffView } from '../core/ui.js';
import { previewAndApply } from '../core/apply-flow.js';
import { num } from '../core/format.js';

const tilesEl = document.getElementById('tiles');
const bodyEl = document.getElementById('routes-body');
const countEl = document.getElementById('route-count');
const kindChip = document.getElementById('kind-chip');
const addBtn = document.getElementById('add-btn');
const applyBtn = document.getElementById('apply-btn');
const importBtn = document.getElementById('import-btn');

const editor = document.getElementById('editor');
const form = document.getElementById('editor-form');
const previewDlg = document.getElementById('preview');

const f = {
  id: document.getElementById('f-id'),
  subdomain: document.getElementById('f-subdomain'),
  container: document.getElementById('f-container'),
  scheme: document.getElementById('f-scheme'),
  host: document.getElementById('f-host'),
  port: document.getElementById('f-port'),
  ssl: document.getElementById('f-ssl'),
  cf: document.getElementById('f-cf'),
  authUser: document.getElementById('f-auth-user'),
  authPass: document.getElementById('f-auth-pass'),
  rate: document.getElementById('f-rate'),
  access: document.getElementById('f-access'),
  extra: document.getElementById('f-extra'),
  enabled: document.getElementById('f-enabled'),
};

let state = { routes: [], containers: [], kind: '', configDir: null, cfApi: false };
/** Set when a save has changed the generated config but Apply hasn't run yet. */
let pending = false;

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

function renderTiles(d) {
  const disabled = d.total - d.enabled_count;
  render(
    tilesEl,
    tile('Routes', num(d.total), disabled ? `${num(disabled)} disabled` : 'all enabled', null, 'route'),
    tile('Serving', num(d.enabled_count), 'after the last apply', null, 'globe'),
    tile('Backend', d.proxy_kind, d.config_dir || 'no config directory', null, 'server'),
    tile(
      'Cloudflare',
      d.cloudflared_api ? 'Connected' : 'Off',
      d.cloudflared_api ? 'tunnels can be imported' : 'no API token configured',
      null,
      'zap'
    )
  );
}

/* =======================================================================
   Pending-apply banner
   ======================================================================= */

function setPending(on) {
  pending = on;
  applyBtn.classList.toggle('attn', on);

  let banner = document.getElementById('pending-banner');
  if (!on) {
    banner?.remove();
    return;
  }
  if (banner) return;

  banner = h(
    'div',
    { class: 'callout warn', id: 'pending-banner', role: 'status' },
    icon('triangle-alert'),
    h(
      'div',
      { class: 'callout-body' },
      h('strong', {}, 'Your changes are saved but not live yet.'),
      ' The config files have been rewritten. The running proxy keeps serving the old routes until you apply and reload.'
    )
  );
  document.querySelector('.page-head').after(banner);
}

/* =======================================================================
   Routes table
   ======================================================================= */

function upstream(r) {
  const url = `${r.target_scheme}://${r.target_host}:${r.target_port}`;
  return h('div', { class: 'upstream' }, h('span', { class: 'mono' }, url), r.container ? h('span', { class: 'sub' }, r.container) : null);
}

function protections(r) {
  const out = [];
  if (r.ssl_managed) out.push(pill('ok', 'TLS'));
  if (r.cloudflare_proxied) out.push(pill('acc', 'CF'));
  if (r.has_auth) out.push(pill('warn', `auth: ${r.http_auth_user}`));
  if (r.rate_limit_rps) out.push(pill('info', `${num(r.rate_limit_rps)}/s`));
  if (r.access_rules_json) out.push(pill('info', 'rules'));
  if (!out.length) return h('span', { class: 'muted' }, 'none');
  return h('div', { class: 'pill-row' }, ...out);
}

function renderRoutes(routes) {
  countEl.textContent = num(routes.length);

  if (!routes.length) {
    render(
      bodyEl,
      h(
        'tr',
        {},
        h(
          'td',
          { colspan: 5 },
          emptyState({
            icon: 'route',
            title: 'No routes yet',
            sub: 'Add one to point a domain at a container or a port on this host.',
            action: h('button', { class: 'btn sm', onclick: () => openEditor() }, 'Add route'),
          })
        )
      )
    );
    return;
  }

  render(
    bodyEl,
    ...routes.map((r) =>
      h(
        'tr',
        { class: r.enabled ? '' : 'is-disabled' },
        h(
          'td',
          {},
          h(
            'a',
            { class: 'domain', href: `https://${r.subdomain}`, target: '_blank', rel: 'noopener noreferrer' },
            r.subdomain,
            icon('external-link')
          )
        ),
        h('td', {}, upstream(r)),
        h('td', {}, protections(r)),
        h(
          'td',
          {},
          h(
            'label',
            { class: 'switch' },
            h('input', {
              type: 'checkbox',
              checked: r.enabled,
              'aria-label': `Enable ${r.subdomain}`,
              'data-destructive': '',
              onchange: (e) => toggleRoute(r, e.currentTarget),
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
            h(
              'button',
              { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': `Show the generated config for ${r.subdomain}`, onclick: (e) => showPreview(r, e.currentTarget) },
              icon('file-text')
            ),
            h(
              'button',
              { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': `Edit ${r.subdomain}`, onclick: () => openEditor(r) },
              icon('pencil')
            ),
            h(
              'button',
              { class: 'btn sm ghost icon-only', type: 'button', 'data-destructive': '', 'aria-label': `Delete ${r.subdomain}`, onclick: (e) => removeRoute(r, e.currentTarget) },
              icon('trash-2')
            )
          )
        )
      )
    )
  );
}

/* =======================================================================
   Actions
   ======================================================================= */

async function toggleRoute(r, input) {
  const next = input.checked;
  try {
    await postUrlEncoded(`/proxy/${r.id}/toggle`, { enabled: next });
    r.enabled = next;
    input.closest('tr').classList.toggle('is-disabled', !next);
    setPending(true);
  } catch (e) {
    input.checked = !next; // the server said no; the switch must not claim otherwise
    reportError(e, "Couldn't change that route");
  }
}

async function removeRoute(r, btn) {
  const ok = await confirm({
    title: `Delete ${r.subdomain}?`,
    message: `The route will be removed and its config file rewritten. ${r.subdomain} will stop resolving to ${r.target_host}:${r.target_port} once you apply.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!ok) return;

  await withLoading(btn, async () => {
    await del(`/proxy/${r.id}`);
    toastOk('Route deleted', r.subdomain);
    setPending(true);
    load();
  });
}

async function showPreview(r, btn) {
  await withLoading(btn, async () => {
    const p = await get(`/proxy/${r.id}/preview`);
    document.getElementById('preview-title').textContent = `Generated ${p.kind} config`;
    document.getElementById('preview-file').textContent = p.file;
    document.getElementById('preview-body').textContent = p.config;
    document.getElementById('preview-copy').onclick = () => copyText(p.config, 'Config copied');
    openModal(previewDlg);
  });
}

const STATUS_PILL = { added: 'ok', removed: 'down', changed: 'warn' };

/**
 * The apply POST + result reporting. Requests a 60-second armed revert; returns
 * the arm descriptor (so the flow runs the countdown) or null on a partial apply,
 * where the server arms nothing and the operator deals with the errors.
 */
async function runApply() {
  const r = await post('/proxy/apply?revert=60');
  // The report carries per-route errors alongside a success count: a partial
  // apply is the common failure here (one bad extra_config block), and
  // reporting it as a flat success would be a lie.
  if (r.errors?.length) {
    toast('warn', `Applied ${num(r.written)} of ${num(r.written + r.errors.length)}`, r.errors.join('\n'), { timeout: 0 });
    return null;
  }
  toastOk('Applied and reloaded', r.reload || `${num(r.written)} config files written.`);
  setPending(false);
  return r.revert || null;
}

// Apply opens a dry-run first: the operator sees the old→new of every config
// file — the route about to stop resolving, the auth block about to appear —
// before the running proxy is reloaded onto it.
applyBtn.addEventListener('click', () => {
  previewAndApply({
    title: 'Apply proxy configuration',
    applyLabel: 'Apply & reload',
    loadPreview: async () => {
      const res = await get('/proxy/preview');
      const files = (res.files || []).filter((f) => f.status !== 'unchanged');
      if (!files.length) {
        return {
          node: h(
            'div',
            { class: 'diff-view is-empty' },
            res.config_dir ? 'The generated config already matches what is on disk — nothing to apply.' : 'No config directory is set, so nothing is written to disk.'
          ),
          empty: true,
        };
      }
      const node = h(
        'div',
        { class: 'diff-file-list' },
        ...files.map((file) =>
          h(
            'div',
            { class: 'diff-file' },
            h(
              'div',
              { class: 'diff-file-head' },
              h('span', { class: 'mono' }, file.file),
              pill(STATUS_PILL[file.status] || 'idle', file.status),
              h('span', { class: 'sub' }, `+${num(file.added)} −${num(file.removed)}`)
            ),
            diffView(file.diff)
          )
        )
      );
      return { node, empty: false };
    },
    apply: runApply,
    confirm: async (token) => {
      await post('/proxy/apply/confirm', { token });
      toastOk('Changes kept', 'The proxy is serving the new configuration.');
    },
    revert: async (token) => {
      await post('/proxy/apply/revert', { token });
      // Reverting restores the previous config files, so the saved routes are
      // once again ahead of what the running proxy serves.
      setPending(true);
      toast('warn', 'Reverted', 'The proxy was rolled back to its previous configuration.');
    },
    onDone: load,
  });
});

importBtn.addEventListener('click', () =>
  withLoading(importBtn, async () => {
    const r = await post('/proxy/import');
    toastOk('Imported from Cloudflare', `${num(r.imported)} added · ${num(r.updated)} updated · ${num(r.skipped)} skipped.`);
    if (r.imported || r.updated) setPending(true);
    load();
  })
);

/* =======================================================================
   Editor
   ======================================================================= */

function fillContainers(containers, selected) {
  render(
    f.container,
    h('option', { value: '' }, 'Not a container'),
    ...containers.map((c) => h('option', { value: c.identifier, selected: c.identifier === selected }, c.name))
  );
}

// Picking a container fills in its hostname — in a Docker network the service
// name *is* the host, and re-typing it is the most common way to get it wrong.
f.container.addEventListener('change', () => {
  const id = f.container.value;
  if (id && !f.host.value.trim()) f.host.value = id;
});

function openEditor(r = null) {
  form.reset();
  document.getElementById('editor-title').textContent = r ? `Edit ${r.subdomain}` : 'Add route';
  document.getElementById('editor-save').textContent = r ? 'Save changes' : 'Add route';
  document.getElementById('access-error').hidden = true;

  f.id.value = r?.id ?? '';
  f.subdomain.value = r?.subdomain ?? '';
  f.scheme.value = r?.target_scheme ?? 'http';
  f.host.value = r?.target_host ?? '';
  f.port.value = r?.target_port ?? '';
  f.ssl.checked = r?.ssl_managed ?? false;
  f.cf.checked = r?.cloudflare_proxied ?? false;
  f.authUser.value = r?.http_auth_user ?? '';
  f.authPass.value = '';
  f.rate.value = r?.rate_limit_rps ?? '';
  f.access.value = r?.access_rules_json ?? '';
  f.extra.value = r?.extra_config ?? '';
  f.enabled.checked = r?.enabled ?? true;

  fillContainers(state.containers, r?.container ?? '');

  // The password is not readable, so the field means different things on an
  // edit and on a create. Say which one this is.
  document.getElementById('auth-hint').textContent = r?.has_auth
    ? 'Leave blank to keep the current password. To remove auth entirely, clear the username.'
    : 'Sets the password for this route.';

  openModal(editor);
}

addBtn.addEventListener('click', () => openEditor());

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Validate the JSON here rather than letting the server reject the whole
  // save with a bare 400 that names no field.
  const errEl = document.getElementById('access-error');
  errEl.hidden = true;
  const access = f.access.value.trim();
  if (access) {
    try {
      JSON.parse(access);
    } catch (err) {
      errEl.textContent = `That isn't valid JSON: ${err.message}`;
      errEl.hidden = false;
      f.access.closest('.field').classList.add('has-error');
      f.access.focus();
      return;
    }
  }
  f.access.closest('.field').classList.remove('has-error');

  const id = f.id.value;
  const payload = {
    subdomain: f.subdomain.value.trim(),
    target_host: f.host.value.trim(),
    target_port: f.port.value,
    target_scheme: f.scheme.value,
    container: f.container.value || undefined,
    ssl_managed: f.ssl.checked,
    cloudflare_proxied: f.cf.checked,
    http_auth_user: f.authUser.value.trim() || undefined,
    // Blank on an edit means "keep": send nothing and let the server COALESCE.
    http_auth_password: f.authPass.value || undefined,
    rate_limit_rps: f.rate.value || undefined,
    access_rules_json: access || undefined,
    extra_config: f.extra.value.trim() || undefined,
    enabled: f.enabled.checked,
  };

  const saveBtn = document.getElementById('editor-save');
  try {
    await withLoading(saveBtn, () => postUrlEncoded(id ? `/proxy/${id}` : '/proxy', payload));
    toastOk(id ? 'Route saved' : 'Route added', payload.subdomain);
    closeModal(editor);
    setPending(true);
    load();
  } catch (err) {
    // A 409 here is the unique index on subdomain — the one error worth naming
    // precisely, because "conflict" tells an operator nothing.
    if (err instanceof ApiError && err.status === 409) {
      toast('error', "That domain is already routed", `A route for ${payload.subdomain} already exists. Edit that one instead.`);
    }
    // withLoading already reported anything else.
  }
});

/* =======================================================================
   Load
   ======================================================================= */

async function load() {
  render(bodyEl, ...skeletonRows(5));
  try {
    const d = await get('/proxy/data');
    state = {
      routes: d.routes || [],
      containers: d.containers || [],
      kind: d.proxy_kind,
      configDir: d.config_dir,
      cfApi: !!d.cloudflared_api,
    };

    kindChip.textContent = d.proxy_kind;
    importBtn.hidden = !state.cfApi;

    renderTiles(d);
    renderRoutes(state.routes);
  } catch (e) {
    reportError(e, "Couldn't load the routes");
    render(tilesEl, emptyState({ degraded: true, title: "Couldn't load the proxy configuration", sub: e?.message }));
    render(bodyEl, emptyRow(5, 'Unavailable.'));
  }
}

load();
