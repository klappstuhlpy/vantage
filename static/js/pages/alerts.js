/* Alerts: which sinks exist, whether they're firing, and what actually got
 * delivered.
 *
 * The page is read-mostly. The only things it can change are the two switches
 * (a sink's on/off, and the sign-in alert), both sudo-gated server-side — so a
 * failed toggle has to put the switch back, since the checkbox has already
 * moved by the time we hear about it.
 */

import { get, post } from '../core/api.js';
import { relative, absolute } from '../core/format.js';
import { h, icon, pill, render, emptyRow, reportError, toastOk, toastErr, withLoading } from '../core/ui.js';

const $ = (id) => document.getElementById(id);

const sinkList = $('sinks');
const deliveriesBody = $('deliveries-body');
const deliveryCount = $('delivery-count');
const adminLoginSwitch = $('on-admin-login');

/** One glyph per sink, so four cards are scannable without reading them. */
const SINK_ICONS = {
  discord: 'message-square',
  ntfy: 'smartphone',
  webhook: 'webhook',
  email: 'mail',
};

// ─── Sinks ───────────────────────────────────────────────────────────────────

function sinkCard(sink) {
  const toggle = h('input', {
    type: 'checkbox',
    checked: sink.enabled ? '' : null,
    disabled: sink.configured ? null : '',
    onchange: (e) => setSink(sink, e.currentTarget),
  });

  const test = h(
    'button',
    {
      class: 'btn sm quiet',
      type: 'button',
      disabled: sink.configured ? null : '',
      onclick: (e) => testSink(sink, e.currentTarget),
    },
    icon('zap'),
    'Test'
  );

  return h(
    'div',
    { class: `sink${sink.configured ? '' : ' absent'}` },
    h(
      'div',
      { class: 'sink-head' },
      icon(SINK_ICONS[sink.name] || 'bell', { size: 20 }),
      h('span', { class: 'sink-name' }, sink.label),
      h('span', { class: 'spacer' }),
      sink.configured ? pill(sink.enabled ? 'ok' : 'idle', sink.enabled ? 'on' : 'off') : pill('idle', 'not set up')
    ),
    h(
      'div',
      { class: 'sink-body' },
      sink.configured
        ? h(
            'div',
            {},
            h('div', { class: 'sink-target' }, sink.target || ''),
            sink.detail ? h('div', { class: 'sink-detail' }, sink.detail) : null
          )
        : // An unconfigured sink's card exists to answer one question: how do I
          // turn this on? So it says the key, not "not configured".
          h(
            'div',
            {},
            h('div', {}, sink.blurb),
            h('div', { class: 'sink-detail' }, h('code', {}, sink.config_key), ' in config.json')
          )
    ),
    h(
      'div',
      { class: 'sink-foot' },
      h('label', { class: 'switch' }, toggle, h('span', { class: 'switch-track', 'aria-hidden': 'true' }), h('span', { class: 'sr-only' }, `${sink.label} enabled`)),
      h('span', { class: 'spacer' }),
      test
    )
  );
}

async function setSink(sink, input) {
  const enabled = input.checked;
  try {
    await post(`/alerts/sinks/${sink.name}`, { enabled });
    sink.enabled = enabled;
    toastOk(enabled ? `${sink.label} alerts on` : `${sink.label} alerts off`);
    await load();
  } catch (err) {
    // The browser already moved the switch; the server said no. Put it back,
    // or the page is now lying about the state of an alarm.
    input.checked = !enabled;
    reportError(err, 'Could not change that sink');
  }
}

async function testSink(sink, btn) {
  await withLoading(btn, async () => {
    const result = await post(`/alerts/test/${sink.name}`);
    if (result.ok) {
      toastOk(`${sink.label} accepted the test`, 'Check that it actually arrived — a sink can accept a message and drop it.');
    } else {
      // Not thrown: the request succeeded, the *delivery* failed, and the
      // reason is the whole point of pressing Test.
      toastErr(`${sink.label} rejected the test`, result.error);
    }
    await load();
  }, { errorTitle: 'Could not send the test' });
}

// ─── Deliveries ──────────────────────────────────────────────────────────────

function deliveryRow(d) {
  return h(
    'tr',
    {},
    h('td', { title: absolute(d.sent_at) }, relative(d.sent_at)),
    h('td', {}, d.sink),
    h(
      'td',
      {},
      h(
        'div',
        { class: 'delivery-title' },
        h('span', {}, d.title),
        // A test that arrived is not evidence that alerting works for events;
        // marking it keeps the log from being read as proof it doesn't have.
        d.test ? pill('idle', 'test') : null
      ),
      d.error ? h('div', { class: 'delivery-error' }, d.error) : null
    ),
    h('td', {}, d.ok ? pill('ok', 'delivered') : pill('down', 'failed'))
  );
}

// ─── Load ────────────────────────────────────────────────────────────────────

async function load() {
  try {
    const data = await get('/alerts/data');

    render(sinkList, ...data.sinks.map(sinkCard));

    adminLoginSwitch.checked = data.on_admin_login;

    const deliveries = data.deliveries || [];
    deliveryCount.textContent = String(deliveries.length);
    if (!deliveries.length) {
      render(
        deliveriesBody,
        emptyRow(4, 'Nothing has been sent yet. Alerts fire on their own — press Test above to prove a sink works.')
      );
      return;
    }
    render(deliveriesBody, ...deliveries.map(deliveryRow));
  } catch (err) {
    reportError(err, 'Could not load your alert settings');
    render(deliveriesBody, emptyRow(4, 'Could not load the delivery log.'));
  }
}

adminLoginSwitch.addEventListener('change', async (e) => {
  const input = e.currentTarget;
  const enabled = input.checked;
  try {
    await post('/alerts/on-admin-login', { enabled });
    toastOk(enabled ? 'Sign-ins will raise an alert' : 'Sign-in alerts off');
  } catch (err) {
    input.checked = !enabled;
    reportError(err, 'Could not change that setting');
  }
});

load();
