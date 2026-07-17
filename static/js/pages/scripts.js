/* Scripts: what runs on this host, when it last ran, and what it said.
 *
 * The page can run a script and read history. It cannot write one — the list is
 * config.json's, and the UI never pretends otherwise.
 */

import { get, post } from '../core/api.js';
import { relative, absolute, latency } from '../core/format.js';
import {
  h,
  icon,
  pill,
  render,
  emptyRow,
  emptyState,
  reportError,
  toastOk,
  toastErr,
  withLoading,
  openModal,
  confirm,
  copyText,
} from '../core/ui.js';

const $ = (id) => document.getElementById(id);

const scriptList = $('scripts');
const runsBody = $('runs-body');
const runCount = $('run-count');

/** Server-side cap on a run, learned from /scripts/data rather than hardcoded. */
let timeoutSeconds = 30;
/** The script whose history the runs table is currently showing, if any. */
let filter = null;

// ─── Output ──────────────────────────────────────────────────────────────────

/** Shows one run's captured output. */
function showOutput(run) {
  const dialog = h(
    'dialog',
    { class: 'modal', style: { width: 'min(760px, calc(100vw - 32px))' } },
    h(
      'div',
      { class: 'modal-header' },
      h('span', { class: 'modal-title' }, run.script_name),
      run.ok ? pill('ok', 'succeeded') : pill('down', 'failed')
    ),
    h(
      'div',
      { class: 'modal-body' },
      h(
        'p',
        { class: 'modal-desc' },
        `${run.trigger === 'manual' ? `Run by ${run.actor || 'someone'}` : 'Ran on schedule'}`,
        ` ${relative(run.started_at)} · took ${latency(run.duration_ms)}`,
        // A killed process has no exit code, and saying "exit 0" for one would
        // be a lie in the direction that costs the most.
        run.exit_code === null || run.exit_code === undefined ? ' · no exit code' : ` · exit ${run.exit_code}`
      ),
      run.output
        ? h('pre', { class: 'run-output' }, h('code', {}, run.output))
        : // Silence is the normal result of a script that worked, and reading
          // "(no output)" is better than staring at an empty box wondering
          // whether the page failed to load it.
          h('p', { class: 'muted' }, 'The script produced no output.')
    ),
    h(
      'div',
      { class: 'modal-footer' },
      run.output
        ? h(
            'button',
            { class: 'btn quiet', type: 'button', onclick: () => copyText(run.output, 'Output copied') },
            icon('copy'),
            'Copy'
          )
        : null,
      h('button', { class: 'btn', type: 'button', 'data-close': '' }, 'Close')
    )
  );
  document.body.append(dialog);
  openModal(dialog, { onClose: () => setTimeout(() => dialog.remove(), 400) });
}

// ─── Script cards ────────────────────────────────────────────────────────────

function scheduleLine(s) {
  if (s.schedule_error) {
    // The worst state this page can render is a script the operator believes is
    // automated. Say the expression is broken, in red, next to the expression.
    return h(
      'div',
      { class: 'script-schedule bad' },
      icon('triangle-alert'),
      h('code', {}, s.schedule),
      h('span', {}, `never runs — ${s.schedule_error}`)
    );
  }
  if (!s.schedule) {
    return h('div', { class: 'script-schedule' }, icon('play'), h('span', { class: 'muted' }, 'Runs only when you press Run'));
  }
  return h(
    'div',
    { class: 'script-schedule' },
    icon('clock'),
    h('code', {}, s.schedule),
    s.next_run
      ? h('span', { class: 'muted', title: absolute(s.next_run) }, `next ${relative(s.next_run)}`)
      : // A parseable schedule with no next run inside a year is a date that
        // never comes (February 30th). It is valid and it is still never.
        h('span', { class: 'bad' }, 'never — no such date')
  );
}

function lastRunLine(s) {
  if (!s.last_run) {
    return h('span', { class: 'muted' }, 'Never run');
  }
  const r = s.last_run;
  return h(
    'button',
    { class: 'link-btn', type: 'button', onclick: () => showOutput(r) },
    r.ok ? pill('ok', 'ok') : pill('down', 'failed'),
    h('span', { title: absolute(r.started_at) }, relative(r.started_at))
  );
}

function scriptCard(s) {
  const runBtn = h(
    'button',
    {
      class: 'btn sm',
      type: 'button',
      disabled: s.running ? '' : null,
      onclick: (e) => runScript(s, e.currentTarget),
    },
    icon('play'),
    s.running ? 'Running…' : 'Run'
  );

  return h(
    'div',
    { class: 'script', id: `script-${s.id}` },
    h(
      'div',
      { class: 'script-head' },
      icon('square-terminal', { size: 20 }),
      h('span', { class: 'script-name' }, s.name),
      h('span', { class: 'spacer' }),
      s.running ? pill('warn', 'running', { pulse: true }) : null
    ),
    h(
      'div',
      { class: 'script-body' },
      s.description ? h('p', { class: 'script-desc' }, s.description) : null,
      h('code', { class: 'script-command' }, s.command),
      s.cwd ? h('div', { class: 'script-cwd' }, icon('folder'), h('span', {}, s.cwd)) : null,
      scheduleLine(s)
    ),
    h(
      'div',
      { class: 'script-foot' },
      lastRunLine(s),
      h('span', { class: 'spacer' }),
      h(
        'button',
        { class: 'btn sm quiet', type: 'button', onclick: () => showHistory(s) },
        icon('history'),
        'History'
      ),
      runBtn
    )
  );
}

// ─── Running ─────────────────────────────────────────────────────────────────

async function runScript(s, btn) {
  // The sudo prompt asks whether you are you; it does not say what you are about
  // to execute. For the app's one arbitrary-command path, the command itself is
  // the thing worth reading before it happens.
  const go = await confirm({
    title: `Run ${s.name}?`,
    message: 'This runs on the host, as the Vantage user:',
    detail: h('code', { class: 'script-command' }, s.command),
    confirmLabel: 'Run it',
  });
  if (!go) return;

  await withLoading(
    btn,
    async () => {
      const run = await post(`/scripts/${encodeURIComponent(s.id)}/run`, undefined, {
        // The server waits out the script (up to its timeout) before answering,
        // so the client must outlast it — otherwise we abort at the exact moment
        // it is about to tell us what happened.
        timeout: (timeoutSeconds + 15) * 1000,
      });
      if (run.ok) {
        toastOk(`${s.name} finished`, `Took ${latency(run.duration_ms)}.`);
      } else {
        toastErr(`${s.name} failed`, run.exit_code === null ? 'It did not finish.' : `Exit code ${run.exit_code}.`);
      }
      // Straight to the output either way: you pressed a button to see what a
      // command does, and a toast is not that.
      showOutput({
        script_name: s.name,
        trigger: 'manual',
        started_at: new Date().toISOString(),
        ...run,
      });
      await load();
    },
    { errorTitle: `Could not run ${s.name}` }
  );
}

// ─── Runs table ──────────────────────────────────────────────────────────────

function runRow(r) {
  return h(
    'tr',
    {},
    h('td', { title: absolute(r.started_at) }, relative(r.started_at)),
    h('td', {}, r.script_name),
    h(
      'td',
      {},
      r.trigger === 'manual'
        ? h('span', {}, `by ${r.actor || 'someone'}`)
        : h('span', { class: 'muted' }, 'schedule')
    ),
    h('td', {}, latency(r.duration_ms)),
    // A real button rather than a click handler on the <tr>: the row is the only
    // way to reach the output, and a table row is not announced as anything a
    // keyboard user would think to press.
    h(
      'td',
      {},
      h(
        'button',
        { class: 'link-btn', type: 'button', onclick: () => showOutput(r) },
        r.ok ? pill('ok', 'ok') : pill('down', 'failed'),
        h('span', { class: 'sr-only' }, `Show output for ${r.script_name}`),
        icon('chevron-right')
      )
    )
  );
}

function renderRuns(runs, { filtered = null } = {}) {
  runCount.textContent = String(runs.length);
  render(
    runsBody,
    ...(runs.length
      ? runs.map(runRow)
      : [
          emptyRow(
            5,
            filtered ? `${filtered} has not run yet.` : 'Nothing has run yet. Scheduled runs appear here on their own.'
          ),
        ])
  );
}

/** Narrows the runs table to one script, using its own (deeper) history. */
async function showHistory(s) {
  try {
    const { runs } = await get(`/scripts/${encodeURIComponent(s.id)}/runs`);
    filter = s;
    renderRuns(runs, { filtered: s.name });
    $('runs').scrollIntoView({ behavior: 'smooth', block: 'center' });
    showFilterChip(s);
  } catch (err) {
    reportError(err, `Could not read ${s.name}'s history`);
  }
}

function showFilterChip(s) {
  const head = $('run-count').parentElement;
  head.querySelector('.filter-chip')?.remove();
  head.append(
    h(
      'button',
      {
        class: 'filter-chip',
        type: 'button',
        onclick: () => {
          filter = null;
          head.querySelector('.filter-chip')?.remove();
          load();
        },
      },
      h('span', {}, s.name),
      icon('x')
    )
  );
}

// ─── Load ────────────────────────────────────────────────────────────────────

async function load() {
  try {
    const data = await get('/scripts/data');
    timeoutSeconds = data.timeout_seconds ?? timeoutSeconds;

    if (data.scripts.length) {
      render(scriptList, ...data.scripts.map(scriptCard));
    } else {
      // The template's callout already explains config.json; repeating it here
      // would be two answers to one question.
      render(
        scriptList,
        emptyState({ icon: 'square-terminal', title: 'No scripts', sub: 'Nothing is configured to run on this host.' })
      );
    }

    // A filtered table survives a reload — pressing Run should not silently
    // throw away the history you were reading.
    if (filter) {
      const still = data.scripts.find((s) => s.id === filter.id);
      if (still) {
        await showHistory(still);
        return;
      }
      filter = null;
    }
    renderRuns(data.runs || []);

    highlightTarget();
  } catch (err) {
    reportError(err, 'Could not load your scripts');
    renderRuns([]);
  }
}

/** Ctrl+K sends `/scripts#<id>`; make the landing obvious. */
function highlightTarget() {
  const id = location.hash.slice(1);
  if (!id) return;
  const card = document.getElementById(`script-${id}`);
  if (!card) return;
  card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  card.classList.add('is-target');
  setTimeout(() => card.classList.remove('is-target'), 2000);
}

window.addEventListener('hashchange', highlightTarget);

load();
