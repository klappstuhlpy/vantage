/* Sanitizer — check a file against ClamAV and VirusTotal.
 *
 * ── On saying "clean" ────────────────────────────────────────────────────
 * The one thing this page must never do is imply safety it hasn't established.
 * There are four distinct outcomes and the old table flattened them into two:
 *
 *   detected  — a scanner named a threat.                     Say so, loudly.
 *   clean     — a scanner looked and found nothing.           Say so.
 *   unknown   — VirusTotal has never seen this hash. This is NOT clean; it is
 *               the state every brand-new piece of malware is in.
 *   error/off — nobody looked. Also NOT clean.
 *
 * So the verdict is computed from what actually ran, and the absence of a
 * scanner produces "not checked", never a reassuring green.
 */

import { get, del } from '../core/api.js';
import { h, icon, render, pill, emptyRow, skeletonRows, reportError, confirm, toastOk, copyText, withLoading } from '../core/ui.js';
import { bytes, relative, absolute, shortId, num, startTimestampTicker } from '../core/format.js';

/** Mirrors MAX_UPLOAD_BYTES in src/sanitizer/routes.rs. */
const MAX_BYTES = 16 * 1024 * 1024;

const dropEl = document.getElementById('drop');
const inputEl = document.getElementById('file-input');
const progressEl = document.getElementById('progress');
const progressBar = document.getElementById('progress-bar');
const resultEl = document.getElementById('result');
const bodyEl = document.getElementById('history-body');
const countEl = document.getElementById('history-count');
const refreshBtn = document.getElementById('refresh-btn');

document.getElementById('drop-hint').textContent = `Up to ${bytes(MAX_BYTES, 0)}`;

/* =======================================================================
   Verdict
   ======================================================================= */

/**
 * Reduce a scan row to one honest headline.
 * @returns {{tone: 'down'|'ok'|'warn'|'idle', title: string, detail: string}}
 */
function verdict(s) {
  const clamRan = s.clamav_clean != null;
  const vtRan = s.vt_status && s.vt_status !== 'error';

  if (s.clamav_clean === 0) {
    return { tone: 'down', title: 'Threat found', detail: s.clamav_virus ? `ClamAV identified ${s.clamav_virus}.` : 'ClamAV flagged this file.' };
  }
  if (s.vt_status === 'detected') {
    const n = s.vt_positives ?? 0;
    const t = s.vt_total ?? 0;
    return { tone: 'down', title: 'Threat found', detail: `${num(n)} of ${num(t)} VirusTotal engines flagged this file.` };
  }
  if (!clamRan && !vtRan) {
    return { tone: 'warn', title: 'Not checked', detail: 'No scanner was available, so nothing examined this file. Its hash was recorded.' };
  }
  if (clamRan && s.vt_status === 'unknown') {
    return { tone: 'ok', title: 'No threat found', detail: 'ClamAV found nothing. VirusTotal has never seen this file, so it has no opinion either way.' };
  }
  if (!clamRan && s.vt_status === 'unknown') {
    return { tone: 'warn', title: 'Nothing known about this file', detail: 'VirusTotal has never seen this hash, and ClamAV is not configured. That is not the same as clean.' };
  }
  const who = [clamRan && 'ClamAV', s.vt_status === 'clean' && 'VirusTotal'].filter(Boolean).join(' and ');
  return { tone: 'ok', title: 'No threat found', detail: `${who} found nothing.` };
}

/* =======================================================================
   Result card
   ======================================================================= */

function renderResult(s) {
  const v = verdict(s);
  const iconName = { down: 'circle-x', ok: 'circle-check', warn: 'triangle-alert', idle: 'circle-help' }[v.tone];

  render(
    resultEl,
    h(
      'div',
      { class: `card verdict ${v.tone}`, role: 'status' },
      h(
        'div',
        { class: 'card-body verdict-body' },
        h('span', { class: 'verdict-icon' }, icon(iconName, { size: 24 })),
        h(
          'div',
          { class: 'verdict-text' },
          h('span', { class: 'verdict-title' }, v.title),
          h('span', { class: 'verdict-detail' }, v.detail),
          h(
            'dl',
            { class: 'kv verdict-kv' },
            h('dt', {}, 'File'),
            h('dd', {}, s.filename),
            h('dt', {}, 'Size'),
            h('dd', { class: 'mono' }, bytes(s.file_size)),
            h('dt', {}, 'SHA-256'),
            h(
              'dd',
              { class: 'mono hash-row' },
              h('span', { class: 'hash' }, s.sha256),
              h(
                'button',
                { class: 'btn sm ghost icon-only', type: 'button', 'aria-label': 'Copy hash', onclick: () => copyText(s.sha256, 'Hash copied') },
                icon('copy')
              )
            )
          ),
          s.vt_url
            ? h(
                'a',
                { class: 'btn sm outline verdict-link', href: s.vt_url, target: '_blank', rel: 'noopener noreferrer' },
                'Open the VirusTotal report',
                icon('external-link')
              )
            : null
        )
      )
    )
  );
}

/* =======================================================================
   Upload
   ======================================================================= */

/**
 * XHR rather than fetch, for one reason: fetch cannot report upload progress.
 * A 16 MB file over a slow uplink with no feedback is the kind of silence that
 * makes an operator hit the button twice.
 */
function upload(file) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/sanitizer/scan');

    xhr.upload.addEventListener('progress', (e) => {
      if (!e.lengthComputable) return;
      progressEl.classList.remove('indeterminate');
      progressBar.style.width = `${(e.loaded / e.total) * 100}%`;
      // Once the bytes are up, the scan itself takes an unknown time — swap
      // back to indeterminate rather than parking at 100% looking stuck.
      if (e.loaded === e.total) progressEl.classList.add('indeterminate');
    });

    xhr.addEventListener('load', () => {
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* non-JSON error page */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else if (xhr.status === 413) reject(new Error(`The server refused that upload as too large. The limit is ${bytes(MAX_BYTES, 0)}.`));
      else if (xhr.status === 401 || xhr.status === 403) {
        window.location.href = '/login';
        reject(new Error('Your session expired.'));
      } else reject(new Error(body?.error || `The scan failed (HTTP ${xhr.status}).`));
    });

    xhr.addEventListener('error', () => reject(new Error('The connection dropped during the upload.')));
    xhr.addEventListener('abort', () => reject(new Error('Upload cancelled.')));
    xhr.send(form);
  });
}

async function handleFile(file) {
  if (!file) return;

  // Check before sending: a 16 MB round-trip only to be told no is a waste of
  // the operator's time and the host's bandwidth.
  if (file.size > MAX_BYTES) {
    render(
      resultEl,
      h(
        'div',
        { class: 'card verdict warn', role: 'status' },
        h(
          'div',
          { class: 'card-body verdict-body' },
          h('span', { class: 'verdict-icon' }, icon('triangle-alert', { size: 24 })),
          h(
            'div',
            { class: 'verdict-text' },
            h('span', { class: 'verdict-title' }, 'That file is too large'),
            h('span', { class: 'verdict-detail' }, `${file.name} is ${bytes(file.size)}. The limit is ${bytes(MAX_BYTES, 0)}.`)
          )
        )
      )
    );
    return;
  }

  render(resultEl);
  progressEl.hidden = false;
  progressEl.classList.add('indeterminate');
  progressBar.style.width = '';
  dropEl.classList.add('is-busy');

  try {
    const s = await upload(file);
    renderResult(s);
    load();
  } catch (e) {
    reportError(e, "Couldn't scan that file");
  } finally {
    progressEl.hidden = true;
    dropEl.classList.remove('is-busy');
    // Let the same file be picked twice — the input keeps its value otherwise
    // and the change event never fires again.
    inputEl.value = '';
  }
}

inputEl.addEventListener('change', () => handleFile(inputEl.files?.[0]));

for (const type of ['dragenter', 'dragover']) {
  dropEl.addEventListener(type, (e) => {
    e.preventDefault();
    dropEl.classList.add('is-over');
  });
}
for (const type of ['dragleave', 'drop']) {
  dropEl.addEventListener(type, (e) => {
    e.preventDefault();
    dropEl.classList.remove('is-over');
  });
}
dropEl.addEventListener('drop', (e) => handleFile(e.dataTransfer?.files?.[0]));

// A file dropped anywhere else would otherwise navigate the browser away from
// the page and open it — losing the operator's place for a mis-aimed drop.
for (const type of ['dragover', 'drop']) {
  window.addEventListener(type, (e) => {
    if (!dropEl.contains(e.target)) e.preventDefault();
  });
}

/* =======================================================================
   History
   ======================================================================= */

function clamCell(s) {
  if (s.clamav_clean == null) return h('span', { class: 'dim' }, 'not run');
  if (s.clamav_clean === 0) return pill('down', s.clamav_virus || 'infected');
  return pill('ok', 'clean');
}

function vtCell(s) {
  if (!s.vt_status) return h('span', { class: 'dim' }, 'not run');
  if (s.vt_status === 'error') return pill('warn', 'lookup failed');
  if (s.vt_status === 'unknown') return pill('idle', 'never seen');
  if (s.vt_status === 'detected') {
    const label = `${num(s.vt_positives ?? 0)}/${num(s.vt_total ?? 0)} flagged`;
    return s.vt_url ? h('a', { class: 'vt-link', href: s.vt_url, target: '_blank', rel: 'noopener noreferrer' }, pill('down', label)) : pill('down', label);
  }
  return pill('ok', 'clean');
}

function renderHistory(scans) {
  countEl.textContent = num(scans.length);

  if (!scans.length) {
    render(bodyEl, emptyRow(7, 'Nothing has been scanned yet. Drop a file above to check it.'));
    return;
  }

  render(
    bodyEl,
    ...scans.map((s) =>
      h(
        'tr',
        {},
        h('td', { class: 'file-cell', title: s.filename }, s.filename),
        h('td', { class: 'num mono' }, bytes(s.file_size)),
        h(
          'td',
          { class: 'mono' },
          h(
            'button',
            { class: 'hash-btn', type: 'button', title: `${s.sha256}\nClick to copy`, onclick: () => copyText(s.sha256, 'Hash copied') },
            shortId(s.sha256, 12)
          )
        ),
        h('td', {}, clamCell(s)),
        h('td', {}, vtCell(s)),
        h('td', {}, h('time', { class: 'js-ts', datetime: s.scanned_at, title: absolute(s.scanned_at) }, relative(s.scanned_at))),
        h(
          'td',
          { class: 'actions' },
          h(
            'div',
            { class: 'btn-row' },
            h(
              'button',
              {
                class: 'btn sm ghost icon-only',
                type: 'button',
                'aria-label': `Delete the record for ${s.filename}`,
                onclick: async (e) => {
                  const ok = await confirm({
                    title: 'Delete this record?',
                    message: `The scan record for ${s.filename} will be removed from the history. The file itself was never stored, so there is nothing else to delete.`,
                    confirmLabel: 'Delete',
                    danger: true,
                  });
                  if (!ok) return;
                  await withLoading(e.currentTarget, async () => {
                    await del(`/sanitizer/${s.id}`);
                    toastOk('Record deleted');
                    load();
                  });
                },
              },
              icon('trash-2')
            )
          )
        )
      )
    )
  );
}

async function load() {
  render(bodyEl, ...skeletonRows(7));
  try {
    const d = await get('/sanitizer/history');
    renderHistory(d.scans || []);
  } catch (e) {
    reportError(e, "Couldn't load the scan history");
    render(bodyEl, emptyRow(7, 'Unavailable.'));
  }
}

refreshBtn.addEventListener('click', () => withLoading(refreshBtn, load));

startTimestampTicker();
load();
