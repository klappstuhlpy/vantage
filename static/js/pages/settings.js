/* Settings page — save the operational overlay over config.json.
 *
 * Each field maps to one override key. An empty field means "no override, use
 * the config.json default", sent as null so the server clears the row. The save
 * is sudo-gated server-side; core/api.js handles the reauth prompt and retry, so
 * nothing here has to know about it.
 */

import { post } from '../core/api.js';
import { toastOk, withLoading } from '../core/ui.js';

const form = document.getElementById('settings-form');
const saveBtn = document.getElementById('settings-save');

/* Release notes render — the GitHub release body, a small markdown subset.
 *
 * We escape the source *first* and only ever emit our own tags, so no raw HTML
 * from the release body can reach the DOM (the notes are trusted-ish, but a
 * control plane doesn't gamble on that). This covers exactly what our notes use:
 * headings, bullet lists, bold, italic, inline code and http(s) links. A
 * construct we don't handle degrades to its plain text, which is fine. */
const escapeHtml = (s) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, t, u) => `<a href="${u}" target="_blank" rel="noopener">${t}</a>`)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

function renderMarkdown(src) {
  const out = [];
  let list = null;
  const flush = () => {
    if (list) {
      out.push(`<ul>${list.join('')}</ul>`);
      list = null;
    }
  };
  for (const line of escapeHtml(src).split(/\r?\n/)) {
    const li = line.match(/^\s*[-*]\s+(.*)$/);
    if (li) {
      (list ??= []).push(`<li>${inlineMd(li[1])}</li>`);
      continue;
    }
    flush();
    const hd = line.match(/^(#{1,6})\s+(.*)$/);
    if (hd) {
      // Cap heading weight: a release's top "# 1.2.0" shouldn't outrank the card.
      const lvl = Math.min(6, hd[1].length + 3);
      out.push(`<h${lvl}>${inlineMd(hd[2])}</h${lvl}>`);
    } else if (line.trim()) {
      out.push(`<p>${inlineMd(line)}</p>`);
    }
  }
  flush();
  return out.join('');
}

const notesEl = document.getElementById('release-notes');
if (notesEl) {
  // textContent is the decoded original markdown, whatever Askama escaped it to.
  notesEl.innerHTML = renderMarkdown(notesEl.textContent);
  notesEl.classList.add('md');
}

/** An input's value as an integer, or null when blank (= use the default). */
function intOrNull(id) {
  const v = document.getElementById(id).value.trim();
  if (v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/* The update button is a one-off action, not an override that saves with the
 * form. A refusal (409) is an expected answer — it carries the command to run
 * by hand — so it is written into the card instead of only flashing in a toast.
 */
document.getElementById('apply-update-btn')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const fallback = document.getElementById('update-fallback');
  try {
    const res = await withLoading(btn, () => post('/updates/apply'), { errorTitle: "Couldn't update" });
    btn.disabled = true;
    toastOk('Update started', res.note || 'Vantage is restarting into the new version.');
  } catch (err) {
    if (fallback) {
      fallback.textContent = err.message;
      fallback.hidden = false;
    }
  }
});

/* Force a self-update check now, then reload so the card re-renders from the
 * fresh status (up-to-date vs. an "Update now" button). */
document.getElementById('check-update-btn')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  try {
    await withLoading(btn, () => post('/updates/self/check'), { errorTitle: "Couldn't check for updates" });
    location.reload();
  } catch {
    /* withLoading already surfaced the error toast */
  }
});

form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    audit_retention_days: intOrNull('audit_retention_days'),
    update_check_interval_hours: intOrNull('update_check_interval_hours'),
    backup_interval_hours: intOrNull('backup_interval_hours'),
    backup_keep: intOrNull('backup_keep'),
  };
  try {
    await withLoading(saveBtn, () => post('/settings', body), { errorTitle: "Couldn't save settings" });
    toastOk('Settings saved', 'Applied on the next scheduled run.');
  } catch {
    /* withLoading already surfaced the error toast */
  }
});
