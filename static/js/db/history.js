/* History & saved-queries side panel for the database console.
 *
 * Two sub-tabs: "History" (reverse-chronological recent runs) and "Saved"
 * (alphabetical named bookmarks). Clicking any row loads the SQL into the
 * editor. The panel itself is a collapsible drawer toggled by a toolbar button.
 */

import { get, post, del } from '../core/api.js';
import { h, render, reportError, confirm } from '../core/ui.js';

/* =======================================================================
   Panel factory
   ======================================================================= */

/**
 * @param {HTMLElement} container - the panel root element (hidden by default)
 * @param {{
 *   getEditor: () => {setText: (s: string) => void},
 *   getSource: () => string,
 * }} opts
 */
export function createHistoryPanel(container, { getEditor, getSource }) {
  let open = false;
  let activeTab = 'history'; // 'history' | 'saved'
  let historyData = [];
  let savedData = [];

  // Build the panel skeleton once
  const tabHistory = h('button', { class: 'hpanel-tab active', dataset: { tab: 'history' } }, 'History');
  const tabSaved = h('button', { class: 'hpanel-tab', dataset: { tab: 'saved' } }, 'Saved');
  const tabBar = h('div', { class: 'hpanel-tabs' }, tabHistory, tabSaved);

  const listEl = h('div', { class: 'hpanel-list' });

  const clearBtn = h('button', { class: 'btn btn-ghost btn-xs hpanel-clear', title: 'Clear all history' }, 'Clear');
  const saveInput = h('input', {
    class: 'input input-sm hpanel-save-input',
    type: 'text',
    placeholder: 'Name…',
    maxlength: '80',
  });
  const saveBtn = h('button', { class: 'btn btn-primary btn-xs', title: 'Save current query' }, 'Save');
  const saveRow = h('div', { class: 'hpanel-save-row' }, saveInput, saveBtn);

  const footerHistory = h('div', { class: 'hpanel-footer' }, clearBtn);
  const footerSaved = h('div', { class: 'hpanel-footer' }, saveRow);

  container.append(tabBar, listEl, footerHistory, footerSaved);

  // ─── Tab switching ──────────────────────────────────────────────

  function switchTab(tab) {
    activeTab = tab;
    tabHistory.classList.toggle('active', tab === 'history');
    tabSaved.classList.toggle('active', tab === 'saved');
    footerHistory.hidden = tab !== 'history';
    footerSaved.hidden = tab !== 'saved';
    paintList();
  }

  tabHistory.addEventListener('click', () => switchTab('history'));
  tabSaved.addEventListener('click', () => switchTab('saved'));

  // ─── History rendering ──────────────────────────────────────────

  function truncate(s, max = 100) {
    if (!s || s.length <= max) return s;
    return s.slice(0, max) + '…';
  }

  function relTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function paintList() {
    if (activeTab === 'history') paintHistory();
    else paintSaved();
  }

  function paintHistory() {
    if (!historyData.length) {
      render(listEl, h('div', { class: 'hpanel-empty' }, 'No queries yet.'));
      return;
    }

    render(
      listEl,
      ...historyData.map((entry) =>
        h(
          'div',
          {
            class: `hpanel-item ${entry.ok ? '' : 'hpanel-item--error'}`,
            onclick: () => loadEntry(entry.sql_text),
            title: entry.sql_text,
          },
          h('div', { class: 'hpanel-item-sql mono' }, truncate(entry.sql_text)),
          h(
            'div',
            { class: 'hpanel-item-meta' },
            h('span', { class: 'hpanel-chip' }, entry.source.split(':')[1] || entry.source),
            h('span', {}, `${entry.row_count} rows`),
            h('span', {}, `${entry.elapsed_ms}ms`),
            h('span', {}, relTime(entry.created_at))
          )
        )
      )
    );
  }

  function paintSaved() {
    if (!savedData.length) {
      render(listEl, h('div', { class: 'hpanel-empty' }, 'No saved queries.'));
      return;
    }

    render(
      listEl,
      ...savedData.map((entry) =>
        h(
          'div',
          { class: 'hpanel-item', title: entry.sql_text },
          h(
            'div',
            { class: 'hpanel-item-header' },
            h('span', { class: 'hpanel-item-name', onclick: () => loadEntry(entry.sql_text) }, entry.name),
            h('button', {
              class: 'btn btn-ghost btn-xs hpanel-delete',
              title: 'Delete',
              onclick: (e) => {
                e.stopPropagation();
                deleteSaved(entry.id);
              },
            }, '×')
          ),
          h(
            'div',
            { class: 'hpanel-item-meta' },
            h('span', { class: 'hpanel-chip' }, entry.source.split(':')[1] || entry.source)
          )
        )
      )
    );
  }

  function loadEntry(sql) {
    getEditor().setText(sql);
  }

  // ─── Data fetching ──────────────────────────────────────────────

  async function fetchHistory() {
    try {
      historyData = await get('/database/history');
    } catch (e) {
      reportError(e, "Couldn't load query history");
      historyData = [];
    }
    if (activeTab === 'history') paintHistory();
  }

  async function fetchSaved() {
    try {
      savedData = await get('/database/saved');
    } catch (e) {
      reportError(e, "Couldn't load saved queries");
      savedData = [];
    }
    if (activeTab === 'saved') paintSaved();
  }

  // ─── Actions ────────────────────────────────────────────────────

  clearBtn.addEventListener('click', async () => {
    const ok = await confirm({
      title: 'Clear query history?',
      message: 'This removes all history entries. The audit log is not affected.',
      confirmLabel: 'Clear',
      danger: true,
    });
    if (!ok) return;
    try {
      await del('/database/history');
      historyData = [];
      paintHistory();
    } catch (e) {
      reportError(e, "Couldn't clear history");
    }
  });

  saveBtn.addEventListener('click', async () => {
    const name = saveInput.value.trim();
    if (!name) {
      saveInput.focus();
      return;
    }
    const sql = getEditor().getText();
    if (!sql.trim()) return;

    try {
      await post('/database/saved', { name, source: getSource(), sql_text: sql });
      saveInput.value = '';
      await fetchSaved();
    } catch (e) {
      reportError(e, "Couldn't save the query");
    }
  });

  saveInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      saveBtn.click();
    }
  });

  async function deleteSaved(id) {
    try {
      await del(`/database/saved?id=${id}`);
      savedData = savedData.filter((s) => s.id !== id);
      paintSaved();
    } catch (e) {
      reportError(e, "Couldn't delete saved query");
    }
  }

  // ─── Public API ─────────────────────────────────────────────────

  function show() {
    open = true;
    container.hidden = false;
    refresh();
  }

  function hide() {
    open = false;
    container.hidden = true;
  }

  async function refresh() {
    if (!open) return;
    await Promise.all([fetchHistory(), fetchSaved()]);
  }

  // Init hidden
  footerSaved.hidden = true;
  container.hidden = true;

  return {
    toggle() {
      if (open) hide();
      else show();
    },
    refresh,
    get isOpen() {
      return open;
    },
  };
}
