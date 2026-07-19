/* Tab strip — DB Studio Phase 2.
 *
 * Two tab kinds for now: the fixed *query* tab (the console) and dynamic
 * *table* tabs (the browser grid, ▦ glyph). A fixed *roles* tab appears for
 * Postgres sources. Table tabs close with × or middle-click, and the open set
 * persists in sessionStorage — per browser tab, surviving reload, never
 * leaking across windows (plan §6). Phase 3 adds multiple query tabs.
 */

import { h, icon, render } from '../core/ui.js';

const STORE_KEY = 'vantage.db.tabs';

/**
 * @param {object} opts
 * @param {HTMLElement} opts.strip
 * @param {boolean} opts.hasRoles    whether a roles panel exists at all
 * @param {(tab: object) => void} opts.onShow      a tab became active
 * @param {(tab: object) => void} [opts.onClose]   a table tab was closed
 */
export function initTabs({ strip, hasRoles, onShow, onClose }) {
  /** @type {Array<{id: string, kind: string, label: string, source?: string, schema?: string, name?: string}>} */
  let tabs = [{ id: 'query', kind: 'query', label: 'query' }];
  if (hasRoles) tabs.push({ id: 'roles', kind: 'roles', label: 'roles' });
  let activeId = 'query';
  let rolesVisible = false;

  const tableId = (t) => `table:${t.source}|${t.schema}|${t.name}`;

  /* The tabs a user can actually see. Everything that picks a tab on the
   * operator's behalf — closing one, restoring the session — goes through this
   * rather than `tabs`, because the roles tab stays in the array while hidden
   * (SQLite has no roles) and handing focus to it painted the roles panel with
   * no tab lit anywhere in the strip. */
  const visible = () => tabs.filter((t) => t.kind !== 'roles' || rolesVisible);

  function paint() {
    render(
      strip,
      ...visible()
        .map((t) =>
          h(
            'button',
            {
              class: `db-tab${t.id === activeId ? ' active' : ''}`,
              type: 'button',
              role: 'tab',
              'aria-selected': String(t.id === activeId),
              onclick: () => activate(t.id),
              onauxclick: (e) => {
                if (e.button === 1 && t.kind === 'table') close(t.id);
              },
            },
            t.kind === 'table' ? h('span', { class: 'db-tab-glyph' }, icon('table', { size: 16 })) : null,
            h('span', { class: 'db-tab-label mono' }, t.label),
            t.kind === 'table'
              ? h(
                  'span',
                  {
                    class: 'db-tab-x',
                    role: 'button',
                    'aria-label': `Close ${t.label}`,
                    onclick: (e) => {
                      e.stopPropagation();
                      close(t.id);
                    },
                  },
                  icon('x')
                )
              : null
          )
        )
    );
  }

  function activate(id) {
    const tab = visible().find((t) => t.id === id);
    if (!tab) return;
    activeId = id;
    paint();
    persist();
    onShow(tab);
  }

  function close(id) {
    const i = tabs.findIndex((t) => t.id === id);
    if (i < 0 || tabs[i].kind !== 'table') return;
    const [closed] = tabs.splice(i, 1);
    onClose?.(closed);
    if (activeId === id) {
      // The visible neighbour to the left inherits focus; the query tab is the
      // floor. Indexing `tabs` directly landed on the hidden roles tab, which
      // is one place left of the first table tab on a SQLite source.
      const left = visible().filter((t) => tabs.indexOf(t) < i);
      activate((left.pop() || visible()[0]).id);
    } else {
      paint();
      persist();
    }
  }

  function persist() {
    const open = tabs.filter((t) => t.kind === 'table').map(({ source, schema, name }) => ({ source, schema, name }));
    try {
      sessionStorage.setItem(STORE_KEY, JSON.stringify({ open, active: activeId }));
    } catch {
      /* storage full or blocked — tabs simply won't survive reload */
    }
  }

  paint();

  return {
    /** Opens (or re-activates) the browser tab for one table. */
    openTable({ source, schema, name }) {
      const t = { source, schema, name };
      const id = tableId(t);
      if (!tabs.some((x) => x.id === id)) {
        tabs.push({ id, kind: 'table', label: name, ...t });
      }
      activate(id);
    },

    activate,

    /** Roles only means something for Postgres sources. */
    setRolesVisible(visible) {
      rolesVisible = visible;
      if (!visible && activeId === 'roles') activate('query');
      else paint();
    },

    /** Reopens the persisted table tabs; `isValid` filters dead sources. */
    restore(isValid) {
      let saved;
      try {
        saved = JSON.parse(sessionStorage.getItem(STORE_KEY) || 'null');
      } catch {
        saved = null;
      }
      if (!saved) return;
      for (const t of saved.open || []) {
        if (!isValid(t)) continue;
        const id = tableId(t);
        if (!tabs.some((x) => x.id === id)) tabs.push({ id, kind: 'table', label: t.name, ...t });
      }
      const wanted = saved.active && visible().some((t) => t.id === saved.active) ? saved.active : activeId;
      activate(wanted);
    },

    get active() {
      return tabs.find((t) => t.id === activeId);
    },
  };
}
