/* ERD (Entity Relationship Diagram) — cytoscape graph of tables and foreign
 * keys for the active source. Clicking a table node opens its browser tab.
 *
 * Colour here is information, not decoration: a node is tinted by its role in
 * the FK graph — what nothing points at, what points at nothing, and what is
 * joined to neither — because "where are the hubs and what is orphaned" is the
 * question you open an ERD to answer. A legend states the mapping, so the
 * colours are readable rather than merely present. Every value comes from the
 * existing tokens, so the graph follows theme and accent like the rest of the
 * app.
 *
 * Layout is breadth-first (plan D14), rooted at the tables nothing references:
 * FK graphs are near-trees, and a hierarchy makes the direction of dependency
 * legible in a way the force-directed default never did — `cose` scattered
 * tables by edge tension alone, which reads as "some tables, some lines".
 */

import { get } from '../core/api.js';
import { h, render, reportError } from '../core/ui.js';
import * as db from './state.js';

/** Node roles, in legend order. `key` is the cytoscape class. */
const ROLES = [
  { key: 'hub', label: 'Referenced', hint: 'Other tables point at it' },
  { key: 'leaf', label: 'References', hint: 'It points at other tables' },
  { key: 'both', label: 'Both', hint: 'Points at others and is pointed at' },
  { key: 'lone', label: 'Unlinked', hint: 'No foreign keys either way' },
];

/**
 * @param {HTMLElement} container
 * @param {{ onOpen: (t: {schema: string, name: string}) => void }} opts
 * @returns {{ show(), hide(), fit(), relayout(), visible: boolean }}
 */
export function createErd(container, { onOpen }) {
  let visible = false;
  let cy = null;
  let loadedSource = null;

  async function show() {
    visible = true;
    container.hidden = false;

    const source = db.current();
    if (loadedSource === source && cy) {
      // A graph built while the panel was hidden measured a zero-size box and
      // laid out into nothing; re-fit now that it has real dimensions.
      cy.resize();
      cy.fit(undefined, 30);
      return;
    }

    render(container, h('div', { class: 'erd-loading' }, 'Loading schema…'));

    try {
      const overview = db.getOverview(source);
      if (!overview || !overview.tables.length) {
        render(container, h('div', { class: 'erd-empty' }, 'No tables to graph.'));
        return;
      }

      const isPg = source.startsWith('pg:');
      const details = await Promise.all(
        overview.tables.map(async (t) => {
          const params = new URLSearchParams({ source, table: t.name });
          if (isPg && t.schema) params.set('schema', t.schema);
          try {
            return await get(`/database/table?${params}`);
          } catch {
            return null;
          }
        })
      );

      const elements = buildElements(overview.tables, details.filter(Boolean));
      render(container);
      mountGraph(container, elements, source);
    } catch (e) {
      reportError(e, "Couldn't build the ERD");
      render(container, h('div', { class: 'erd-empty' }, 'Failed to load schema.'));
    }
  }

  function hide() {
    visible = false;
    container.hidden = true;
  }

  function buildElements(tables, details) {
    const nodes = new Map();
    for (const t of tables) {
      const id = `${t.schema}.${t.name}`;
      nodes.set(id, {
        data: { id, label: t.name, schema: t.schema, out: 0, in: 0 },
      });
    }

    const edges = [];
    const seen = new Set();
    for (const detail of details) {
      if (!detail?.foreign_keys) continue;
      for (const fk of detail.foreign_keys) {
        const src = `${detail.schema}.${detail.name}`;
        const tgt = `${fk.ref_schema}.${fk.ref_table}`;
        // A FK can point at a table outside the overview (another schema we
        // did not list). Skip rather than inventing a node for it — a node
        // with no table behind it is not clickable and lies about the source.
        if (!nodes.has(src) || !nodes.has(tgt)) continue;
        const id = `${src}->${tgt}:${fk.columns.join(',')}`;
        if (seen.has(id)) continue;
        seen.add(id);
        nodes.get(src).data.out++;
        nodes.get(tgt).data.in++;
        edges.push({ data: { id, source: src, target: tgt, label: fk.columns.join(', ') } });
      }
    }

    for (const n of nodes.values()) {
      const { out, in: inc } = n.data;
      n.classes = out && inc ? 'both' : inc ? 'hub' : out ? 'leaf' : 'lone';
    }

    return [...nodes.values(), ...edges];
  }

  function resolveVar(name) {
    return getComputedStyle(container).getPropertyValue(name).trim();
  }

  function mountGraph(el, elements, source) {
    if (cy) {
      cy.destroy();
      cy = null;
    }

    const t = {
      bg1: resolveVar('--bg-1') || '#181825',
      bg2: resolveVar('--bg-2') || '#1e1e2e',
      line: resolveVar('--line-1') || '#444',
      ink1: resolveVar('--ink-1') || '#cdd6f4',
      ink3: resolveVar('--ink-3') || '#6c7086',
      acc: resolveVar('--acc') || '#2ac3de',
      info: resolveVar('--info') || '#60a5fa',
      ok: resolveVar('--ok') || '#3ecf8e',
      mono: resolveVar('--font-mono') || 'monospace',
    };

    // One tinted style per role. `color-mix` is not available inside a
    // cytoscape canvas style, so the fill is the role colour at low alpha
    // composited by cytoscape's own opacity instead.
    const roleStyle = (cls, color) => [
      {
        selector: `node.${cls}`,
        style: { 'border-color': color, color: t.ink1 },
      },
      {
        selector: `node.${cls}.hl`,
        style: { 'background-color': color, 'background-opacity': 0.22 },
      },
    ];

    cy = cytoscape({
      container: el,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-valign': 'center',
            'text-halign': 'center',
            'background-color': t.bg2,
            'background-opacity': 1,
            'border-width': 1.5,
            'border-color': t.line,
            color: t.ink1,
            'font-size': '11px',
            'font-family': t.mono,
            width: 'label',
            height: 32,
            shape: 'round-rectangle',
            'padding-left': '14px',
            'padding-right': '14px',
            'transition-property': 'border-width, background-opacity, opacity',
            'transition-duration': '120ms',
          },
        },
        ...roleStyle('hub', t.info),
        ...roleStyle('leaf', t.acc),
        ...roleStyle('both', t.ok),
        ...roleStyle('lone', t.ink3),
        {
          // Unlinked tables are context, not subject: they carry no edges, so
          // they recede rather than competing with the graph proper.
          selector: 'node.lone',
          style: { 'border-style': 'dashed', color: t.ink3 },
        },
        {
          selector: 'edge',
          style: {
            width: 1.2,
            'line-color': t.line,
            'target-arrow-color': t.line,
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.9,
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': '8px',
            'font-family': t.mono,
            color: t.ink3,
            'text-background-color': t.bg1,
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
            'text-opacity': 0, // revealed on hover; always-on labels are noise
            'transition-property': 'line-color, target-arrow-color, width, text-opacity, opacity',
            'transition-duration': '120ms',
          },
        },
        {
          // Hovering a table lights its relationships and names the columns
          // that make them — the ERD's actual payload.
          selector: 'edge.hl',
          style: {
            width: 2,
            'line-color': t.acc,
            'target-arrow-color': t.acc,
            'text-opacity': 1,
            color: t.ink1,
          },
        },
        {
          selector: 'node.dim, edge.dim',
          style: { opacity: 0.25 },
        },
        {
          selector: 'node.hl',
          style: { 'border-width': 2.5 },
        },
      ],
      // No `layout` here: breadth-first roots are computed from the graph, so
      // the graph has to exist first. Laid out immediately below.
      minZoom: 0.2,
      maxZoom: 2.5,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    cy.layout(layoutOpts()).run();
    cy.fit(undefined, 30);

    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      onOpen({ schema: d.schema, name: d.label });
    });

    // Hover: highlight the node's neighbourhood, dim everything else. This is
    // what makes a 40-table graph readable — without it, tracing one table's
    // relationships means following lines by eye across the whole canvas.
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      const near = node.closedNeighborhood();
      cy.elements().difference(near).addClass('dim');
      near.addClass('hl');
    });
    cy.on('mouseout', 'node', () => {
      cy.elements().removeClass('dim hl');
    });

    loadedSource = source;
  }

  function layoutOpts() {
    return {
      name: 'breadthfirst',
      directed: true,
      // Roots are the tables nothing points at: the dependency hierarchy reads
      // top-down from them. Left empty, cytoscape picks arbitrarily and the
      // arrows end up running in every direction.
      roots: cy ? cy.nodes().filter((n) => n.indegree(false) === 0) : undefined,
      spacingFactor: 1.3,
      padding: 30,
      animate: false,
      nodeDimensionsIncludeLabels: true,
      avoidOverlap: true,
    };
  }

  return {
    show,
    hide,
    fit() {
      cy?.fit(undefined, 30);
    },
    relayout() {
      if (!cy) return;
      cy.layout(layoutOpts()).run();
      cy.fit(undefined, 30);
    },
    get visible() {
      return visible;
    },
  };
}

/** The legend, rendered once by the page next to the graph. */
export function erdLegend() {
  return h(
    'div',
    { class: 'db-erd-legend' },
    ...ROLES.map((r) =>
      h(
        'span',
        { class: 'db-erd-legend-item', title: r.hint },
        h('span', { class: `db-erd-swatch ${r.key}`, 'aria-hidden': 'true' }),
        r.label
      )
    )
  );
}
