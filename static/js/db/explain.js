/* EXPLAIN plan viewer — renders the flat node list from /database/explain
 * as a collapsible tree. SQLite nodes show just a label; Postgres nodes
 * additionally show cost/rows/width in a detail line.
 */

import { h, render } from '../core/ui.js';

/**
 * @param {HTMLElement} container
 * @returns {{ show(nodes: Array), hide(), visible: boolean }}
 */
export function createExplainView(container) {
  let visible = false;

  function show(nodes) {
    visible = true;

    if (!nodes.length) {
      render(container, h('div', { class: 'explain-empty' }, 'No plan produced.'));
      return;
    }

    const tree = buildTree(nodes);
    render(container, h('div', { class: 'explain-tree' }, ...tree.map((n) => renderNode(n, 0))));
  }

  function hide() {
    visible = false;
    render(container);
  }

  return {
    show,
    hide,
    get visible() { return visible; },
  };
}

function buildTree(nodes) {
  const map = new Map();
  const roots = [];

  for (const node of nodes) {
    map.set(node.id, { ...node, children: [] });
  }

  for (const node of nodes) {
    const entry = map.get(node.id);
    if (node.parent && map.has(node.parent)) {
      map.get(node.parent).children.push(entry);
    } else {
      roots.push(entry);
    }
  }

  return roots;
}

function renderNode(node, depth) {
  const indent = depth * 20;
  const hasChildren = node.children.length > 0;

  const children = node.children.map((c) => renderNode(c, depth + 1));

  return h(
    'div',
    { class: 'explain-node' },
    h(
      'div',
      { class: 'explain-row', style: { paddingLeft: `${indent}px` } },
      hasChildren
        ? h('span', { class: 'explain-arrow' }, '→')
        : h('span', { class: 'explain-dot' }, '·'),
      h('span', { class: 'explain-label' }, node.label),
      node.detail
        ? h('span', { class: 'explain-detail' }, node.detail)
        : null
    ),
    ...children
  );
}
