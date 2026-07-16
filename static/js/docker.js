/* Docker graph admin page */

(function () {
    'use strict';

    // Guard — only run on pages that have the cytoscape canvas.
    const canvas = document.getElementById('cy');
    if (!canvas) return;

    // ── CSS variable helpers ──────────────────────────────────────────────────

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    // ── Cytoscape stylesheet ──────────────────────────────────────────────────

    function buildStyle() {
        return [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'font-size': '10px',
                    'text-valign': 'bottom',
                    'text-margin-y': '4px',
                    'text-wrap': 'ellipsis',
                    'text-max-width': '90px',
                    'color': cssVar('--foreground') || '#e0e0e0',
                    'width': 36,
                    'height': 36,
                    'border-width': 2,
                    'border-color': cssVar('--box-border') || '#444',
                },
            },
            {
                selector: 'node[kind = "container"]',
                style: {
                    'background-color': cssVar('--info-bg') || '#1a2b3c',
                    'border-color': cssVar('--info-text') || '#61afef',
                    'shape': 'round-rectangle',
                },
            },
            {
                selector: 'node[kind = "network"]',
                style: {
                    'background-color': cssVar('--warning-bg') || '#2b2200',
                    'border-color': cssVar('--warning-text') || '#e5a800',
                    'shape': 'diamond',
                    'width': 30,
                    'height': 30,
                },
            },
            {
                selector: 'node[kind = "volume"]',
                style: {
                    'background-color': cssVar('--success-bg') || '#0a2b0a',
                    'border-color': cssVar('--success-text') || '#4caf50',
                    'shape': 'barrel',
                    'width': 30,
                    'height': 30,
                },
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': cssVar('--branding') || '#7aa2f7',
                },
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': cssVar('--box-border') || '#555',
                    'target-arrow-color': cssVar('--box-border') || '#555',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'arrow-scale': 0.8,
                },
            },
            {
                selector: 'edge[type = "network"]',
                style: {
                    'line-color': cssVar('--warning-text') || '#e5a800',
                    'target-arrow-color': cssVar('--warning-text') || '#e5a800',
                    'line-style': 'dashed',
                    'line-dash-pattern': [4, 3],
                },
            },
            {
                selector: 'edge[type = "volume"]',
                style: {
                    'line-color': cssVar('--success-text') || '#4caf50',
                    'target-arrow-color': cssVar('--success-text') || '#4caf50',
                },
            },
            {
                selector: 'edge[type = "depends_on"]',
                style: {
                    'line-color': cssVar('--info-text') || '#61afef',
                    'target-arrow-color': cssVar('--info-text') || '#61afef',
                    'line-style': 'dotted',
                },
            },
            {
                selector: 'edge:selected',
                style: {
                    'width': 2.5,
                    'line-color': cssVar('--branding') || '#7aa2f7',
                    'target-arrow-color': cssVar('--branding') || '#7aa2f7',
                },
            },
        ];
    }

    // ── Cytoscape instance ────────────────────────────────────────────────────

    let cy = cytoscape({
        container: canvas,
        style: buildStyle(),
        layout: { name: 'grid' },
        wheelSensitivity: 0.3,
    });

    // ── Graph data loading ────────────────────────────────────────────────────

    let activeFilter = 'all';

    async function loadGraph() {
        let graph;
        try {
            const r = await fetch('/docker/graph');
            if (!r.ok) {
                const j = await r.json().catch(() => ({}));
                showError(j.error || `HTTP ${r.status}`);
                return;
            }
            graph = await r.json();
        } catch (e) {
            showError(e.message);
            return;
        }

        cy.elements().remove();

        const nodes = (graph.nodes || []).map(n => ({
            group: 'nodes',
            data: {
                id: n.id,
                label: n.label,
                kind: n.kind,
                ...n.data,
            },
        }));

        // Only keep edges whose endpoints actually exist as nodes. A single
        // edge referencing a missing node makes cytoscape throw inside cy.add,
        // which aborts the whole batch — leaving every node disconnected and
        // the cose layout packing them into a useless line.
        const nodeIds = new Set(nodes.map(n => n.data.id));
        const edges = (graph.edges || [])
            .filter(e => {
                const ok = nodeIds.has(e.source) && nodeIds.has(e.target);
                if (!ok) console.warn('docker graph: dropping dangling edge', e);
                return ok;
            })
            .map(e => ({
                group: 'edges',
                data: {
                    id: `${e.source}→${e.target}→${e.type}`,
                    source: e.source,
                    target: e.target,
                    type: e.type,
                    label: e.label || '',
                },
            }));

        cy.add([...nodes, ...edges]);
        applyFilter(activeFilter);
        runLayout();
    }

    function applyFilter(filter) {
        activeFilter = filter;
        cy.elements().show();
        if (filter !== 'all') {
            cy.nodes().filter(n => n.data('kind') !== filter).hide();
            // Also hide edges connected to hidden nodes
            cy.edges().forEach(e => {
                if (e.source().hidden() || e.target().hidden()) e.hide();
            });
        }
    }

    function runLayout() {
        if (cy.elements().length === 0) return;
        // Make sure the renderer has picked up the container's real size before
        // laying out — a 0-height viewport collapses cose into a flat line.
        cy.resize();
        const layout = cy.layout({
            name: 'cose',
            animate: true,
            animationDuration: 400,
            randomize: true,
            componentSpacing: 80,
            nodeRepulsion: () => 8000,
            idealEdgeLength: () => 80,
            edgeElasticity: () => 100,
            gravity: 0.25,
            numIter: 1000,
            padding: 40,
            fit: true,
        });
        layout.run();
    }

    function showError(msg) {
        canvas.insertAdjacentHTML('afterend',
            `<div class="docker-unavailable"><div class="docker-unavailable-title">Error loading graph</div><div class="docker-unavailable-sub">${msg}</div></div>`
        );
    }

    // ── Side panel ────────────────────────────────────────────────────────────

    const panel  = document.getElementById('side-panel');
    const spKind = document.getElementById('sp-kind');
    const spName = document.getElementById('sp-name');
    const spBody = document.getElementById('sp-body');

    function openPanel(node) {
        const d = node.data();
        const kind = d.kind;

        spKind.textContent = kind;
        spKind.className = `side-panel-kind ${kind}`;
        spName.textContent = d.label;
        spBody.innerHTML = '';

        if (kind === 'container') {
            buildContainerPanel(d);
        } else if (kind === 'network') {
            buildNetworkPanel(d);
        } else if (kind === 'volume') {
            buildVolumePanel(d);
        }

        panel.hidden = false;
    }

    function closePanel() {
        panel.hidden = true;
        cy.elements(':selected').unselect();
    }

    document.getElementById('sp-close').addEventListener('click', closePanel);

    function row(label, value, cls) {
        const d = document.createElement('div');
        d.className = 'sp-row';
        const l = document.createElement('div');
        l.className = 'sp-label';
        l.textContent = label;
        const v = document.createElement('div');
        v.className = `sp-value${cls ? ' ' + cls : ''}`;
        v.textContent = value || '—';
        d.appendChild(l);
        d.appendChild(v);
        spBody.appendChild(d);
        return d;
    }

    function buildContainerPanel(d) {
        row('ID', (d.full_id || '').substring(0, 20) + '…', 'mono');
        const stateClass = ({running: 'status-running', exited: 'status-exited', paused: 'status-paused'})[d.state] || '';
        row('State', `${d.state} (${d.status})`, stateClass);
        row('Image', d.image);

        if (d.compose_project || d.compose_service) {
            row('Compose', `${d.compose_project || '—'} / ${d.compose_service || '—'}`);
        }

        const ports = d.ports || [];
        if (ports.length) {
            const r = document.createElement('div');
            r.className = 'sp-row';
            const l = document.createElement('div');
            l.className = 'sp-label';
            l.textContent = 'Ports';
            const ps = document.createElement('div');
            ps.className = 'sp-ports';
            ports.forEach(p => {
                const s = document.createElement('span');
                s.className = 'sp-port';
                s.textContent = p;
                ps.appendChild(s);
            });
            r.appendChild(l);
            r.appendChild(ps);
            spBody.appendChild(r);
        }

        const labels = d.labels || {};
        const labelEntries = Object.entries(labels).filter(([k]) => !k.startsWith('com.docker.compose'));
        if (labelEntries.length) {
            const r = document.createElement('div');
            r.className = 'sp-row';
            const l = document.createElement('div');
            l.className = 'sp-label';
            l.textContent = 'Labels';
            const list = document.createElement('div');
            list.className = 'sp-label-list';
            labelEntries.forEach(([k, v]) => {
                const row = document.createElement('div');
                row.className = 'sp-label-row';
                const key = document.createElement('span');
                key.className = 'sp-label-key';
                key.textContent = k;
                key.title = k;
                const val = document.createElement('span');
                val.className = 'sp-label-val';
                val.textContent = v;
                row.appendChild(key);
                row.appendChild(val);
                list.appendChild(row);
            });
            r.appendChild(l);
            r.appendChild(list);
            spBody.appendChild(r);
        }
    }

    function buildNetworkPanel(d) {
        row('ID', (d.full_id || '').substring(0, 20) + '…', 'mono');
        row('Driver', d.driver);
        row('Scope', d.scope);
        const labels = d.labels || {};
        const lk = Object.keys(labels);
        if (lk.length) row('Labels', lk.length + ' entries');
    }

    function buildVolumePanel(d) {
        row('Driver', d.driver);
        row('Mountpoint', d.mountpoint, 'mono');
    }

    // ── Cytoscape event handlers ──────────────────────────────────────────────

    cy.on('tap', 'node', evt => openPanel(evt.target));

    cy.on('tap', evt => {
        if (evt.target === cy) closePanel();
    });

    // ── Toolbar buttons ───────────────────────────────────────────────────────

    document.getElementById('btn-relayout').addEventListener('click', runLayout);
    document.getElementById('btn-refresh').addEventListener('click', loadGraph);
    document.getElementById('btn-fit').addEventListener('click', () => cy.fit(undefined, 40));

    document.getElementById('filter-chips').addEventListener('click', e => {
        const chip = e.target.closest('.chip');
        if (!chip) return;
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        applyFilter(chip.dataset.filter);
    });

    // ── Soft graph refresh (update-in-place, no layout re-run unless structure changed) ──

    async function softRefresh() {
        let graph;
        try {
            const r = await fetch('/docker/graph');
            if (!r.ok) return;
            graph = await r.json();
        } catch (_) { return; }

        const newNodes = new Map((graph.nodes || []).map(n => [n.id, n]));
        const newEdges = new Map((graph.edges || []).map(e => [
            `${e.source}→${e.target}→${e.type}`, e
        ]));

        let structureChanged = false;

        // Remove nodes/edges that no longer exist
        cy.nodes().forEach(n => {
            if (!newNodes.has(n.id())) { cy.remove(n); structureChanged = true; }
        });
        cy.edges().forEach(e => {
            if (!newEdges.has(e.id())) { cy.remove(e); structureChanged = true; }
        });

        // Update existing nodes, add new ones
        for (const [id, n] of newNodes) {
            const el = cy.getElementById(id);
            if (el.length) {
                el.data({ ...n.data, label: n.label, kind: n.kind });
            } else {
                cy.add({ group: 'nodes', data: { id, label: n.label, kind: n.kind, ...n.data } });
                structureChanged = true;
            }
        }

        // Add new edges — skip any whose endpoints aren't present, otherwise
        // cytoscape throws and the refresh aborts.
        for (const [eid, e] of newEdges) {
            if (cy.getElementById(eid).length) continue;
            if (!cy.getElementById(e.source).length || !cy.getElementById(e.target).length) {
                console.warn('docker graph: dropping dangling edge', e);
                continue;
            }
            cy.add({ group: 'edges', data: { id: eid, source: e.source, target: e.target, type: e.type, label: e.label || '' } });
            structureChanged = true;
        }

        if (structureChanged) runLayout();
        applyFilter(activeFilter);
    }

    // ── Live event log ────────────────────────────────────────────────────────

    const logBody   = document.getElementById('event-log-body');
    const logEmpty  = document.getElementById('event-log-empty');
    const logStatus = document.getElementById('event-log-status');
    const MAX_LOG   = 100;

    function formatTime(ts) {
        if (!ts) return '';
        try { return new Date(ts * 1000).toLocaleTimeString(); } catch (_) { return ''; }
    }

    const ACTION_CLASSES = {
        start: 'ev-start', create: 'ev-create',
        stop: 'ev-stop', die: 'ev-stop', kill: 'ev-stop', destroy: 'ev-destroy',
        restart: 'ev-start',
    };

    function appendEvent(msg) {
        if (logEmpty) logEmpty.remove();
        const rawAction = msg.Action || msg.action || '?';
        const action    = rawAction.split(':')[0];
        const evType    = msg.Type   || msg.type   || '';
        const actor     = msg.Actor  || msg.actor  || {};
        const attrs     = actor.Attributes || actor.attributes || {};
        const name      = attrs.name || actor.ID || actor.id || '';
        const ts        = msg.time;

        const row = document.createElement('div');
        row.className = 'event-row';

        const badge = document.createElement('span');
        badge.className = `event-badge ${ACTION_CLASSES[action] || ''}`;
        badge.textContent = action;

        const info = document.createElement('span');
        info.className = 'event-info';
        info.textContent = name ? `${evType}  ${name}` : evType;

        const time = document.createElement('span');
        time.className = 'event-time';
        time.textContent = (ts && isFinite(ts)) ? new Date(ts * 1000).toLocaleTimeString() : '';

        row.appendChild(badge);
        row.appendChild(info);
        row.appendChild(time);
        logBody.prepend(row);

        // Trim to MAX_LOG rows
        const rows = logBody.querySelectorAll('.event-row');
        for (let i = MAX_LOG; i < rows.length; i++) rows[i].remove();
    }

    document.getElementById('event-log-clear').addEventListener('click', () => {
        logBody.innerHTML = '<div class="event-log-empty" id="event-log-empty">Waiting for events…</div>';
    });

    // ── WebSocket ─────────────────────────────────────────────────────────────

    const STATE_CHANGING = new Set(['start', 'stop', 'die', 'create', 'destroy', 'rename', 'restart', 'kill']);
    let wsReconnectTimer = null;

    function connectWs() {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(`${proto}://${location.host}/ws`);

        ws.addEventListener('open', () => {
            logStatus.textContent = 'Connected';
            logStatus.className = 'event-log-status connected';
            ws.send(JSON.stringify({ action: 'subscribe', topics: ['docker'] }));
        });

        ws.addEventListener('message', evt => {
            let envelope;
            try { envelope = JSON.parse(evt.data); } catch (_) { return; }
            if (envelope.topic !== 'docker') return;
            const msg = envelope.data;
            if (!msg) return;
            appendEvent(msg);
            const action = (msg.Action || msg.action || '').split(':')[0];
            if (STATE_CHANGING.has(action)) softRefresh();
        });

        ws.addEventListener('close', () => {
            logStatus.textContent = 'Disconnected';
            logStatus.className = 'event-log-status';
            wsReconnectTimer = setTimeout(connectWs, 5000);
        });

        ws.addEventListener('error', () => ws.close());
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    loadGraph();
    connectWs();
}());
