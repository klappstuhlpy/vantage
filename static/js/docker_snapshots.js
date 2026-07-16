/* Docker snapshots admin page */

(function () {
    'use strict';

    const tbody      = document.getElementById('snap-tbody');
    if (!tbody) return; // Docker not available — page shows placeholder

    const drawer     = document.getElementById('snap-drawer');
    const btnNew     = document.getElementById('btn-new-snap');
    const btnClose   = document.getElementById('snap-drawer-close');
    const btnCreate  = document.getElementById('btn-snap-create');
    const selCont    = document.getElementById('snap-container');
    const descInput  = document.getElementById('snap-desc');
    const snapErr    = document.getElementById('snap-error');
    const snapSuc    = document.getElementById('snap-success');
    const snapSucMsg = document.getElementById('snap-success-msg');
    const btnSucDis  = document.getElementById('snap-success-dismiss');

    const restoreModal   = document.getElementById('restore-modal');
    const restoreName    = document.getElementById('restore-name');
    const restoreErr     = document.getElementById('restore-error');
    const btnRestoreOk   = document.getElementById('restore-confirm');
    const btnRestoreCanc = document.getElementById('restore-cancel');

    let pendingRestoreId = null;

    // ── Utilities ─────────────────────────────────────────────────────────────

    function fmtDate(iso) {
        try { return new Date(iso).toLocaleString(); } catch (_) { return iso; }
    }

    function showErr(el, msg) {
        el.textContent = msg;
        el.hidden = false;
    }

    function hideErr(el) { el.hidden = true; }

    // ── Load containers into the select ───────────────────────────────────────

    async function loadContainers() {
        selCont.innerHTML = '<option value="">— Loading… —</option>';
        try {
            const r = await fetch('/docker/graph');
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const graph = await r.json();
            const containers = (graph.nodes || []).filter(n => n.kind === 'container');
            selCont.innerHTML = containers.length
                ? containers.map(c => `<option value="${c.id}" data-name="${c.label}" data-image="${c.image || ''}">${c.label} (${(c.state || '')})</option>`).join('')
                : '<option value="">— No containers found —</option>';
        } catch (e) {
            selCont.innerHTML = `<option value="">— Error: ${e.message} —</option>`;
        }
    }

    // ── Drawer open/close ─────────────────────────────────────────────────────

    btnNew.addEventListener('click', () => {
        drawer.hidden = false;
        hideErr(snapErr);
        descInput.value = '';
        loadContainers();
    });

    btnClose.addEventListener('click', () => { drawer.hidden = true; });

    // ── Create snapshot ───────────────────────────────────────────────────────

    btnCreate.addEventListener('click', async () => {
        hideErr(snapErr);
        const opt = selCont.selectedOptions[0];
        if (!opt || !opt.value) { showErr(snapErr, 'Select a container.'); return; }

        // opt.value is "container:<short_id>" — extract the raw full_id from data
        // The node id is "container:<short_id>"; we need full_id from the graph data.
        // Simpler: pass the displayed name and image, rely on container_id from opt.value.
        const rawId  = opt.value.replace(/^container:/, '');
        const name   = opt.dataset.name || rawId;
        const image  = opt.dataset.image || '';

        btnCreate.disabled = true;
        btnCreate.textContent = 'Capturing…';
        try {
            const r = await fetch('/docker/snapshots', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    container_id: rawId,
                    container_name: name,
                    image,
                    description: descInput.value.trim() || null,
                }),
            });
            const json = await r.json();
            if (!r.ok) { showErr(snapErr, json.error || `HTTP ${r.status}`); return; }
            drawer.hidden = true;
            snapSucMsg.textContent = `Snapshot created: ${json.snapshot_tag}`;
            snapSuc.hidden = false;
            loadSnapshots();
        } catch (e) {
            showErr(snapErr, e.message);
        } finally {
            btnCreate.disabled = false;
            btnCreate.textContent = 'Capture';
        }
    });

    btnSucDis.addEventListener('click', () => { snapSuc.hidden = true; });

    // ── Load & render snapshot table ──────────────────────────────────────────

    async function loadSnapshots() {
        tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Loading…</td></tr>';
        try {
            const r = await fetch('/docker/snapshots/data');
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const { snapshots } = await r.json();

            document.getElementById('stat-total').textContent = snapshots.length;
            if (snapshots.length) {
                const oldest = snapshots[snapshots.length - 1];
                document.getElementById('stat-oldest').textContent = fmtDate(oldest.created_at);
            } else {
                document.getElementById('stat-oldest').textContent = '—';
            }

            if (!snapshots.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No snapshots yet.</td></tr>';
                return;
            }

            tbody.innerHTML = snapshots.map(s => `
                <tr>
                    <td class="snap-tag">${escHtml(s.snapshot_tag)}</td>
                    <td>${escHtml(s.container_name)}</td>
                    <td class="snap-image">${escHtml(s.original_image)}</td>
                    <td>${s.description ? escHtml(s.description) : '<span class="text-muted">—</span>'}</td>
                    <td class="snap-date">${escHtml(fmtDate(s.created_at))}</td>
                    <td class="col-actions">
                        <div class="row-actions">
                            <button class="button outline small" data-action="restore" data-id="${s.id}" data-name="${escAttr(s.container_name)}">Restore</button>
                            <button class="button danger small"  data-action="delete"  data-id="${s.id}">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="6" class="table-empty">Error: ${escHtml(e.message)}</td></tr>`;
        }
    }

    function escHtml(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function escAttr(s) { return String(s ?? '').replace(/"/g, '&quot;'); }

    // ── Table actions (restore / delete) ──────────────────────────────────────

    tbody.addEventListener('click', e => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const id   = parseInt(btn.dataset.id, 10);
        const act  = btn.dataset.action;

        if (act === 'delete') {
            if (!confirm('Delete this snapshot image permanently?')) return;
            doDelete(id, btn);
        } else if (act === 'restore') {
            pendingRestoreId = id;
            restoreName.value = (btn.dataset.name || 'restored') + '-restored';
            hideErr(restoreErr);
            restoreModal.hidden = false;
            restoreName.focus();
        }
    });

    async function doDelete(id, btn) {
        btn.disabled = true;
        try {
            const r = await fetch(`/docker/snapshots/${id}`, { method: 'DELETE' });
            if (!r.ok) {
                const j = await r.json().catch(() => ({}));
                alert(j.error || `HTTP ${r.status}`);
                return;
            }
            loadSnapshots();
        } finally {
            btn.disabled = false;
        }
    }

    // ── Restore modal ─────────────────────────────────────────────────────────

    btnRestoreCanc.addEventListener('click', () => {
        restoreModal.hidden = true;
        pendingRestoreId = null;
    });

    restoreModal.addEventListener('click', e => {
        if (e.target === restoreModal) { restoreModal.hidden = true; pendingRestoreId = null; }
    });

    btnRestoreOk.addEventListener('click', async () => {
        if (!pendingRestoreId) return;
        hideErr(restoreErr);
        const name = restoreName.value.trim();
        if (!name) { showErr(restoreErr, 'Enter a container name.'); return; }

        btnRestoreOk.disabled = true;
        btnRestoreOk.textContent = 'Restoring…';
        try {
            const r = await fetch(`/docker/snapshots/${pendingRestoreId}/restore`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name }),
            });
            const json = await r.json().catch(() => ({}));
            if (!r.ok) { showErr(restoreErr, json.error || `HTTP ${r.status}`); return; }
            restoreModal.hidden = true;
            pendingRestoreId = null;
            snapSucMsg.textContent = `Container restored: ${json.container_id.substring(0, 12)}`;
            snapSuc.hidden = false;
        } finally {
            btnRestoreOk.disabled = false;
            btnRestoreOk.textContent = 'Restore';
        }
    });

    // ── Init ──────────────────────────────────────────────────────────────────

    loadSnapshots();
}());
