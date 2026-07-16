/* ── Health / uptime dashboard ──────────────────────────────────
   - Polls /monitors/data every 15s
   - Modal editor for create / update
   - Inline action buttons: probe, toggle, delete
   ───────────────────────────────────────────────────────────── */

function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmtNumber(n) { return (n ?? 0).toLocaleString(); }

function fmtPercent(p) {
    if (p == null) return "—";
    return (p * 100).toFixed(p >= 0.999 ? 2 : 1) + "%";
}

function fmtRelative(iso) {
    if (!iso) return "—";
    const t = new Date(iso).getTime();
    if (!isFinite(t)) return "—";
    const diff = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (diff < 60)    return diff + "s ago";
    if (diff < 3600)  return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
}

function fmtDuration(startIso, endIso) {
    if (!startIso) return "—";
    const start = new Date(startIso).getTime();
    const end = endIso ? new Date(endIso).getTime() : Date.now();
    const secs = Math.max(0, Math.floor((end - start) / 1000));
    if (secs < 60)   return secs + "s";
    if (secs < 3600) return Math.floor(secs / 60) + "m " + (secs % 60) + "s";
    if (secs < 86400) return Math.floor(secs / 3600) + "h " + Math.floor((secs % 3600) / 60) + "m";
    return Math.floor(secs / 86400) + "d " + Math.floor((secs % 86400) / 3600) + "h";
}

function uptimeClass(p) {
    if (p == null) return "";
    if (p < 0.9)  return "bad";
    if (p < 0.99) return "warn";
    return "";
}

/* ── data load ─────────────────────────────────────────────── */

async function loadData() {
    const res = await fetch("/monitors/data");
    if (!res.ok) return;
    const data = await res.json();
    renderTiles(data);
    renderTargets(data.summaries);
    renderIncidents(data.summaries);
}

function renderTiles(data) {
    document.getElementById("tile-total").textContent     = fmtNumber(data.total_targets);
    document.getElementById("tile-up").textContent        = fmtNumber(data.up_count);
    document.getElementById("tile-degraded").textContent  = fmtNumber(data.degraded_count);
    document.getElementById("tile-down").textContent      = fmtNumber(data.down_count);
}

function renderTargets(rows) {
    const tbody = document.querySelector("#targets-table tbody");
    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="muted">No monitors yet. Click <strong>+ New monitor</strong> to add one.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(r => {
        const status = r.last_status || (r.enabled ? "pending" : "disabled");
        const statusCls = r.last_status || (r.enabled ? "pending" : "down");
        const uptime = r.uptime_24h;
        const upPct = uptime != null ? Math.max(0, Math.min(1, uptime)) * 100 : 0;
        const upCls = uptimeClass(uptime);
        const latency = r.last_latency_ms != null ? r.last_latency_ms + " ms" : "—";
        const sslDays = r.last_ssl_days_left;
        const sslExtra = (r.kind === "ssl" && sslDays != null)
            ? `<div class="muted" style="font-size:.7rem">${sslDays} d left</div>`
            : "";

        return `<tr data-id="${r.id}">
            <td><span class="pill dot ${statusCls}">${escapeHtml(status)}</span></td>
            <td>
                <strong>${escapeHtml(r.name)}</strong>
                ${!r.enabled ? '<span class="muted" style="margin-left:.4rem">(disabled)</span>' : ''}
            </td>
            <td><span class="chip kind-chip">${escapeHtml(r.kind)}</span></td>
            <td><div class="health-target" title="${escapeHtml(r.target)}">${escapeHtml(r.target)}</div></td>
            <td>${latency}${sslExtra}</td>
            <td>
                <div class="uptime-cell">
                    <div class="uptime-bar ${upCls}"><div class="uptime-bar-fill" style="width:${upPct.toFixed(1)}%"></div></div>
                    <span>${fmtPercent(uptime)}</span>
                </div>
            </td>
            <td>${r.last_check ? fmtRelative(r.last_check) : '—'}</td>
            <td><div class="row-actions">
                <button class="button outline" data-action="probe">Check now</button>
                <button class="button outline" data-action="toggle">${r.enabled ? "Disable" : "Enable"}</button>
                <button class="button outline" data-action="edit">Edit</button>
                <button class="button danger small" data-action="delete">Delete</button>
            </div></td>
        </tr>`;
    }).join("");

    tbody.querySelectorAll("button[data-action]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            const tr = ev.target.closest("tr");
            const id = tr.dataset.id;
            const action = ev.target.dataset.action;
            handleAction(id, action, rows.find(x => String(x.id) === id));
        });
    });
}

function renderIncidents(summaries) {
    // Pull the full incident list separately so we get closed ones too.
    fetch("/monitors/incidents?limit=100").then(r => r.json()).then(rows => {
        const tbody = document.querySelector("#incidents-table tbody");
        if (!rows || rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="muted">No incidents recorded.</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.map(i => {
            const ongoing = !i.ended_at;
            return `<tr>
                <td><span class="pill dot ${i.status}">${escapeHtml(i.status)}</span></td>
                <td>${escapeHtml(i.target_name || ("#" + i.target_id))}</td>
                <td>${fmtRelative(i.started_at)}</td>
                <td>${ongoing ? '<span class="ongoing">ongoing</span>' : fmtRelative(i.ended_at)}</td>
                <td>${fmtDuration(i.started_at, i.ended_at)}</td>
                <td>${escapeHtml(i.last_error || "")}</td>
            </tr>`;
        }).join("");
    });
}

/* ── per-row actions ───────────────────────────────────────── */

async function handleAction(id, action, target) {
    if (action === "probe") {
        const res = await fetch(`/monitors/${id}/check`, { method: "POST" });
        if (res.ok) loadData();
        else alert(`Probe failed (HTTP ${res.status}).`);
    } else if (action === "toggle") {
        const body = new URLSearchParams({ enabled: target.enabled ? "false" : "true" });
        const res = await fetch(`/monitors/${id}/toggle`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body,
        });
        if (res.ok) loadData();
    } else if (action === "delete") {
        if (!confirm(`Delete monitor "${target.name}"? This also drops its samples and incidents.`)) return;
        const res = await fetch(`/monitors/${id}`, { method: "DELETE" });
        if (res.ok) loadData();
    } else if (action === "edit") {
        openModal(target);
    }
}

/* ── modal editor ──────────────────────────────────────────── */

const modal = document.getElementById("health-modal");

function openModal(target) {
    document.getElementById("modal-title").textContent = target ? "Edit monitor" : "New monitor";
    document.getElementById("f-id").value = target ? target.id : "";
    document.getElementById("f-name").value = target ? target.name : "";
    document.getElementById("f-kind").value = target ? target.kind : "http";
    document.getElementById("f-target").value = target ? target.target : "";
    document.getElementById("f-interval").value = target ? target.interval_seconds : 60;
    document.getElementById("f-timeout").value = target ? target.timeout_ms : 5000;
    document.getElementById("f-degraded").value = target ? target.degraded_ms : 1000;
    document.getElementById("f-enabled").checked = target ? !!target.enabled : true;

    let config = {};
    if (target && target.config_json) {
        try { config = JSON.parse(target.config_json); } catch { /* ignore */ }
    }
    document.getElementById("f-method").value = config.method || "GET";
    document.getElementById("f-expected-status").value = (config.expected_status || []).join(",");
    document.getElementById("f-keyword").value = config.keyword || "";
    document.getElementById("f-invert").checked = !!config.invert_keyword;
    document.getElementById("f-warn-days").value = config.warn_days || 14;

    syncKindFields();
    modal.hidden = false;
}

function closeModal() { modal.hidden = true; }

function syncKindFields() {
    const kind = document.getElementById("f-kind").value;
    modal.querySelectorAll(".kind-extra").forEach(fs => {
        const kinds = fs.dataset.kind.split(" ");
        fs.hidden = !kinds.includes(kind);
    });
    modal.querySelectorAll(".kind-only").forEach(el => {
        const kinds = el.dataset.kind.split(" ");
        el.hidden = !kinds.includes(kind);
    });
}

document.getElementById("new-target-btn").addEventListener("click", () => openModal(null));
document.getElementById("modal-close").addEventListener("click", closeModal);
document.getElementById("modal-cancel").addEventListener("click", closeModal);
document.getElementById("refresh-btn").addEventListener("click", loadData);
document.getElementById("f-kind").addEventListener("change", syncKindFields);
modal.addEventListener("click", (ev) => { if (ev.target === modal) closeModal(); });

document.getElementById("health-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const id = document.getElementById("f-id").value;
    const kind = document.getElementById("f-kind").value;
    const config = {};
    if (kind === "http" || kind === "keyword") {
        config.method = document.getElementById("f-method").value;
        const raw = document.getElementById("f-expected-status").value.trim();
        if (raw) {
            config.expected_status = raw.split(",")
                .map(s => parseInt(s.trim(), 10))
                .filter(n => !isNaN(n));
        }
    }
    if (kind === "keyword") {
        config.keyword = document.getElementById("f-keyword").value;
        config.invert_keyword = document.getElementById("f-invert").checked;
    }
    if (kind === "ssl") {
        config.warn_days = parseInt(document.getElementById("f-warn-days").value, 10) || 14;
    }
    const form = new URLSearchParams({
        name: document.getElementById("f-name").value,
        kind,
        target: document.getElementById("f-target").value,
        interval_seconds: document.getElementById("f-interval").value,
        timeout_ms: document.getElementById("f-timeout").value,
        degraded_ms: document.getElementById("f-degraded").value,
        enabled: document.getElementById("f-enabled").checked ? "true" : "false",
        config_json: JSON.stringify(config),
    });
    const url = id ? `/monitors/${id}` : "/monitors";
    const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form,
    });
    if (res.ok) {
        closeModal();
        loadData();
    } else {
        alert(`Save failed (HTTP ${res.status}).`);
    }
});

/* ── live updates over WS, fallback to polling ─────────────── */

loadData();
setInterval(loadData, 15_000);

// Push-based refresh: reload the dashboard whenever the monitor publishes a
// health event. Polling above stays as the fallback when the socket is down
// (LiveConnection reconnects on its own). Mirrors the metrics page's usage.
if (window.LiveConnection) {
    const conn = new LiveConnection({
        topics: ["health", "health.event"],
        onEvent: () => loadData(),
    });
    conn.start();
}
