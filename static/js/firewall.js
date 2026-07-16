/* ── Firewall dashboard ───────────────────────────────────────
   Rules + lockouts CRUD, auto-refresh every 30s.
   ─────────────────────────────────────────────────────────── */

function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmtNumber(n) { return (n ?? 0).toLocaleString(); }

function fmtRelative(iso) {
    if (!iso) return "—";
    const t = new Date(iso).getTime();
    if (!isFinite(t)) return "—";
    const diff = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (diff < 60)   return diff + "s ago";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
}

function fmtExpires(iso) {
    if (!iso) return "permanent";
    const ts = new Date(iso).getTime();
    if (!isFinite(ts)) return "permanent";
    const diff = Math.floor((ts - Date.now()) / 1000);
    if (diff <= 0)   return "expiring…";
    if (diff < 60)   return "in " + diff + "s";
    if (diff < 3600) return "in " + Math.floor(diff / 60) + "m";
    if (diff < 86400) return "in " + Math.floor(diff / 3600) + "h";
    return "in " + Math.floor(diff / 86400) + "d";
}

async function loadData() {
    const res = await fetch("/firewall/data");
    if (!res.ok) return;
    const data = await res.json();
    renderTiles(data);
    renderRules(data.rules);
    renderLockouts(data.lockouts);
}

function renderTiles(data) {
    document.getElementById("tile-backend").textContent  = data.backend;
    document.getElementById("tile-rules").textContent    = fmtNumber((data.rules || []).filter(r => r.enabled).length);
    document.getElementById("tile-lockouts").textContent = fmtNumber((data.lockouts || []).filter(l => l.status === "active").length);
    document.getElementById("tile-auto").textContent = data.auto_threshold + " in " + Math.round(data.auto_window_secs / 60) + "m";
    document.getElementById("tile-auto-sub").textContent =
        "blocks for " + Math.round(data.auto_lockout_secs / 60) + "m";
}

function renderRules(rows) {
    const tbody = document.querySelector("#rules-table tbody");
    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="muted">No rules. Add one with <strong>+ New rule</strong>.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(r => {
        return `<tr data-id="${r.id}">
            <td><span class="pill ${r.action}">${r.action.replace('_', ' ')}</span></td>
            <td>${escapeHtml(r.source || "any")}</td>
            <td>${r.port ?? "any"}</td>
            <td>${r.proto}</td>
            <td>${escapeHtml(r.country || "")}</td>
            <td>${r.rate_per_s ? r.rate_per_s + "/s" : ""}</td>
            <td>${escapeHtml(r.note || "")}</td>
            <td>${r.enabled ? '<span class="pill dot up">enabled</span>' : '<span class="pill dot pending">disabled</span>'}</td>
            <td><div class="row-actions">
                <button class="button outline" data-action="toggle">${r.enabled ? "Disable" : "Enable"}</button>
                <button class="button danger" data-action="delete">Delete</button>
            </div></td>
        </tr>`;
    }).join("");

    tbody.querySelectorAll("button[data-action]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            const tr = ev.target.closest("tr");
            const id = tr.dataset.id;
            const action = ev.target.dataset.action;
            const rule = rows.find(x => String(x.id) === id);
            handleRuleAction(id, action, rule);
        });
    });
}

function renderLockouts(rows) {
    const tbody = document.querySelector("#lockouts-table tbody");
    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="muted">No lockouts on record.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(l => {
        return `<tr data-id="${l.id}">
            <td><span class="pill dot ${l.status === 'active' ? 'down' : 'pending'}">${l.status}</span></td>
            <td>${escapeHtml(l.ip)}</td>
            <td>${escapeHtml(l.reason)}</td>
            <td>${fmtNumber(l.hit_count)}</td>
            <td>${fmtRelative(l.locked_at)}</td>
            <td>${l.expires_at ? fmtExpires(l.expires_at) : '<span class="muted">permanent</span>'}</td>
            <td>${l.status === "active"
                ? `<button class="button outline" data-action="release">Release</button>`
                : ""}</td>
        </tr>`;
    }).join("");
    tbody.querySelectorAll("button[data-action='release']").forEach(btn => {
        btn.addEventListener("click", async (ev) => {
            const id = ev.target.closest("tr").dataset.id;
            await fetch(`/firewall/lockout/${id}/release`, { method: "POST" });
            loadData();
        });
    });
}

async function handleRuleAction(id, action, rule) {
    if (action === "delete") {
        if (!confirm(`Delete rule #${id}?`)) return;
        const res = await fetch(`/firewall/rule/${id}`, { method: "DELETE" });
        if (res.ok) loadData();
    } else if (action === "toggle") {
        const body = new URLSearchParams({ enabled: rule.enabled ? "false" : "true" });
        const res = await fetch(`/firewall/rule/${id}/toggle`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body,
        });
        if (res.ok) loadData();
    }
}

/* ── Rule modal ─────────────────────────────────────────────── */

const ruleModal = document.getElementById("rule-modal");
function openRuleModal() {
    document.getElementById("r-action").value = "deny";
    document.getElementById("r-direction").value = "in";
    document.getElementById("r-proto").value = "any";
    document.getElementById("r-port").value = "";
    document.getElementById("r-source").value = "";
    document.getElementById("r-country").value = "";
    document.getElementById("r-rate").value = "";
    document.getElementById("r-note").value = "";
    document.getElementById("r-enabled").checked = true;
    syncActionFields();
    ruleModal.hidden = false;
}
function closeRuleModal() { ruleModal.hidden = true; }
function syncActionFields() {
    const action = document.getElementById("r-action").value;
    ruleModal.querySelectorAll(".kind-only").forEach(el => {
        el.hidden = el.dataset.action !== action;
    });
}

document.getElementById("new-rule-btn").addEventListener("click", openRuleModal);
document.getElementById("rule-modal-close").addEventListener("click", closeRuleModal);
document.getElementById("rule-modal-cancel").addEventListener("click", closeRuleModal);
document.getElementById("r-action").addEventListener("change", syncActionFields);
ruleModal.addEventListener("click", (ev) => { if (ev.target === ruleModal) closeRuleModal(); });

document.getElementById("rule-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = new URLSearchParams();
    body.set("action", document.getElementById("r-action").value);
    body.set("direction", document.getElementById("r-direction").value);
    body.set("proto", document.getElementById("r-proto").value);
    const port = document.getElementById("r-port").value;
    if (port) body.set("port", port);
    const src = document.getElementById("r-source").value.trim();
    if (src) body.set("source", src);
    const cty = document.getElementById("r-country").value.trim();
    if (cty) body.set("country", cty);
    const rate = document.getElementById("r-rate").value;
    if (rate) body.set("rate_per_s", rate);
    const note = document.getElementById("r-note").value.trim();
    if (note) body.set("note", note);
    body.set("enabled", document.getElementById("r-enabled").checked ? "true" : "false");

    const res = await fetch("/firewall/rule", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
    });
    if (res.ok) {
        closeRuleModal();
        loadData();
    } else {
        alert(`Create rule failed (HTTP ${res.status}).`);
    }
});

/* ── Lockout form ───────────────────────────────────────────── */

document.getElementById("lockout-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = new URLSearchParams();
    body.set("ip", document.getElementById("lo-ip").value.trim());
    const reason = document.getElementById("lo-reason").value.trim();
    if (reason) body.set("reason", reason);
    const dur = document.getElementById("lo-duration").value;
    if (dur) body.set("duration_secs", dur);
    const res = await fetch("/firewall/lockout", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
    });
    if (res.ok) {
        document.getElementById("lockout-form").reset();
        loadData();
    } else {
        alert(`Lockout failed (HTTP ${res.status}).`);
    }
});

/* ── Re-apply all ───────────────────────────────────────────── */

document.getElementById("reapply-btn").addEventListener("click", async () => {
    const btn = document.getElementById("reapply-btn");
    btn.disabled = true;
    try {
        const res = await fetch("/firewall/apply", { method: "POST" });
        const data = await res.json();
        let msg = `Applied ${data.applied} rules.`;
        if (data.errors && data.errors.length) {
            msg += "\n\nErrors:\n" + data.errors.join("\n");
        }
        alert(msg);
        loadData();
    } finally {
        btn.disabled = false;
    }
});

loadData();
setInterval(loadData, 30_000);
