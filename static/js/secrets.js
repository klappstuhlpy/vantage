let currentFilter = "open";

function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmtRelative(iso) {
    if (!iso) return "—";
    const t = new Date(iso).getTime();
    if (!isFinite(t)) return "—";
    const diff = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (diff < 60)   return diff + "s ago";
    if (diff < 3600) return Math.floor(diff / 60)   + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
}

function fmtNumber(n) {
    return (n ?? 0).toLocaleString();
}

async function loadData() {
    const url = `/secrets/data?status=${encodeURIComponent(currentFilter)}`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    renderTiles(data);
    renderFindings(data.findings);
}

function renderTiles(data) {
    document.getElementById("tile-open").textContent      = fmtNumber(data.counts.open);
    document.getElementById("tile-critical").textContent  = fmtNumber(data.counts.critical_open);
    document.getElementById("tile-dismissed").textContent = fmtNumber(data.counts.dismissed);

    const ls = data.last_scan;
    if (ls && ls.started_at) {
        document.getElementById("tile-last-scan").textContent = fmtRelative(ls.started_at);
        document.getElementById("tile-last-scan-detail").textContent =
            `${fmtNumber(ls.files_scanned)} files · ${fmtNumber(ls.findings_new)} new / ${fmtNumber(ls.findings_total)} total`;
    } else {
        document.getElementById("tile-last-scan").textContent = "never";
        document.getElementById("tile-last-scan-detail").textContent = "run a scan to populate";
    }
}

function renderFindings(rows) {
    const tbody = document.querySelector("#findings-table tbody");
    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="muted">No findings</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(r => {
        const sevCls = r.severity;
        const isOpen = r.status === "open";
        const actions = isOpen
            ? `<button class="button outline" data-id="${r.id}" data-status="dismissed">Dismiss</button>
               <button class="button primary" data-id="${r.id}" data-status="resolved">Resolved</button>`
            : `<button class="button outline" data-id="${r.id}" data-status="open">Reopen</button>`;

        return `<tr>
            <td><span class="pill ${sevCls}">${sevCls}</span></td>
            <td>${escapeHtml(r.rule)}</td>
            <td><div class="finding-file"><code>${escapeHtml(r.file_path)}</code>
                <span class="line">:${r.line}</span></div></td>
            <td><code class="finding-snippet" title="${escapeHtml(r.snippet)}">${escapeHtml(r.snippet)}</code></td>
            <td>${fmtRelative(r.last_seen)}</td>
            <td><div class="row-actions">${actions}</div></td>
        </tr>`;
    }).join("");

    tbody.querySelectorAll(".row-actions .button").forEach(btn => {
        btn.addEventListener("click", () => updateStatus(btn.dataset.id, btn.dataset.status));
    });
}

async function updateStatus(id, status) {
    const body = new URLSearchParams({ status });
    const res = await fetch(`/secrets/${id}/status`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
    });
    if (res.ok) {
        loadData();
    } else {
        alert(`Failed to update status (HTTP ${res.status}).`);
    }
}

document.querySelectorAll("#filter-tabs .button").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll("#filter-tabs .button").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        currentFilter = btn.dataset.filter;
        loadData();
    });
});

document.getElementById("scan-now-btn").addEventListener("click", async () => {
    const btn = document.getElementById("scan-now-btn");
    btn.disabled = true;
    btn.textContent = "Scanning…";
    try {
        const res = await fetch("/secrets/scan", { method: "POST" });
        const data = await res.json();
        if (!data.started) {
            alert(data.detail);
        } else {
            setTimeout(loadData, 3000);
        }
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = "Scan now";
        }, 3000);
    }
});

loadData();
setInterval(loadData, 30000);
