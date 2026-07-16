/* ── Vantage database console ────────────────────────────────
   Browses the single admin.db and runs ad-hoc queries against it.
   Safe-mode is on by default; toggling it off shows a confirmation
   banner and switches the Run button to danger style.
   Extracted from the page (no inline JS → a strict CSP holds later).
   ──────────────────────────────────────────────────────────── */

const tablesTbody = document.querySelector("#db-tables tbody");
const sqlInput    = document.getElementById("sql-input");
const runBtn      = document.getElementById("run-btn");
const safeToggle  = document.getElementById("safe-mode");
const statusEl    = document.getElementById("db-status");
const resultMeta  = document.getElementById("db-result-meta");
const resultTable = document.getElementById("db-result");
const errorBox    = document.getElementById("db-error");
const errorBody   = document.getElementById("db-error-body");

function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmtNumber(n) { return (n ?? 0).toLocaleString(); }

function showStatus(text, cls) {
    statusEl.className = "db-status" + (cls ? " " + cls : "");
    statusEl.textContent = text || "";
}

/* Pulls a usable message out of a failed Response. The backend sends
   `{ "error": "…" }`; a non-JSON body is shown verbatim, and as a last
   resort we fall back to the status code (res.statusText is empty over
   HTTP/2, so never rely on it alone). */
async function errorMessage(res) {
    const text = await res.text().catch(() => "");
    if (text) {
        try {
            const j = JSON.parse(text);
            if (j && j.error) return String(j.error);
        } catch { /* not JSON — show the raw body */ }
        return text;
    }
    return `Request failed (HTTP ${res.status})`;
}

function showError(msg) {
    errorBody.textContent = msg || "Unknown error";
    errorBox.hidden = false;
}

function clearError() {
    errorBox.hidden = true;
    errorBody.textContent = "";
}

/* ── Tables list ───────────────────────────────────────────── */

async function loadTables() {
    tablesTbody.innerHTML = '<tr><td colspan="3" class="muted">Loading…</td></tr>';
    const res = await fetch("/database/tables");
    if (!res.ok) {
        tablesTbody.innerHTML = `<tr><td colspan="3" class="muted">Error: ${escapeHtml(await errorMessage(res))}</td></tr>`;
        return;
    }
    const rows = await res.json();
    if (rows.length === 0) {
        tablesTbody.innerHTML = '<tr><td colspan="3" class="muted">No tables</td></tr>';
        return;
    }
    tablesTbody.innerHTML = rows.map(r => `<tr>
        <td><code>${escapeHtml(r.name)}</code></td>
        <td class="numeric">${fmtNumber(r.row_estimate)}</td>
        <td><button class="button outline use-table-btn" data-name="${escapeHtml(r.name)}"
                title="Insert a SELECT * stub into the query box">Use</button></td>
    </tr>`).join("");

    tablesTbody.querySelectorAll(".use-table-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const ref = `"${btn.dataset.name.replace(/"/g, '""')}"`;
            sqlInput.value = `SELECT * FROM ${ref} LIMIT 100;`;
            sqlInput.focus();
        });
    });
}

/* ── Safe-mode toggle ───────────────────────────────────────── */

safeToggle.addEventListener("change", () => {
    const safe = safeToggle.checked;
    runBtn.classList.toggle("danger", !safe);
    let banner = document.querySelector(".db-danger-banner");
    if (!safe && !banner) {
        banner = document.createElement("div");
        banner.className = "db-danger-banner";
        banner.textContent =
            "⚠ Safe mode off. The query runs with writes enabled — INSERT, UPDATE, DELETE, DROP and other writes are permitted.";
        runBtn.closest(".db-actions").insertAdjacentElement("afterend", banner);
    } else if (safe && banner) {
        banner.remove();
    }
});

/* ── Run query ──────────────────────────────────────────────── */

runBtn.addEventListener("click", async () => {
    const sql = sqlInput.value.trim();
    if (!sql) return;
    runBtn.disabled = true;
    clearError();
    showStatus("Running…");

    // serde_urlencoded can't parse an empty `danger_mode=` into a bool, so
    // always send an explicit "true"/"false".
    const body = new URLSearchParams({
        sql,
        danger_mode: safeToggle.checked ? "false" : "true",
    });

    try {
        const res = await fetch("/database/query", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body,
        });
        if (!res.ok) {
            showError(await errorMessage(res));
            showStatus("Query failed", "error");
            return;
        }
        const data = await res.json();
        renderResult(data);
        showStatus(`OK · ${data.row_count} rows in ${data.elapsed_ms} ms`, "ok");
        // A write may have changed row counts — refresh the tables panel.
        if (!safeToggle.checked) loadTables();
    } catch (e) {
        showError("Network error: " + (e.message || e));
        showStatus("Query failed", "error");
    } finally {
        runBtn.disabled = false;
    }
});

function renderResult(data) {
    const cols = data.columns || [];
    const rows = data.rows || [];

    resultMeta.textContent = data.truncated
        ? `Showing first ${rows.length} of ${fmtNumber(data.row_count)} rows (capped at 1000) · ${data.elapsed_ms} ms`
        : `${fmtNumber(rows.length)} row${rows.length === 1 ? "" : "s"} · ${data.elapsed_ms} ms`;

    const thead = resultTable.querySelector("thead");
    const tbody = resultTable.querySelector("tbody");

    if (cols.length === 0 && rows.length === 0) {
        thead.innerHTML = '<tr><th class="muted">Query executed (no rows returned)</th></tr>';
        tbody.innerHTML = "";
        return;
    }

    thead.innerHTML = "<tr>" + cols.map(c => `<th>${escapeHtml(c)}</th>`).join("") + "</tr>";
    tbody.innerHTML = rows.map(row =>
        "<tr>" + row.map(cell => `<td>${escapeHtml(cell)}</td>`).join("") + "</tr>"
    ).join("");
}

/* ── Boot ──────────────────────────────────────────────────── */

loadTables();

// Ctrl/Cmd+Enter runs the query.
sqlInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runBtn.click();
    }
});
