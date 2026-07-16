/* ── Service card button state ───────────────────────────────── */
function syncCardButtons(card) {
  // While an action (start/stop/restart/pull/recreate) is in flight, its
  // buttons are intentionally locked and the submitter shows "Working…".
  // The periodic refresh must not re-enable them mid-action — onActionSubmit
  // owns the button state until it finishes and clears this flag.
  if (card.dataset.actionBusy === "true") return;

  const isRunning  = card.dataset.running === "true";
  const startBtn   = card.querySelector(".start-btn");
  const restartBtn = card.querySelector(".restart-btn");
  const stopBtn    = card.querySelector(".stop-btn");
  const pullBtn    = card.querySelector(".pull-btn");
  const recreateBtn = card.querySelector(".recreate-btn");

  if (startBtn)   startBtn.disabled   = isRunning;
  if (restartBtn) restartBtn.disabled = !isRunning;
  if (stopBtn)    stopBtn.disabled    = !isRunning;
  // Pull / Recreate are always available. (A registry update-availability hint
  // that could disable Pull for locally-built images arrives with the updates
  // slice; until then Pull just runs `docker pull` / `compose pull`.)
  if (pullBtn) pullBtn.disabled = false;
  if (recreateBtn) recreateBtn.disabled = false;
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".service-card").forEach(syncCardButtons);
  wireActionForms();
  loadActionLog();
});

/* ── Docker action log ───────────────────────────────────────── */

const actionLogBody  = document.getElementById("action-log-body");
const actionLogEmpty = document.getElementById("action-log-empty");
const actionLogBusy  = document.getElementById("action-log-busy");
const actionLogRefresh = document.getElementById("action-log-refresh");

function fmtActionTime(iso) {
  try {
    return new Date(iso).toLocaleString([], {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch (_) {
    return "";
  }
}

function buildActionRow(entry) {
  const row = document.createElement("div");
  row.className = "action-row " + (entry.success ? "ok" : "fail");

  const head = document.createElement("div");
  head.className = "action-row-head";
  head.innerHTML =
    `<span class="action-badge ${entry.success ? "ok" : "fail"}">${escHtml(entry.action)}</span>` +
    `<span class="action-service">${escHtml(entry.service)}</span>` +
    (entry.actor ? `<span class="action-actor">${escHtml(entry.actor)}</span>` : "") +
    `<span class="action-time">${escHtml(fmtActionTime(entry.ts))}</span>`;
  row.appendChild(head);

  const out = (entry.output || "").trim();
  if (out) {
    const pre = document.createElement("pre");
    pre.className = "action-output";
    pre.textContent = out;
    row.appendChild(pre);
  }
  return row;
}

async function loadActionLog() {
  if (!actionLogBody) return;
  try {
    const res = await fetch("/docker/actions/log");
    if (!res.ok) return;
    const data = await res.json();
    const entries = Array.isArray(data.actions) ? data.actions : [];
    actionLogBody.querySelectorAll(".action-row").forEach(n => n.remove());
    if (entries.length === 0) {
      if (actionLogEmpty) actionLogEmpty.hidden = false;
      return;
    }
    if (actionLogEmpty) actionLogEmpty.hidden = true;
    // Server returns newest-first; append in order so newest stays on top.
    for (const entry of entries) actionLogBody.appendChild(buildActionRow(entry));
  } catch (e) {
    console.error("action log load failed", e);
  }
}

actionLogRefresh?.addEventListener("click", loadActionLog);

/* ── Service action buttons (start/stop/restart/pull/recreate) ── */

function wireActionForms() {
  document
    .querySelectorAll(".service-card form[action='/docker/action']")
    .forEach(form => form.addEventListener("submit", onActionSubmit));
}

async function onActionSubmit(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const card = form.closest(".service-card");
  const submitter = e.submitter || form.querySelector("button[type='submit']");
  const action = submitter ? submitter.value : "";
  const nameInput = form.querySelector("input[name='name']");
  const name = nameInput ? nameInput.value : (card ? card.dataset.name : "");
  if (!action || !name) return;

  // Busy state: lock every button on the card and show a spinner label.
  // The actionBusy flag tells syncCardButtons (run by the periodic refresh)
  // to leave this card's buttons alone until the action finishes.
  if (card) card.dataset.actionBusy = "true";
  const buttons = card ? Array.from(card.querySelectorAll("button")) : [];
  buttons.forEach(b => { b.disabled = true; });
  const originalText = submitter ? submitter.textContent : "";
  if (submitter) submitter.textContent = "Working…";
  if (actionLogBusy) actionLogBusy.hidden = false;

  const body = new URLSearchParams({ name, action });

  try {
    const res = await fetch("/docker/action", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const data = await res.json().catch(() => ({}));

    // Optimistically show the result immediately; loadActionLog() below
    // reconciles with the authoritative server-side log.
    if (actionLogBody) {
      if (actionLogEmpty) actionLogEmpty.hidden = true;
      actionLogBody.prepend(buildActionRow({
        ts: new Date().toISOString(),
        service: data.service || name,
        action: data.action || action,
        success: data.ok === true,
        actor: "you",
        output: data.output || (res.ok ? "" : `request failed (HTTP ${res.status})`),
      }));
    }
  } catch (err) {
    console.error("docker action failed", err);
    if (actionLogBody) {
      actionLogBody.prepend(buildActionRow({
        ts: new Date().toISOString(),
        service: name, action, success: false, actor: "you",
        output: "network error — could not reach the server",
      }));
    }
  } finally {
    if (submitter) submitter.textContent = originalText;
    if (actionLogBusy) actionLogBusy.hidden = true;
    // Action done: drop the busy lock first so the refresh below can re-derive
    // the correct per-button disabled states. Re-enable everything we locked
    // (including the Logs button, which syncCardButtons doesn't manage), then
    // refresh the live data so the card reflects the new running state /
    // restart count / start time. A second delayed refresh catches containers
    // that are still settling after a restart or recreate.
    if (card) delete card.dataset.actionBusy;
    buttons.forEach(b => { b.disabled = false; });
    await refreshServices();
    await loadActionLog();
    setTimeout(refreshServices, 2500);
  }
}

/* ── Filter (search) ─────────────────────────────────────────── */

const searchInput = document.getElementById("services-search");
const emptyState  = document.getElementById("services-empty");

function applyFilter() {
  if (!searchInput) return;
  const q = searchInput.value.trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll(".service-card").forEach(card => {
    const hay = [
      card.dataset.name  || "",
      card.dataset.kind  || "",
      card.dataset.image || "",
    ].join(" ").toLowerCase();
    const match = q === "" || hay.includes(q);
    card.classList.toggle("filtered", !match);
    if (match) visible++;
  });
  if (emptyState) emptyState.hidden = visible !== 0 || q === "";
}

searchInput?.addEventListener("input", applyFilter);

/* ── Live auto-refresh ──────────────────────────────────────── */

const refreshState = document.getElementById("services-refresh-state");
const REFRESH_MS   = 15_000;
let logModalOpen   = false;

function fmtBytes(n) {
  if (n == null || !isFinite(n)) return "—";
  if (n === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i = Math.floor(Math.log(Math.abs(n)) / Math.log(k));
  return (n / Math.pow(k, i)).toFixed(i ? 1 : 0) + " " + sizes[i];
}

function fmtIsoStarted(iso) {
  if (!iso) return null;
  try {
    return "Started " + new Date(iso).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  } catch (_) {
    return null;
  }
}

function statusClass(pct) {
  if (pct == null) return "";
  if (pct >= 90) return "alert";
  if (pct >= 70) return "warn";
  return "";
}

function updateCardFromView(card, view) {
  // Status badge + running flag (drives button disabled-state)
  card.dataset.running = view.running ? "true" : "false";
  const badge = card.querySelector("[data-role='status']");
  if (badge) {
    badge.classList.toggle("running", view.running);
    badge.classList.toggle("offline", !view.running);
    badge.textContent = view.running ? "Running" : "Offline";
  }

  // Started / not running text
  const started = card.querySelector("[data-role='started']");
  if (started) {
    if (view.running) {
      const label = fmtIsoStarted(view.started_at);
      if (label) {
        started.textContent = label;
        started.classList.remove("muted");
      } else {
        started.textContent = "Start time unavailable";
        started.classList.add("muted");
      }
    } else {
      started.textContent = "Not running";
      started.classList.add("muted");
    }
  }

  // Restarts
  const restarts = card.querySelector("[data-role='restarts']");
  if (restarts && view.restart_count != null) {
    restarts.textContent = view.restart_count;
  }

  // Live CPU / RAM (only Docker services with `docker stats` data)
  const cpuRow = card.querySelector("[data-role='cpu-row']");
  const memRow = card.querySelector("[data-role='mem-row']");
  if (view.cpu_pct != null && cpuRow && memRow) {
    cpuRow.hidden = false;
    memRow.hidden = false;

    cpuRow.querySelector("[data-role='cpu-value']").textContent = view.cpu_pct.toFixed(1) + "%";
    const cpuBar = cpuRow.querySelector("[data-role='cpu-bar']");
    cpuBar.style.width = Math.min(view.cpu_pct, 100).toFixed(1) + "%";
    cpuRow.querySelector(".bar").className = "bar " + statusClass(view.cpu_pct);

    const memPct = view.mem_limit > 0 ? (view.mem_used / view.mem_limit * 100) : 0;
    memRow.querySelector("[data-role='mem-value']").textContent =
      `${fmtBytes(view.mem_used)} / ${fmtBytes(view.mem_limit)} (${memPct.toFixed(1)}%)`;
    const memBar = memRow.querySelector("[data-role='mem-bar']");
    memBar.style.width = Math.min(memPct, 100).toFixed(1) + "%";
    memRow.querySelector(".bar").className = "bar " + statusClass(memPct);
  } else if (cpuRow && memRow) {
    cpuRow.hidden = true;
    memRow.hidden = true;
  }

  syncCardButtons(card);
}

async function refreshServices() {
  // Pause while the user is reading logs — the SSE stream would compete
  // for the docker socket and the page is already pinned to one service.
  if (logModalOpen) return;
  if (refreshState) {
    refreshState.classList.add("refreshing");
    refreshState.textContent = "refreshing";
  }
  try {
    const res = await fetch("/docker/services/data");
    if (!res.ok) return;
    const views = await res.json();
    const byName = new Map(views.map(v => [v.name, v]));
    document.querySelectorAll(".service-card").forEach(card => {
      const v = byName.get(card.dataset.name);
      if (v) updateCardFromView(card, v);
    });
  } catch (e) {
    console.error("services refresh failed", e);
  } finally {
    if (refreshState) {
      refreshState.classList.remove("refreshing");
      refreshState.textContent = "auto · 15s";
    }
  }
}

// Initial label + start the loop.
if (refreshState) refreshState.textContent = "auto · 15s";
refreshServices();
setInterval(refreshServices, REFRESH_MS);

/* ── Log console ─────────────────────────────────────────────── */

const modal         = document.getElementById("log-modal");
const terminal      = document.getElementById("log-terminal");
const modalName     = document.getElementById("log-modal-name");
const connDot       = document.getElementById("log-connection-dot");
const connLabel     = document.getElementById("log-connection-label");
const closeBtn      = document.getElementById("log-close-btn");
const clearBtn      = document.getElementById("log-clear-btn");
const autoscrollCbx = document.getElementById("autoscroll-toggle");

let activeSource = null;

/* ── Log line highlighting ───────────────────────────────────── */

/** Strip ANSI/VT escape sequences. */
function stripAnsi(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
}

/** Escape the five HTML special characters. */
function escHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Patterns are listed highest-priority first.
 * When two matches overlap the one that starts earlier wins; if they start
 * at the same position the longer (more specific) match wins.
 */
const LOG_PATTERNS = [
  // ISO-8601 / Docker timestamps
  { re: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, cls: "hl-ts" },
  // Log levels — error
  { re: /\b(?:ERROR|FATAL|CRITICAL|PANIC|EXCEPTION|EMERG|ALERT)\b/gi,               cls: "hl-error" },
  // Log levels — warning
  { re: /\bWARN(?:ING)?\b/gi,                                                        cls: "hl-warn" },
  // Log levels — info
  { re: /\b(?:INFO|NOTICE|SUCCESS)\b/gi,                                             cls: "hl-info" },
  // Log levels — debug
  { re: /\b(?:DEBUG|TRACE|VERBOSE)\b/gi,                                             cls: "hl-debug" },
  // HTTP methods
  { re: /\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\b/g,                   cls: "hl-method" },
  // URLs
  { re: /https?:\/\/[^\s"<>]+/g,                                                     cls: "hl-url" },
  // HTTP status 4xx / 5xx
  { re: /\b[45]\d{2}\b/g,                                                            cls: "hl-status-err" },
  // HTTP status 1xx / 2xx / 3xx
  { re: /\b[123]\d{2}\b/g,                                                           cls: "hl-status-ok" },
  // Double-quoted strings
  { re: /"(?:[^"\\]|\\.)*"/g,                                                        cls: "hl-string" },
  // IP address (optionally with port)
  { re: /\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g,                               cls: "hl-ip" },
  // Durations: 123ms, 1.5s, 800µs, 400ns
  { re: /\b\d+(?:\.\d+)?(?:µs|ms|ns|us|s|m|h)\b/g,                                 cls: "hl-duration" },
  // Plain numbers (lowest priority)
  { re: /\b\d+(?:\.\d+)?\b/g,                                                        cls: "hl-num" },
];

/**
 * Returns an HTML string for one log line with semantic spans.
 * Strips ANSI codes, HTML-escapes all plain text, and wraps matched
 * tokens in <span class="hl-*"> elements.  Patterns never overlap —
 * higher-priority (earlier in the list) matches shadow lower ones.
 */
function highlightLogLine(raw) {
  const text = stripAnsi(raw);

  // Collect every match from every pattern
  const matches = [];
  for (const { re, cls } of LOG_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, cls, src: m[0] });
    }
  }

  // Sort: earlier start first; same start → longer match first
  matches.sort((a, b) => a.start - b.start || b.end - a.end);

  // Walk left-to-right, keeping only non-overlapping tokens
  const tokens = [];
  let cursor = 0;
  for (const tok of matches) {
    if (tok.start >= cursor) {
      tokens.push(tok);
      cursor = tok.end;
    }
  }

  // Rebuild the line as HTML
  let html = "";
  let pos = 0;
  for (const { start, end, cls, src } of tokens) {
    if (start > pos) html += escHtml(text.slice(pos, start));
    html += `<span class="${cls}">${escHtml(src)}</span>`;
    pos = end;
  }
  if (pos < text.length) html += escHtml(text.slice(pos));
  return html;
}

function setConnectionState(state) {
  connDot.className   = "log-connection-dot " + state;    // connecting | connected | closed | error
  const labels = { connecting: "Connecting…", connected: "Connected", closed: "Closed", error: "Error" };
  connLabel.textContent = labels[state] ?? state;
}

function appendLine(text) {
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = highlightLogLine(text);   // stripAnsi + escHtml called inside
  terminal.appendChild(line);

  if (autoscrollCbx.checked) {
    terminal.scrollTop = terminal.scrollHeight;
  }
}

function openLogs(serviceName) {
  closeLogs();                          // close any existing connection first
  logModalOpen = true;                  // pause auto-refresh while reading
  terminal.innerHTML = "";
  modalName.textContent = serviceName + " — logs";
  setConnectionState("connecting");
  modal.showModal();

  activeSource = new EventSource(`/docker/logs/${encodeURIComponent(serviceName)}`);

  activeSource.onopen = () => setConnectionState("connected");

  activeSource.onmessage = (e) => appendLine(e.data);

  activeSource.onerror = () => {
    setConnectionState("error");
    activeSource.close();
    activeSource = null;
  };
}

function closeLogs() {
  if (activeSource) {
    activeSource.close();
    activeSource = null;
  }
  logModalOpen = false;       // resume auto-refresh
  setConnectionState("closed");
}

/* Wire up the Logs button on each service card */
document.querySelectorAll(".logs-btn").forEach(btn => {
  const card = btn.closest(".service-card");
  btn.addEventListener("click", () => openLogs(card.dataset.name));
});

closeBtn.addEventListener("click", () => {
  closeLogs();
  modal.close();
});

clearBtn.addEventListener("click", () => {
  terminal.innerHTML = "";
});

/* Close on backdrop click */
modal.addEventListener("click", (e) => {
  if (e.target === modal) {
    closeLogs();
    modal.close();
  }
});

/* Close on Escape (dialog already handles this, but we need to stop the stream) */
modal.addEventListener("cancel", () => closeLogs());
