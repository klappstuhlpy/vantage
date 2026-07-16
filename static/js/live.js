/* ── Shared WebSocket client ────────────────────────────────────
   Auto-reconnects with exponential backoff. Each dashboard page
   creates one LiveConnection, subscribes to its topics, and provides
   an onEvent handler. Falls back gracefully — when the socket is
   closed/lagging, polling logic on the same page keeps running.

   Usage:
     const conn = new LiveConnection({
       topics: ["metrics", "audit"],
       onEvent: (topic, data) => { … },
       onStateChange: (state) => { … },   // "connecting" | "live" | "closed"
     });
     conn.start();
   ────────────────────────────────────────────────────────────── */

class LiveConnection {
  constructor({ topics, onEvent, onStateChange }) {
    this.topics = topics || [];
    this.onEvent = onEvent || (() => {});
    this.onStateChange = onStateChange || (() => {});
    this.ws = null;
    this.retryDelayMs = 1000;
    this.maxDelayMs = 30_000;
    this.stopped = false;
  }

  start() {
    if (this.stopped) return;
    this.connect();
  }

  stop() {
    this.stopped = true;
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
      this.ws = null;
    }
    this.onStateChange("closed");
  }

  connect() {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const url = `${scheme}://${location.host}/ws`;
    this.onStateChange("connecting");

    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      console.error("ws constructor failed:", e);
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.retryDelayMs = 1000;  // reset backoff
      ws.send(JSON.stringify({ action: "subscribe", topics: this.topics }));
      // We treat the connection as live only after the server has
      // echoed back the subscribed topics list (or any other meta).
    };

    ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch (_) { return; }
      if (msg.topic === "_meta") {
        if (msg.data && msg.data.subscribed) {
          this.onStateChange("live");
        } else if (msg.data && msg.data.lagged) {
          console.warn("ws lagged, dropped", msg.data.lagged, "messages");
        }
        return;
      }
      this.onEvent(msg.topic, msg.data);
    };

    ws.onerror = () => {
      // onclose runs right after.
    };

    ws.onclose = () => {
      this.ws = null;
      this.onStateChange("closed");
      if (!this.stopped) this.scheduleReconnect();
    };
  }

  scheduleReconnect() {
    const delay = this.retryDelayMs;
    this.retryDelayMs = Math.min(this.retryDelayMs * 2, this.maxDelayMs);
    setTimeout(() => this.connect(), delay);
  }
}

// Make it globally available without ES modules.
window.LiveConnection = LiveConnection;
