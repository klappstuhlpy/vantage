/* The live-update WebSocket client.
 *
 * Descended from the old static/js/live.js, which was the one genuinely good
 * piece of the previous frontend — the reconnect/backoff logic here is its
 * logic. What changed:
 *
 *  - One socket per page, not one per feature. The old design had each page
 *    construct its own LiveConnection; the shell needs `metrics` for its live
 *    badge while a page wants `docker`, and that meant two sockets racing to
 *    reconnect. This module is a singleton that multiplexes topics and
 *    refcounts them, so subscribing twice costs one connection.
 *  - Subscriptions are declared per-handler and survive reconnects: on
 *    re-open, the full topic set is re-sent.
 *
 * Protocol (see src/ws.rs — this must stay in step with it):
 *   client → {"action":"subscribe","topics":[...]} / {"action":"unsubscribe",...}
 *   server → {"topic":"metrics","data":{...}}
 *            {"topic":"_meta","data":{"hello":true}}          on connect
 *            {"topic":"_meta","data":{"subscribed":[...]}}    after subscribe
 *            {"topic":"_meta","data":{"lagged":N}}            broadcast overflow
 */

const RECONNECT_MIN = 1000;
const RECONNECT_MAX = 30_000;

/** @type {Map<string, Set<Function>>} topic → handlers */
const handlers = new Map();
const stateListeners = new Set();

let ws = null;
let state = 'offline'; // 'live' | 'connecting' | 'offline'
let backoff = RECONNECT_MIN;
let reconnectTimer = null;
let intentionallyClosed = false;

function setState(next) {
  if (state === next) return;
  state = next;
  for (const fn of stateListeners) {
    try {
      fn(state);
    } catch (e) {
      console.error('live state listener failed', e);
    }
  }
}

function send(action, topics) {
  if (ws?.readyState === WebSocket.OPEN && topics.length) {
    ws.send(JSON.stringify({ action, topics }));
  }
}

function connect() {
  if (ws || !handlers.size) return;

  clearTimeout(reconnectTimer);
  intentionallyClosed = false;
  setState('connecting');

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let socket;
  try {
    socket = new WebSocket(`${proto}//${location.host}/ws`);
  } catch (e) {
    scheduleReconnect();
    return;
  }
  ws = socket;

  socket.addEventListener('open', () => {
    backoff = RECONNECT_MIN;
    // Re-declare everything: the server holds subscriptions per connection, so
    // a reconnect starts from nothing.
    send('subscribe', [...handlers.keys()]);
  });

  socket.addEventListener('message', (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }

    if (msg.topic === '_meta') {
      // The server confirms the subscription set; that ack — not the socket
      // opening — is when we are actually receiving what we asked for, so it
      // is what the live badge reports.
      if (msg.data?.subscribed) setState('live');
      if (msg.data?.hello && !handlers.size) setState('live');
      if (msg.data?.lagged) {
        // The broadcast buffer overflowed and dropped events for this client.
        // Live views are snapshots-over-time, so a gap is survivable, but it
        // must not be silent — a page may want to refetch.
        console.warn(`live: dropped ${msg.data.lagged} event(s) — client fell behind`);
        for (const fn of handlers.get('_lagged') || []) fn(msg.data.lagged);
      }
      return;
    }

    for (const fn of handlers.get(msg.topic) || []) {
      try {
        fn(msg.data);
      } catch (e) {
        console.error(`live handler for "${msg.topic}" failed`, e);
      }
    }
  });

  socket.addEventListener('close', () => {
    ws = null;
    if (intentionallyClosed) {
      setState('offline');
      return;
    }
    scheduleReconnect();
  });

  socket.addEventListener('error', () => {
    // 'close' always follows; let it own the reconnect so we don't double-arm.
    socket.close();
  });
}

function scheduleReconnect() {
  ws = null;
  if (!handlers.size) {
    setState('offline');
    return;
  }
  setState('connecting');
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(connect, backoff);
  // Exponential up to a ceiling: a box that is down for an hour must not be
  // hammered, but an operator watching a restart wants a fast reconnect.
  backoff = Math.min(backoff * 2, RECONNECT_MAX);
}

/**
 * Subscribe to a live topic.
 *
 *   const off = subscribe('metrics', (data) => { ... });
 *
 * @param {string} topic
 * @param {(data: any) => void} handler
 * @returns {() => void} unsubscribe
 */
export function subscribe(topic, handler) {
  let set = handlers.get(topic);
  const isNew = !set;
  if (!set) {
    set = new Set();
    handlers.set(topic, set);
  }
  set.add(handler);

  if (isNew) send('subscribe', [topic]);
  connect();

  return () => {
    const s = handlers.get(topic);
    if (!s) return;
    s.delete(handler);
    if (s.size === 0) {
      handlers.delete(topic);
      send('unsubscribe', [topic]);
      // Nothing left to listen for — drop the socket rather than hold one open
      // for a page that no longer wants it.
      if (!handlers.size) close();
    }
  };
}

/** Subscribe to several topics with one handler; returns one unsubscribe. */
export function subscribeAll(topics, handler) {
  const offs = topics.map((t) => subscribe(t, (data) => handler(t, data)));
  return () => offs.forEach((off) => off());
}

/** Called when the server reports it dropped events for us. */
export function onLagged(handler) {
  return subscribe('_lagged', handler);
}

/** Connection state changes: 'live' | 'connecting' | 'offline'. */
export function onStateChange(fn) {
  stateListeners.add(fn);
  fn(state);
  return () => stateListeners.delete(fn);
}

export function getState() {
  return state;
}

export function close() {
  intentionallyClosed = true;
  clearTimeout(reconnectTimer);
  ws?.close();
  ws = null;
  setState('offline');
}

// A backgrounded tab gets its socket closed by some browsers and its timers
// throttled by all of them. Coming back to a stale dashboard that looks live is
// worse than one that admits it is reconnecting, so retry immediately on
// return rather than waiting out the backoff.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && !ws && handlers.size) {
    backoff = RECONNECT_MIN;
    clearTimeout(reconnectTimer);
    connect();
  }
});
