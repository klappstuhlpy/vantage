/* The HTTP layer. Every fetch in the app goes through here.
 *
 * Vantage's handlers are not uniform about failure — some answer
 * `{"error": "..."}`, many return a bare status code with no body at all. That
 * is a backend wart we are not fixing in a frontend rewrite, so this module
 * absorbs it: callers always get an ApiError with a message worth showing a
 * human, whichever shape came back.
 */

export class ApiError extends Error {
  constructor(message, { status = 0, body = null, url = '' } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.url = url;
  }

  /** 503 means a host integration is absent (no Docker socket, no firewall
   *  backend) rather than something being broken — pages render a degraded
   *  state for it instead of an error. */
  get isUnavailable() {
    return this.status === 503;
  }

  get isAuth() {
    return this.status === 401 || this.status === 403;
  }
}

// Messages for the handlers that answer with a status and nothing else.
const STATUS_TEXT = {
  400: "The server rejected that request as invalid.",
  401: 'Your session has expired. Sign in again to continue.',
  403: "You don't have permission to do that.",
  404: "That doesn't exist any more — it may have been removed.",
  409: 'That conflicts with the current state. Reload and try again.',
  413: 'That upload is too large.',
  429: 'Too many requests. Wait a moment and try again.',
  500: 'The server hit an unexpected error carrying that out.',
  502: 'A backend the server depends on is not responding.',
  503: 'That capability is not available on this host right now.',
  504: 'The server timed out carrying that out.',
};

async function parseBody(res) {
  const type = res.headers.get('content-type') || '';
  try {
    if (type.includes('application/json')) return await res.json();
    const text = await res.text();
    return text || null;
  } catch {
    return null;
  }
}

function messageFrom(body, status) {
  if (body && typeof body === 'object') {
    const m = body.error || body.message || body.detail;
    if (typeof m === 'string' && m.trim()) return m;
  }
  // A plain-text body is usually axum's own reason phrase — useful, but only
  // if it isn't an HTML error page.
  if (typeof body === 'string' && body.trim() && !body.trimStart().startsWith('<')) {
    return body.length > 300 ? `${body.slice(0, 300)}…` : body;
  }
  return STATUS_TEXT[status] || `Request failed (${status}).`;
}

/**
 * @param {string} url
 * @param {RequestInit & {json?: any, timeout?: number, reauthed?: boolean}} [opts]
 */
export async function request(url, opts = {}) {
  const { json, timeout = 30_000, headers, reauthed = false, ...rest } = opts;

  const init = {
    credentials: 'same-origin',
    headers: { Accept: 'application/json', ...headers },
    ...rest,
  };

  if (json !== undefined) {
    init.method = init.method || 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(json);
  }

  // AbortSignal.timeout would be tidier but a caller may pass its own signal
  // (the log stream does), and combining them is not worth a polyfill.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  if (init.signal) init.signal.addEventListener('abort', () => ctrl.abort(), { once: true });
  init.signal = ctrl.signal;

  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    clearTimeout(timer);
    if (e.name === 'AbortError') {
      throw new ApiError('The request timed out. The server may be busy or unreachable.', { url });
    }
    throw new ApiError('Could not reach the server. Check your connection to this host.', { url });
  }
  clearTimeout(timer);

  // An expired session redirects to /login; from fetch that surfaces as an
  // opaque HTML 200. Send the browser there rather than parse HTML as JSON.
  if (res.redirected && new URL(res.url).pathname.startsWith('/login')) {
    window.location.href = '/login';
    throw new ApiError('Your session has expired. Sign in again to continue.', { status: 401, url });
  }

  const body = await parseBody(res);

  if (!res.ok) {
    if (res.status === 401) window.location.href = '/login';

    // Sudo mode. A destructive route answers 403 + `reauth_required` when this
    // session's re-authentication has gone stale (see core/reauth.js). Handling
    // it here rather than at each call site is the point: every destructive
    // action in the app gets the prompt-and-retry for free, and none of them can
    // forget to. `reauthed` stops a server that keeps saying no from looping.
    if (res.status === 403 && body?.reauth_required && !reauthed) {
      const { requestReauth } = await import('./reauth.js');
      if (await requestReauth(body.error)) {
        return request(url, { ...opts, reauthed: true });
      }
    }

    throw new ApiError(messageFrom(body, res.status), { status: res.status, body, url });
  }

  return body;
}

export const get = (url, opts) => request(url, { ...opts, method: 'GET' });
export const post = (url, json, opts) => request(url, { ...opts, method: 'POST', json });
export const patch = (url, json, opts) => request(url, { ...opts, method: 'PATCH', json });
export const put = (url, json, opts) => request(url, { ...opts, method: 'PUT', json });
export const del = (url, opts) => request(url, { ...opts, method: 'DELETE' });

/** POST a FormData body (uploads) — no JSON content-type, longer default timeout. */
export function postForm(url, formData, opts = {}) {
  return request(url, { method: 'POST', body: formData, timeout: 120_000, ...opts });
}

/**
 * POST/PATCH an application/x-www-form-urlencoded body.
 *
 * Not every handler takes JSON: several (health's monitor upsert, firewall's
 * rule create) are axum `Form(...)` extractors, which reject a JSON body with
 * a bare 415. Encoding lives here so pages don't each rebuild URLSearchParams.
 *
 * `null`/`undefined` values are dropped rather than sent as the strings
 * "null"/"undefined" — serde would happily parse those into a field.
 *
 * Booleans go out as "true"/"false", not the "on"/"off" a browser sends for a
 * checkbox. Both work for the handlers that parse the field as a String and
 * match on it (`matches!(s, "on" | "true" | "1")` — firewall, health, proxy),
 * but "on" fails outright on a handler that takes a real `bool`, because serde
 * only accepts true/false/1/0 and answers anything else with a 422. Vantage has
 * exactly one such field today — dbadmin's `danger_mode` — and "true" is the
 * form that satisfies every one of them.
 */
export function postUrlEncoded(url, obj, opts = {}) {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined || v === null) continue;
    body.set(k, String(v));
  }
  return request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    ...opts,
  });
}

/** Build "/x?a=1" while dropping empty params, so callers stop hand-rolling it. */
export function withQuery(url, params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '') continue;
    q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `${url}?${s}` : url;
}
