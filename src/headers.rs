//! Security response headers — the CSP the frontend rewrite was built for
//! (FRONTEND_MIGRATION_PLAN §13).
//!
//! The rewrite kept a hard discipline — zero inline `<script>`, zero inline
//! event handlers, no `eval`, no `new Function`, no CDN, every font, icon and
//! chart library vendored under `static/` — explicitly so that a strict policy
//! could be switched on without a nonce pipeline or a single `'unsafe-inline'`.
//! That discipline shipped; this header did not, which left the expensive half
//! of the work done and the cheap half undone for the whole of the rewrite.
//!
//! ## Why the policy can be this strict
//!
//! * **`script-src 'self'`** — every script is a module file under `/static`.
//!   Even the anti-FOUC theme bootstrap, which is the one snippet almost every
//!   app inlines, is a real file (`core/theme-init.js`).
//! * **`style-src 'self' 'unsafe-inline'`** — our own markup still carries no
//!   `<style>` block and no `style=` attribute, and styling done *from
//!   JavaScript* goes through the CSSOM (`el.style.setProperty`, see `ui.js`'s
//!   `applyStyle`), which CSP does not govern. The escape hatch is for the two
//!   vendored libraries that ship their CSS *inside* the JS and inject it as a
//!   `<style>` element at runtime: CodeMirror 6 (via `style-mod`, the database
//!   console's SQL editor) and Cytoscape (the container/schema graphs). Under a
//!   strict `style-src` both render unstyled — a blank editor and an unusable
//!   graph. Their sheets are generated per instance, so there is no stable hash
//!   to pin, and a nonce cannot reach a `<style>` element the library creates
//!   itself. `script-src` stays strict, which is the half of the policy that
//!   stops code execution; inline *style* buys an attacker who can already
//!   inject markup very little here, with no remote `img-src`/`font-src` sink
//!   to exfiltrate to.
//! * **`object-src 'none'`, `base-uri 'none'`** — nothing embeds plugins, and
//!   nothing sets a `<base>`; both are pure attack surface here.
//! * **`frame-ancestors 'none'`** — a control plane for a host has no business
//!   inside someone else's frame. `X-Frame-Options: DENY` says the same thing
//!   for anything that predates `frame-ancestors`.
//!
//! ## The WebSocket, and why `connect-src 'self'` covers it
//!
//! The live hub connects to `ws(s)://<same host>/ws`. CSP Level 3 resolves
//! `'self'` for a `ws:` request from an `http:` page (and `wss:` from `https:`)
//! as a match — the scheme is upgraded rather than compared literally, which is
//! exactly the case here since `live.js` derives the scheme from
//! `location.protocol`. This is the one clause worth remembering if live
//! updates ever go quiet right after a policy change.
//!
//! ## Report-only, deliberately available
//!
//! `Config::csp_report_only` swaps the enforcing header for
//! `Content-Security-Policy-Report-Only`. Turning a policy on for the first
//! time against a real browser is the moment you discover the one asset nobody
//! remembered; report-only lets that discovery happen in the console instead of
//! as a blank page on a machine that may be the only way in to the box.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// The policy, as one line per directive so a change is one line of diff.
///
/// Kept as a const rather than built per request: it never varies by request,
/// and a header that could vary is a header someone will eventually make vary
/// by something attacker-controlled.
const POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self'; \
     font-src 'self'; \
     connect-src 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'; \
     base-uri 'none'; \
     object-src 'none'";

/// Attaches the security headers to every response.
///
/// Applied on the outermost layer, so it covers static assets, error responses
/// and the ones produced by middleware that refuses a request (safe mode's 423,
/// the public guard's 403) — the responses least likely to be reviewed and so
/// the ones most likely to be missed by a per-handler approach.
pub async fn security_headers(report_only: bool, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    let csp = if report_only {
        "content-security-policy-report-only"
    } else {
        "content-security-policy"
    };
    headers.insert(csp, HeaderValue::from_static(POLICY));

    // Belt-and-braces beside `frame-ancestors`, for anything that does not
    // implement it.
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // Stops a browser second-guessing a declared Content-Type — the sniffing
    // that turns an uploaded text file into an executed script.
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    // A Vantage URL can name a container, a route, or a database source. None
    // of that should ride along to whatever an operator clicks through to.
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    // Nothing in this app uses a camera, a microphone, or a location, so the
    // honest declaration is that none of it may.
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );

    response
}

/// Paths whose JSON responses tolerate a short browser-cache lifetime.
/// The browser serves from cache for `max-age` seconds (eliminating the round
/// trip entirely on rapid tab-switches and back-button navigations), then
/// revalidates in the background for `stale-while-revalidate` more seconds.
///
/// `private` ensures shared proxies never cache admin data.
const SWR_PATHS: &[&str] = &[
    "/metrics/current",
    "/metrics/history",
    "/docker/services/data",
    "/docker/graph",
    "/docker/actions/log",
    "/monitors/data",
    "/firewall/data",
    "/secrets/data",
    "/security/data",
    "/security/cloudflare",
    "/api/updates",
];

const SWR_HEADER: &str = "private, max-age=5, stale-while-revalidate=30";

/// Static assets — `/static/*`, served by `ServeDir`.
///
/// These carried *no* `Cache-Control` at all, so a hard refresh re-downloaded
/// the whole 1.5 MB tree (`codemirror.bundle.js` is 430 KB, `cytoscape.min.js`
/// 372 KB), which is what made the first load of the pages that use them feel
/// broken.
///
/// The URLs are unversioned — there is no content hash in the filename — so this
/// is deliberately *not* `immutable`. A short `max-age` with a long
/// `stale-while-revalidate` means a repeat visit paints instantly from cache and
/// revalidates in the background, and a deploy is picked up on the next
/// revalidation rather than being pinned until the user clears their cache.
///
/// `public` is safe here and only here: these are the design system's own assets,
/// identical for every visitor and served before any session exists. Everything
/// else stays `private` — see [`SWR_HEADER`].
const STATIC_HEADER: &str = "public, max-age=300, stale-while-revalidate=86400";

/// Sets `Cache-Control` on successful GET responses: a short private window for
/// the data endpoints the frontend polls, a longer public one for static assets.
/// Applied after the inner handler so it only touches 2xx — error and redirect
/// responses stay uncached.
pub async fn cache_control(request: Request, next: Next) -> Response {
    let is_get = request.method() == axum::http::Method::GET;
    let path = request.uri().path();
    let header = if !is_get {
        None
    } else if path.starts_with("/static/") {
        Some(STATIC_HEADER)
    } else if SWR_PATHS.iter().any(|p| path.starts_with(p)) {
        Some(SWR_HEADER)
    } else {
        None
    };

    let mut response = next.run(request).await;

    if let Some(header) = header {
        if response.status().is_success() {
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static(header));
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `script-src` must not contain the escapes that would make it decorative.
    /// This is the test that fails when someone reaches for `'unsafe-inline'` to
    /// make one stubborn snippet work — at which point the snippet should move
    /// to a file instead, which is what the whole frontend already does.
    /// `style-src` is exempt by design (see the module docs: CodeMirror and
    /// Cytoscape inject their own `<style>` elements).
    #[test]
    fn the_policy_permits_no_inline_or_eval_escape_hatch() {
        let script_src = POLICY
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src"))
            .expect("policy must name script-src");
        assert!(
            !script_src.contains("unsafe-inline"),
            "script-src must not allow inline"
        );
        assert!(!POLICY.contains("unsafe-eval"), "policy must not allow eval");
        assert!(!POLICY.contains('*'), "policy must not wildcard a source");
    }

    /// The two cache policies must not trade places. `public` on an admin JSON
    /// endpoint would hand a shared proxy the operator's data, and the long
    /// `stale-while-revalidate` that makes static assets cheap would pin stale
    /// metrics on the dashboard. This asserts the split rather than the strings:
    /// static is public and long-lived, data is private and short-lived, and a
    /// path that is neither gets no header at all.
    #[test]
    fn static_assets_cache_publicly_and_data_endpoints_never_do() {
        assert!(STATIC_HEADER.starts_with("public"), "static assets are shareable");
        assert!(
            SWR_PATHS.iter().all(|p| !p.starts_with("/static")),
            "a data path must not be routed to the static policy"
        );
        assert!(
            SWR_HEADER.starts_with("private"),
            "admin data must never enter a shared cache"
        );
        // The static window is the long one — that is the whole point of it.
        assert!(STATIC_HEADER.contains("max-age=300") && SWR_HEADER.contains("max-age=5"));
    }

    /// Every fetch directive the app actually uses is named. A missing one falls
    /// back to `default-src`, which is correct here but silent — naming them
    /// means a future `default-src` relaxation cannot widen them by accident.
    #[test]
    fn the_policy_names_every_directive_the_app_relies_on() {
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ] {
            assert!(POLICY.contains(directive), "policy is missing `{directive}`");
        }
    }
}
