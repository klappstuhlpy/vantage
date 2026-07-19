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
//! * **`style-src 'self'`** — no `<style>` blocks and no `style=` attributes in
//!   markup. Styling done *from JavaScript* goes through the CSSOM
//!   (`el.style.setProperty`, see `ui.js`'s `applyStyle`), which CSP does not
//!   govern, so the dynamic column widths and accent swatches keep working.
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
     style-src 'self'; \
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy must not contain the two escapes that would make it
    /// decorative. This is the test that fails when someone reaches for
    /// `'unsafe-inline'` to make one stubborn snippet work — at which point the
    /// snippet should move to a file instead, which is what the whole frontend
    /// already does.
    #[test]
    fn the_policy_permits_no_inline_or_eval_escape_hatch() {
        assert!(!POLICY.contains("unsafe-inline"), "policy must not allow inline");
        assert!(!POLICY.contains("unsafe-eval"), "policy must not allow eval");
        assert!(!POLICY.contains('*'), "policy must not wildcard a source");
    }

    /// Every fetch directive the app actually uses is named. A missing one falls
    /// back to `default-src`, which is correct here but silent — naming them
    /// means a future `default-src` relaxation cannot widen them by accident.
    #[test]
    fn the_policy_names_every_directive_the_app_relies_on() {
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ] {
            assert!(POLICY.contains(directive), "policy is missing `{directive}`");
        }
    }
}
