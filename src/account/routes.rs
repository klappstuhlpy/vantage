//! Account & security routes.
//!
//! GET    /account                     — the account page
//! GET    /account/sessions            — JSON session list (current flagged)
//! DELETE /account/sessions/:id        — revoke one session
//! POST   /account/sessions/revoke-all — revoke every session but this one
//! POST   /account/password            — change password (sudo)
//!
//! GET    /account/reauth              — what re-authentication needs (methods)
//! POST   /account/reauth              — re-authenticate; stamps the sudo window
//!
//! POST   /account/totp/start          — begin enrollment (sudo) → secret + QR
//! POST   /account/totp/enable         — verify a code and turn it on
//! POST   /account/totp/disable        — turn it off (sudo)
//! POST   /account/recovery            — mint a fresh batch of codes (sudo)
//!
//! Everything that changes a credential sits behind [`Sudo`], not just a live
//! session — see the module docs on why 12 hours of "signed in" is not consent.

use askama::Template;
use axum::{
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{header::USER_AGENT, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use time::OffsetDateTime;

use crate::{
    account, audit,
    session::{self, Account, AuthRedirect},
    totp, AppState,
};

/// How long an enrollment may sit half-finished before the secret expires.
const ENROLLMENT_TTL_SECONDS: i64 = 600;

// ─── Extractors ──────────────────────────────────────────────────────────────

/// A session that has re-authenticated inside [`account::SUDO_WINDOW_MINUTES`].
///
/// The rejection is not a generic 403: it is a machine-readable "prove it again"
/// that the frontend turns into the reauth modal and a transparent retry (see
/// `static/js/core/reauth.js`). That contract — `reauth_required: true` — is the
/// reason this is one extractor rather than a check copy-pasted into handlers.
pub struct Sudo {
    pub account: Account,
    pub session_id: String,
}

/// The rejection for [`Sudo`]: either "you are not signed in" (bounce to login)
/// or "you are, but not recently enough" (403 + the reauth marker).
pub enum SudoRejection {
    NoSession(AuthRedirect),
    ReauthRequired,
}

impl IntoResponse for SudoRejection {
    fn into_response(self) -> Response {
        match self {
            SudoRejection::NoSession(redirect) => redirect.into_response(),
            SudoRejection::ReauthRequired => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Confirm it's you to continue.",
                    "reauth_required": true,
                })),
            )
                .into_response(),
        }
    }
}

#[async_trait::async_trait]
impl FromRequestParts<AppState> for Sudo {
    type Rejection = SudoRejection;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let account = Account::from_request_parts(parts, state)
            .await
            .map_err(SudoRejection::NoSession)?;
        let session_id = current_session_id(parts, state).ok_or(SudoRejection::ReauthRequired)?;
        if !account::has_sudo(&state.db, &session_id).await {
            return Err(SudoRejection::ReauthRequired);
        }
        Ok(Sudo { account, session_id })
    }
}

/// The id of the session this request came in on.
fn current_session_id(parts: &Parts, state: &AppState) -> Option<String> {
    let cookies = parts.extensions.get::<Vec<Cookie>>()?;
    session::session_id_from(cookies, state.config.session_cookie_name())
}

// ─── Router ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/account", get(account_page))
        .route("/account/sessions", get(list_sessions))
        .route("/account/sessions/:id", delete(revoke_session))
        .route("/account/sessions/revoke-all", post(revoke_all_sessions))
        .route("/account/password", post(change_password))
        .route("/account/reauth", get(reauth_methods).post(reauth))
        .route("/account/totp/start", post(totp_start))
        .route("/account/totp/enable", post(totp_enable))
        .route("/account/totp/disable", post(totp_disable))
        .route("/account/recovery", post(regenerate_recovery_codes))
        .route("/account/prefs", get(get_prefs).put(put_prefs))
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "account.html")]
struct AccountTemplate {
    account: Option<Account>,
    active_page: &'static str,
    totp_enabled: bool,
    recovery_remaining: i64,
    recovery_total: usize,
    min_password_len: usize,
    sudo_window_minutes: i64,
    /// Whether passkey management can be offered at all. Always false today —
    /// `webauthn-rs` has not reached `kls-web-core`. The section renders a stated
    /// placeholder rather than a disabled control that implies it nearly works.
    passkeys_available: bool,
}

async fn account_page(State(state): State<AppState>, account: Account) -> AccountTemplate {
    let status = account::totp_status(&state.db, &account).await;
    AccountTemplate {
        account: Some(account),
        active_page: "account",
        totp_enabled: status.enabled,
        recovery_remaining: status.recovery_remaining,
        recovery_total: status.recovery_total,
        min_password_len: account::MIN_PASSWORD_LEN,
        sudo_window_minutes: account::SUDO_WINDOW_MINUTES,
        passkeys_available: false,
    }
}

// ─── Error helper ────────────────────────────────────────────────────────────

/// The error shape every handler here answers with — `{"error": "…"}`, which is
/// what `core/api.js` reads to build the message a human sees.
fn fail(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

fn server_error(err: anyhow::Error, context: &'static str) -> Response {
    tracing::error!(error = ?err, "{context}");
    fail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "The server could not carry that out.",
    )
}

// ─── Sessions ────────────────────────────────────────────────────────────────

async fn list_sessions(
    State(state): State<AppState>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
) -> Response {
    let current = session::session_id_from(&cookies, state.config.session_cookie_name()).unwrap_or_default();
    match account::list_sessions(&state.db, account.id, &current).await {
        Ok(sessions) => Json(serde_json::json!({ "sessions": sessions })).into_response(),
        Err(e) => server_error(e, "listing sessions failed"),
    }
}

async fn revoke_session(State(state): State<AppState>, account: Account, Path(id): Path<String>) -> Response {
    match account::revoke_session(&state.db, account.id, &id).await {
        Ok(true) => {
            // Cutting off a session is how you end someone else's access — and
            // how someone ends yours. It belongs in the audit log even though it
            // is the mildest thing on this page.
            audit::event("account.session.revoke", &account)
                .target(crate::account::session_label(&id))
                .record(&state.db)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => fail(StatusCode::NOT_FOUND, "That session has already ended."),
        Err(e) => server_error(e, "revoking a session failed"),
    }
}

#[derive(Serialize)]
struct RevokedResponse {
    revoked: usize,
}

async fn revoke_all_sessions(
    State(state): State<AppState>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
) -> Response {
    let current = session::session_id_from(&cookies, state.config.session_cookie_name()).unwrap_or_default();
    match account::revoke_other_sessions(&state.db, account.id, &current).await {
        Ok(revoked) => {
            audit::event("account.session.revoke_all", &account)
                .detail(serde_json::json!({ "revoked": revoked }))
                .record(&state.db)
                .await;
            Json(RevokedResponse { revoked }).into_response()
        }
        Err(e) => server_error(e, "revoking other sessions failed"),
    }
}

// ─── Password ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PasswordBody {
    new_password: String,
}

/// Changes the password.
///
/// The *current* password is not asked for here, and that is not an oversight:
/// [`Sudo`] means this session proved the password (or a passkey, later) within
/// the last few minutes. Asking again in the form would be asking the same
/// question twice and would quietly diverge from every other sudo-gated action.
async fn change_password(State(state): State<AppState>, sudo: Sudo, Json(body): Json<PasswordBody>) -> Response {
    if let Err(message) = account::validate_password(&body.new_password) {
        return fail(StatusCode::BAD_REQUEST, message);
    }

    let Ok(hash) = crate::hash_password(&body.new_password) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "The server could not hash that.");
    };
    if let Err(e) = account::set_password(&state.db, sudo.account.id, hash).await {
        return server_error(e, "changing the password failed");
    }

    // Everything the old password authorised ends with it. If the password was
    // changed because it leaked, leaving the other sessions — or this session's
    // own sudo grant — alive would defeat the exercise.
    let revoked = account::revoke_other_sessions(&state.db, sudo.account.id, &sudo.session_id)
        .await
        .unwrap_or(0);
    account::clear_sudo(&state.db, sudo.account.id).await;
    audit::event("account.password.change", &sudo.account)
        .detail(serde_json::json!({ "other_sessions_revoked": revoked }))
        .record(&state.db)
        .await;

    Json(serde_json::json!({ "revoked": revoked })).into_response()
}

// ─── Re-authentication (sudo) ────────────────────────────────────────────────

#[derive(Serialize)]
struct ReauthMethods {
    /// Whether a TOTP code is required alongside the password.
    totp: bool,
    /// Whether this session already holds a live sudo stamp — lets the page skip
    /// the modal rather than ask for a password it does not need.
    active: bool,
    window_minutes: i64,
}

async fn reauth_methods(
    State(state): State<AppState>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
) -> Json<ReauthMethods> {
    let active = match session::session_id_from(&cookies, state.config.session_cookie_name()) {
        Some(id) => account::has_sudo(&state.db, &id).await,
        None => false,
    };
    Json(ReauthMethods {
        totp: account.has_totp(),
        active,
        window_minutes: account::SUDO_WINDOW_MINUTES,
    })
}

#[derive(Deserialize)]
struct ReauthBody {
    password: String,
    #[serde(default)]
    code: Option<String>,
}

/// Re-authenticates the current session and stamps its sudo window.
///
/// Rate-limited by the same per-IP lockout as `/login`, and for the same reason:
/// this endpoint takes a password and says whether it was right. Leaving it
/// ungated would make it a bypass around the front door's lockout.
async fn reauth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
    Json(body): Json<ReauthBody>,
) -> Response {
    let ip = peer.ip();
    if crate::lockout::is_locked(ip) {
        return fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts — try again later.",
        );
    }

    let Some(session_id) = session::session_id_from(&cookies, state.config.session_cookie_name()) else {
        return fail(StatusCode::UNAUTHORIZED, "Your session has expired.");
    };

    if !crate::verify_password(&body.password, &account.password) {
        crate::lockout::register_failure(ip);
        return fail(StatusCode::UNAUTHORIZED, "That password is not right.");
    }

    if account.has_totp() {
        let code = body.code.unwrap_or_default();
        let ok = account
            .totp_secret
            .as_deref()
            .and_then(|enc| totp::decrypt_secret(&state.config.secret_key, enc))
            .map(|secret| totp::verify(&secret, &code))
            .unwrap_or(false);
        // A recovery code works here too: the case this exists for is "my
        // authenticator is gone", and the account page — where you go to fix
        // that — is itself behind sudo. Without this you could not get in to
        // re-enroll without being locked out of your own account settings.
        if !ok && !account::redeem_recovery_code(&state.db, account.id, &code).await {
            crate::lockout::register_failure(ip);
            return fail(StatusCode::UNAUTHORIZED, "That code is not right.");
        }
    }

    if let Err(e) = account::stamp_sudo(&state.db, &session_id).await {
        return server_error(e, "stamping the sudo window failed");
    }
    crate::lockout::clear(ip);
    audit::event("account.reauth", &account).record(&state.db).await;

    Json(serde_json::json!({ "ok": true, "window_minutes": account::SUDO_WINDOW_MINUTES })).into_response()
}

// ─── TOTP enrollment ─────────────────────────────────────────────────────────

/// The half-finished enrollment, handed to the client and back.
///
/// Signed with the app key and carried by the client rather than parked in a
/// column, so a started-then-abandoned enrollment leaves nothing behind — no
/// half-enrolled account state to reconcile, and no window where the DB holds a
/// secret the operator never confirmed.
#[derive(Serialize, Deserialize)]
struct PendingEnrollment {
    account_id: i64,
    /// Already ChaCha20-Poly1305-encrypted, so the pending blob is not a
    /// plaintext secret in transit even though it is signed.
    secret: String,
    exp: i64,
}

#[derive(Serialize)]
struct EnrollmentStart {
    /// The signed blob to hand back to `/account/totp/enable`.
    token: String,
    /// Base32, for someone typing it into an app that cannot scan.
    secret: String,
    uri: String,
    qr: account::QrMatrix,
}

async fn totp_start(State(state): State<AppState>, sudo: Sudo) -> Response {
    if sudo.account.has_totp() {
        return fail(
            StatusCode::CONFLICT,
            "Two-factor authentication is already on. Turn it off first to enroll a new device.",
        );
    }

    let Ok(secret) = account::generate_totp_secret() else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The server could not generate a secret.",
        );
    };
    let Ok(encrypted) = totp::encrypt_secret(&state.config.secret_key, &secret) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The server could not store that secret.",
        );
    };

    let label = enrollment_label(&state, &sudo.account);
    let uri = account::provisioning_uri("Vantage", &label, &secret);
    let qr = match account::qr_matrix(&uri) {
        Ok(qr) => qr,
        Err(e) => return server_error(e, "encoding the enrollment QR failed"),
    };

    let pending = PendingEnrollment {
        account_id: sudo.account.id,
        secret: encrypted,
        exp: OffsetDateTime::now_utc().unix_timestamp() + ENROLLMENT_TTL_SECONDS,
    };
    let Ok(token) = state.config.secret_key.sign(&pending) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The server could not start enrollment.",
        );
    };

    Json(EnrollmentStart {
        token,
        secret: account::base32_encode(&secret),
        uri,
        qr,
    })
    .into_response()
}

/// What the authenticator app files this entry under.
///
/// `name@host` rather than a bare username: an operator running Vantage on more
/// than one box otherwise ends up with two identical "Vantage: root" entries and
/// no way to tell which machine either one opens.
fn enrollment_label(state: &AppState, account: &Account) -> String {
    match host_of(&state.config.base_url) {
        Some(host) => format!("{}@{}", account.name, host),
        None => account.name.clone(),
    }
}

/// The host part of a base URL — `https://box.example.com/x` → `box.example.com`.
fn host_of(base_url: &str) -> Option<&str> {
    let rest = base_url.split_once("://").map(|(_, rest)| rest).unwrap_or(base_url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    (!host.is_empty()).then_some(host)
}

#[derive(Deserialize)]
struct EnableBody {
    token: String,
    code: String,
}

#[derive(Serialize)]
struct EnableResponse {
    recovery_codes: Vec<String>,
}

/// Verifies a code against the pending secret and turns the factor on.
///
/// Verify-to-enable, never enable-on-generate: an operator whose authenticator
/// silently failed to save the entry would otherwise be locked out at their next
/// login, on a box whose whole point is that it is hard to get into.
async fn totp_enable(State(state): State<AppState>, sudo: Sudo, Json(body): Json<EnableBody>) -> Response {
    let Some(pending) = state.config.secret_key.verify::<PendingEnrollment>(&body.token) else {
        return fail(StatusCode::BAD_REQUEST, "That enrollment is not valid. Start again.");
    };
    if pending.account_id != sudo.account.id || OffsetDateTime::now_utc().unix_timestamp() > pending.exp {
        return fail(StatusCode::BAD_REQUEST, "That enrollment has expired. Start again.");
    }

    let Some(secret) = totp::decrypt_secret(&state.config.secret_key, &pending.secret) else {
        return fail(StatusCode::BAD_REQUEST, "That enrollment is not valid. Start again.");
    };
    if !totp::verify(&secret, &body.code) {
        return fail(
            StatusCode::UNAUTHORIZED,
            "That code doesn't match. Check your device's clock, then try the next code.",
        );
    }

    if let Err(e) = account::enable_totp(&state.db, sudo.account.id, pending.secret).await {
        return server_error(e, "enabling TOTP failed");
    }

    let codes = match account::generate_recovery_codes() {
        Ok(codes) => codes,
        Err(e) => return server_error(e, "generating recovery codes failed"),
    };
    if let Err(e) = account::store_recovery_codes(&state.db, sudo.account.id, &codes).await {
        return server_error(e, "storing recovery codes failed");
    }
    audit::event("account.totp.enable", &sudo.account)
        .record(&state.db)
        .await;

    Json(EnableResponse { recovery_codes: codes }).into_response()
}

async fn totp_disable(State(state): State<AppState>, sudo: Sudo) -> Response {
    if !sudo.account.has_totp() {
        return fail(StatusCode::CONFLICT, "Two-factor authentication is already off.");
    }
    if let Err(e) = account::disable_totp(&state.db, sudo.account.id).await {
        return server_error(e, "disabling TOTP failed");
    }
    audit::event("account.totp.disable", &sudo.account)
        .record(&state.db)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn regenerate_recovery_codes(State(state): State<AppState>, sudo: Sudo) -> Response {
    if !sudo.account.has_totp() {
        return fail(
            StatusCode::CONFLICT,
            "Recovery codes exist to get you past the second factor. Turn it on first.",
        );
    }
    let codes = match account::generate_recovery_codes() {
        Ok(codes) => codes,
        Err(e) => return server_error(e, "generating recovery codes failed"),
    };
    if let Err(e) = account::store_recovery_codes(&state.db, sudo.account.id, &codes).await {
        return server_error(e, "storing recovery codes failed");
    }
    audit::event("account.recovery.regenerate", &sudo.account)
        .record(&state.db)
        .await;
    Json(EnableResponse { recovery_codes: codes }).into_response()
}

// ─── Login-path provenance ───────────────────────────────────────────────────

/// Pulls the User-Agent out of a request's headers, bounded.
///
/// Bounded because this string is attacker-controlled, goes into the database,
/// and is rendered in the session list. 300 characters is past every real
/// browser's UA and nowhere near a useful place to hide a payload.
pub fn user_agent_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(USER_AGENT)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.chars().take(300).collect())
}

// ─── Preferences ────────────────────────────────────────────────────────────

const PREFS_MAX_BYTES: usize = 8192;

async fn get_prefs(account: Account, State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let id = account.id;
    let row: Option<String> = state
        .db
        .call(move |conn| {
            conn.query_row("SELECT prefs FROM user_prefs WHERE account_id = ?1", [id], |r| r.get(0))
                .ok()
        })
        .await;
    let value = match row {
        Some(json) => serde_json::from_str(&json).unwrap_or(serde_json::json!({})),
        None => serde_json::json!({}),
    };
    Ok(Json(value))
}

async fn put_prefs(
    account: Account,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    if body.len() > PREFS_MAX_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "preferences payload too large"));
    }
    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid JSON"))?;
    if !json.is_object() {
        return Err((StatusCode::BAD_REQUEST, "preferences must be a JSON object"));
    }
    let text = json.to_string();
    let id = account.id;
    state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO user_prefs (account_id, prefs, updated_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                 ON CONFLICT(account_id) DO UPDATE SET prefs = excluded.prefs, updated_at = excluded.updated_at",
                rusqlite::params![id, text],
            )
        })
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "could not save preferences"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_handles_the_base_urls_a_config_can_hold() {
        assert_eq!(host_of("https://box.example.com"), Some("box.example.com"));
        assert_eq!(host_of("http://127.0.0.1:8087"), Some("127.0.0.1:8087"));
        assert_eq!(host_of("https://box.example.com/vantage/"), Some("box.example.com"));
        assert_eq!(host_of("box.example.com"), Some("box.example.com"));
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://"), None);
    }

    #[test]
    fn user_agent_is_bounded_and_optional() {
        let mut headers = HeaderMap::new();
        assert_eq!(user_agent_of(&headers), None);

        headers.insert(USER_AGENT, "Mozilla/5.0".parse().unwrap());
        assert_eq!(user_agent_of(&headers).as_deref(), Some("Mozilla/5.0"));

        headers.insert(USER_AGENT, "x".repeat(1000).parse().unwrap());
        assert_eq!(user_agent_of(&headers).unwrap().len(), 300);

        headers.insert(USER_AGENT, "   ".parse().unwrap());
        assert_eq!(user_agent_of(&headers), None);
    }
}
