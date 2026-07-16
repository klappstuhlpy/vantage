//! Session authentication: Vantage's own identities, layered on the shared
//! [`Token`] wire format.
//!
//! Vantage has no Discord link and no SSO with the site (ADMIN_SEPARATION_PLAN
//! §4, §7.3): its cookie has a different name, is `__Host-`-prefixed and
//! `SameSite=Strict`, and is never domain-scoped — a cookie theft on the site
//! domain yields nothing here. The tamper-proof [`Token`] format (HMAC signing)
//! is reused from `kls-web-core`; turning a token into an [`Account`] against
//! this app's own `session`/`account` tables is what lives here.
//!
//! Sessions are deliberately short-lived (12 h) — the admin app is a remote-root
//! surface, so there is no "remember me". A finer idle-timeout and the full
//! session-management UI (list/revoke) are a Step B2 refinement.

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use cookie::{Cookie, SameSite};
use kls_web_core::{token::Token, Database};

use crate::AppState;

/// How long an admin session stays valid. Short by design (§7.3).
pub const SESSION_MAX_AGE_HOURS: i64 = 12;

/// A host-admin account — Vantage's own identity (no Discord, no site link).
#[derive(Debug, Clone)]
pub struct Account {
    pub id: i64,
    pub name: String,
    pub password: String,
    pub flags: i64,
    pub totp_enabled: bool,
    /// The encrypted (ChaCha20-Poly1305) TOTP shared secret, when enrolled.
    /// Decrypted only at the 2FA verification step (see `crate::totp`).
    pub totp_secret: Option<String>,
}

impl Account {
    /// Whether the admin flag (bit 0) is set. Every Vantage account is a host
    /// admin today; the flag is kept for wire-compatibility with the site.
    pub fn is_admin(&self) -> bool {
        self.flags & crate::FLAG_ADMIN != 0
    }

    /// Whether the account has a verified second factor.
    pub fn has_totp(&self) -> bool {
        self.totp_enabled
    }
}

fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: row.get(0)?,
        name: row.get(1)?,
        password: row.get(2)?,
        flags: row.get(3)?,
        totp_enabled: row.get::<_, i64>(4)? != 0,
        totp_secret: row.get(5)?,
    })
}

/// Looks up an account by (unique) name. `None` when absent.
pub async fn account_by_name(db: &Database, name: &str) -> Option<Account> {
    db.get_row(
        "SELECT id, name, password, flags, totp_enabled, totp_secret FROM account WHERE name = ?",
        (name.to_string(),),
        row_to_account,
    )
    .await
    .ok()
}

/// Looks up an account by id (used to resume a pending 2FA challenge). `None` when absent.
pub async fn account_by_id(db: &Database, id: i64) -> Option<Account> {
    db.get_row(
        "SELECT id, name, password, flags, totp_enabled, totp_secret FROM account WHERE id = ?",
        (id,),
        row_to_account,
    )
    .await
    .ok()
}

/// Validates a browser session: the row must exist, belong to `account_id`, be a
/// non-API-key session, and be within [`SESSION_MAX_AGE_HOURS`].
pub async fn session_account(db: &Database, session_id: &str, account_id: i64) -> Option<Account> {
    db.get_row(
        "SELECT account.id, account.name, account.password, account.flags, account.totp_enabled, \
                account.totp_secret \
         FROM account INNER JOIN session ON session.account_id = account.id \
         WHERE session.id = ? AND session.account_id = ? AND session.api_key = 0 \
           AND session.created_at >= datetime('now', ?)",
        (
            session_id.to_string(),
            account_id,
            format!("-{SESSION_MAX_AGE_HOURS} hours"),
        ),
        row_to_account,
    )
    .await
    .ok()
}

/// Persists a freshly minted browser session.
pub async fn save_session(db: &Database, token: &Token, description: Option<String>) -> anyhow::Result<()> {
    use anyhow::Context;
    db.execute(
        "INSERT INTO session(id, account_id, description, api_key) VALUES (?, ?, ?, 0)",
        (token.base64(), token.id, description),
    )
    .await
    .context("could not persist session")?;
    Ok(())
}

/// Deletes a session by id (logout / revoke). Best-effort.
pub async fn delete_session(db: &Database, session_id: &str) {
    let _ = db
        .execute("DELETE FROM session WHERE id = ?", (session_id.to_string(),))
        .await;
}

/// Builds the signed session cookie.
pub fn session_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    let mut builder = Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::hours(SESSION_MAX_AGE_HOURS));
    if secure {
        builder = builder.secure(true);
    }
    builder.build()
}

/// Builds a cookie that clears the session (logout). Matches the set cookie's
/// name/scope so it actually removes it.
pub fn clear_cookie(name: &'static str, secure: bool) -> Cookie<'static> {
    let mut builder = Cookie::build((name, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .expires(cookie::time::OffsetDateTime::UNIX_EPOCH);
    if secure {
        builder = builder.secure(true);
    }
    builder.build()
}

/// The rejection for the [`Account`] extractor: bounce to the login page.
pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::to("/login").into_response()
    }
}

/// Request extractor requiring a valid admin session. Reads the signed cookie
/// (parsed into a `Vec<Cookie>` extension by [`crate::parse_cookies`]), verifies
/// its HMAC against the config key, then confirms the session against the DB.
#[async_trait::async_trait]
impl FromRequestParts<AppState> for Account {
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let name = state.config.session_cookie_name();
        let cookie = parts
            .extensions
            .get::<Vec<Cookie>>()
            .and_then(|cookies| cookies.iter().find(|c| c.name() == name))
            .ok_or(AuthRedirect)?;

        let token = Token::from_signed(cookie.value(), &state.config.secret_key).ok_or(AuthRedirect)?;
        // Safe: `from_signed` succeeded, so the value has the `<payload>.<hmac>` shape.
        let (session_id, _) = cookie.value().split_once('.').ok_or(AuthRedirect)?;
        session_account(&state.db, session_id, token.id)
            .await
            .ok_or(AuthRedirect)
    }
}
