//! SSH key management admin routes.
//!
//! GET    /ssh                          — keys + tokens page
//! GET    /ssh/data                     — JSON key list + stats
//! POST   /ssh/keys                     — add a key (JSON)
//! POST   /ssh/keys/:id/revoke          — revoke key
//! DELETE /ssh/keys/:id                 — delete key (hard)
//!
//! GET    /ssh/tokens                   — JSON token list (no plaintext)
//! POST   /ssh/tokens                   — issue token (plaintext returned ONCE)
//! POST   /ssh/tokens/:id/revoke        — revoke token
//! DELETE /ssh/tokens/:id               — delete token (hard)
//!
//! GET    /ssh/audit                    — SSH session audit page
//! GET    /ssh/audit/data               — JSON audit entries (filterable)
//! GET    /ssh/export/authorized_keys   — download active keys as authorized_keys

use crate::{
    audit,
    session::Account,
    ssh::{self, SshKey, SshSessionAudit, SshToken},
    AppState,
};
use askama::Template;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "ssh.html")]
struct SshTemplate {
    account: Option<Account>,
    active_page: &'static str,
}

async fn ssh_page(account: Account) -> Result<SshTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(SshTemplate {
        account: Some(account),
        active_page: "ssh",
    })
}

// ─── Data endpoint ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SshData {
    keys: Vec<SshKey>,
    total: usize,
    active: usize,
    revoked: usize,
}

async fn ssh_data(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<SshData>, (StatusCode, Json<ErrorResponse>)> {
    if !account.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
            }),
        ));
    }

    let keys: Vec<SshKey> = state
        .db
        .call(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, account_id, name, public_key, fingerprint, algo, comment,
                        target_user, added_at, last_used_at, revoked_at
                 FROM ssh_key ORDER BY added_at DESC",
            )?;
            let result: rusqlite::Result<Vec<SshKey>> =
                stmt.query_map(rusqlite::params![], SshKey::from_row)?.collect();
            result
        })
        .await
        .map_err(|e| {
            // Surface the real cause both in logs and in the response body
            // so 'Failed to load — HTTP 500' in the UI shows the actual
            // SQL error (e.g. 'no such column: target_user') instead of
            // making the operator dig through docker logs.
            tracing::error!(error = %e, "ssh_data: SELECT FROM ssh_key failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("database error: {e}"),
                }),
            )
        })?;

    let active = keys.iter().filter(|k| k.is_active()).count();
    let revoked = keys.len() - active;

    Ok(Json(SshData {
        total: keys.len(),
        active,
        revoked,
        keys,
    }))
}

// ─── Add key ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddKeyPayload {
    name: String,
    public_key: String,
}

#[derive(Serialize)]
struct AddKeyResponse {
    id: i64,
    fingerprint: String,
    algo: String,
    target_user: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn add_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Json(payload): Json<AddKeyPayload>,
) -> Result<(StatusCode, Json<AddKeyResponse>), (StatusCode, Json<ErrorResponse>)> {
    if !account.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
            }),
        ));
    }

    let name = payload.name.trim().to_owned();
    if name.is_empty() || name.len() > 100 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: "name must be 1–100 characters".into(),
            }),
        ));
    }

    let raw_key = payload.public_key.trim().to_owned();
    let parsed = ssh::parse_public_key(&raw_key).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: format!("invalid SSH key: {e}"),
            }),
        )
    })?;

    let fingerprint = parsed.fingerprint.clone();
    let algo = parsed.algo.clone();
    let comment = parsed.comment.clone();
    let account_id = account.id;

    // Derive target_user from the key's comment ('user@host' → 'user').
    // Required: without a comment we have no way to know which host
    // account this key authorizes.
    let target_user = comment
        .as_deref()
        .and_then(|c| c.split('@').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: "key has no comment — cannot determine target host user. \
                            Add a trailing 'user@host' to the key line."
                        .into(),
                }),
            )
        })?;

    // Verify the host user exists (i.e. has a home dir under the mounted
    // /host-home or is root with /host-root mounted) and prepare ~/.ssh.
    // We run this synchronously on a blocking thread so we can return a
    // clear 422 if e.g. the user doesn't exist on the host.
    let prepared = {
        let user = target_user.clone();
        tokio::task::spawn_blocking(move || ssh::ensure_user_ssh_dir(&user))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("ssh-dir prep panicked: {e}"),
                    }),
                )
            })?
    };
    match prepared {
        Ok(()) => {}
        Err(ssh::PrepareError::UserNotFound { user, home }) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: format!(
                        "host user '{user}' does not exist (no directory at {}). \
                         Either create the user on the host or fix the key's comment.",
                        home.display()
                    ),
                }),
            ));
        }
        Err(ssh::PrepareError::MountMissing { path }) => {
            return Err((
                StatusCode::FAILED_DEPENDENCY,
                Json(ErrorResponse {
                    error: format!(
                        "host filesystem mount missing at {} — bind-mount /home and \
                         /root into the container per docker-compose.yml to enable \
                         authorized_keys sync.",
                        path.display()
                    ),
                }),
            ));
        }
        Err(ssh::PrepareError::Io { path, error }) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to prepare {}: {error}", path.display()),
                }),
            ));
        }
    }

    let target_user_db = Some(target_user.clone());

    let result = state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO ssh_key(account_id, name, public_key, fingerprint, algo, comment, target_user)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![account_id, name, raw_key, fingerprint, algo, comment, target_user_db],
            )
            .map(|_| conn.last_insert_rowid())
        })
        .await;

    match result {
        Ok(id) => {
            ssh::audit(
                &state,
                Some(account.id),
                Some(id),
                "ssh.key.add",
                Some(peer.ip().to_string()),
                None,
            );
            audit::event("ssh.key.add", &account)
                .target(&parsed.fingerprint)
                .detail(serde_json::json!({ "key_id": id, "algo": parsed.algo }))
                .record(&state.db)
                .await;
            ssh::sync_authorized_keys(&state);
            Ok((
                StatusCode::CREATED,
                Json(AddKeyResponse {
                    id,
                    fingerprint: parsed.fingerprint,
                    algo: parsed.algo,
                    target_user: Some(target_user),
                }),
            ))
        }
        Err(e) if is_unique_constraint_violation(&e) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "a key with this fingerprint already exists for this account".into(),
            }),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".into(),
            }),
        )),
    }
}

/// Checks if a rusqlite error is a UNIQUE constraint violation.
fn is_unique_constraint_violation(e: &rusqlite::Error) -> bool {
    match e {
        rusqlite::Error::SqliteFailure(err, _) => err.code == rusqlite::ErrorCode::ConstraintViolation,
        _ => false,
    }
}

// ─── Revoke key ───────────────────────────────────────────────────────────────

async fn revoke_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE ssh_key SET revoked_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND revoked_at IS NULL",
                rusqlite::params![id],
            )
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, key_id = id, "revoke_key: UPDATE failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if rows == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    ssh::audit(
        &state,
        Some(account.id),
        Some(id),
        "ssh.key.revoke",
        Some(peer.ip().to_string()),
        None,
    );
    audit::event("ssh.key.revoke", &account)
        .target(format!("key:{id}"))
        .record(&state.db)
        .await;
    ssh::sync_authorized_keys(&state);

    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete key ───────────────────────────────────────────────────────────────

async fn delete_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = state
        .db
        .call(move |conn| conn.execute("DELETE FROM ssh_key WHERE id = ?", rusqlite::params![id]))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, key_id = id, "delete_key: DELETE failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if rows == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    ssh::audit(
        &state,
        Some(account.id),
        None,
        "ssh.key.delete",
        Some(peer.ip().to_string()),
        None,
    );
    audit::event("ssh.key.delete", &account)
        .target(format!("key:{id}"))
        .record(&state.db)
        .await;
    ssh::sync_authorized_keys(&state);

    Ok(StatusCode::NO_CONTENT)
}

// ─── Token list ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TokensData {
    tokens: Vec<SshToken>,
    total: usize,
    active: usize,
}

async fn list_tokens(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<TokensData>, (StatusCode, Json<ErrorResponse>)> {
    if !account.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
            }),
        ));
    }

    let tokens: Vec<SshToken> = state
        .db
        .call(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, account_id, token_hash, label, scopes,
                        expires_at, created_at, used_at, revoked_at
                 FROM ssh_token ORDER BY created_at DESC",
            )?;
            let result: rusqlite::Result<Vec<SshToken>> =
                stmt.query_map(rusqlite::params![], SshToken::from_row)?.collect();
            result
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list_tokens: SELECT FROM ssh_token failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("database error: {e}"),
                }),
            )
        })?;

    let active = tokens.iter().filter(|t| t.is_active()).count();

    Ok(Json(TokensData {
        total: tokens.len(),
        active,
        tokens,
    }))
}

// ─── Issue token ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IssueTokenPayload {
    label: String,
    /// Comma-separated scopes, or empty for full access.
    #[serde(default)]
    scopes: String,
    /// Expiry in hours from now. None / 0 = never expires.
    expires_in_hours: Option<i64>,
}

#[derive(Serialize)]
struct IssueTokenResponse {
    id: i64,
    /// Plaintext token — shown ONCE, never stored.
    token: String,
    label: String,
    expires_at: Option<String>,
}

async fn issue_token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Json(payload): Json<IssueTokenPayload>,
) -> Result<(StatusCode, Json<IssueTokenResponse>), (StatusCode, Json<ErrorResponse>)> {
    if !account.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
            }),
        ));
    }

    let label = payload.label.trim().to_owned();
    if label.is_empty() || label.len() > 100 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: "label must be 1–100 characters".into(),
            }),
        ));
    }

    let plaintext = ssh::generate_token();
    let token_hash = ssh::hash_token(&plaintext);
    let scopes = payload.scopes.trim().to_owned();
    let account_id = account.id;

    let expires_at: Option<time::OffsetDateTime> = payload
        .expires_in_hours
        .filter(|&h| h > 0)
        .map(|h| time::OffsetDateTime::now_utc() + time::Duration::hours(h));

    let expires_at_str = expires_at.as_ref().map(|dt| {
        dt.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    });

    let expires_at_db = expires_at_str.clone();
    let label_db = label.clone();
    let scopes_db = scopes.clone();

    let result = state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO ssh_token(account_id, token_hash, label, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![account_id, token_hash, label_db, scopes_db, expires_at_db],
            )
            .map(|_| conn.last_insert_rowid())
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "issue_token: INSERT INTO ssh_token failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("database error: {e}"),
                }),
            )
        })?;

    ssh::audit(
        &state,
        Some(account.id),
        None,
        "ssh.token.issue",
        Some(peer.ip().to_string()),
        None,
    );
    audit::event("ssh.token.issue", &account)
        .target(format!("token:{result}"))
        .detail(serde_json::json!({ "label": label, "expires_in_hours": payload.expires_in_hours }))
        .record(&state.db)
        .await;

    Ok((
        StatusCode::CREATED,
        Json(IssueTokenResponse {
            id: result,
            token: plaintext,
            label,
            expires_at: expires_at_str,
        }),
    ))
}

// ─── Revoke token ─────────────────────────────────────────────────────────────

async fn revoke_token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE ssh_token SET revoked_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND revoked_at IS NULL",
                rusqlite::params![id],
            )
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, token_id = id, "revoke_token: UPDATE failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if rows == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    ssh::audit(
        &state,
        Some(account.id),
        None,
        "ssh.token.revoke",
        Some(peer.ip().to_string()),
        None,
    );
    audit::event("ssh.token.revoke", &account)
        .target(format!("token:{id}"))
        .record(&state.db)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete token ─────────────────────────────────────────────────────────────

async fn delete_token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = state
        .db
        .call(move |conn| conn.execute("DELETE FROM ssh_token WHERE id = ?", rusqlite::params![id]))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, token_id = id, "delete_token: DELETE failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if rows == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    ssh::audit(
        &state,
        Some(account.id),
        None,
        "ssh.token.delete",
        Some(peer.ip().to_string()),
        None,
    );
    audit::event("ssh.token.delete", &account)
        .target(format!("token:{id}"))
        .record(&state.db)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── SSH audit page ───────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "ssh_audit.html")]
struct SshAuditTemplate {
    account: Option<Account>,
    active_page: &'static str,
}

async fn ssh_audit_page(account: Account) -> Result<SshAuditTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(SshAuditTemplate {
        account: Some(account),
        active_page: "ssh",
    })
}

// ─── SSH audit data ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SshAuditQuery {
    /// Filter by key ID.
    key_id: Option<i64>,
    /// Filter by action prefix (e.g. "ssh.key").
    #[serde(default)]
    action: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    200
}

#[derive(Serialize)]
struct SshAuditData {
    entries: Vec<SshSessionAudit>,
    total: usize,
}

async fn ssh_audit_data(
    State(state): State<AppState>,
    account: Account,
    Query(query): Query<SshAuditQuery>,
) -> Result<Json<SshAuditData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let key_id = query.key_id;
    let action_filter = query.action.filter(|s| !s.is_empty()).map(|s| format!("{s}%"));
    let limit = query.limit.clamp(1, 500);

    let entries: Vec<SshSessionAudit> = state
        .db
        .call(move |conn| {
            let mut sql = "SELECT id, account_id, key_id, action, ip, user_agent, created_at
                           FROM ssh_session_audit WHERE 1=1"
                .to_string();
            if key_id.is_some() {
                sql.push_str(" AND key_id = ?");
            }
            if action_filter.is_some() {
                sql.push_str(" AND action LIKE ?");
            }
            sql.push_str(" ORDER BY id DESC LIMIT ?");

            let mut stmt = conn.prepare_cached(&sql)?;
            let rows: rusqlite::Result<Vec<SshSessionAudit>> = match (key_id, action_filter) {
                (Some(k), Some(a)) => stmt
                    .query_map(rusqlite::params![k, a, limit], SshSessionAudit::from_row)?
                    .collect(),
                (Some(k), None) => stmt
                    .query_map(rusqlite::params![k, limit], SshSessionAudit::from_row)?
                    .collect(),
                (None, Some(a)) => stmt
                    .query_map(rusqlite::params![a, limit], SshSessionAudit::from_row)?
                    .collect(),
                (None, None) => stmt
                    .query_map(rusqlite::params![limit], SshSessionAudit::from_row)?
                    .collect(),
            };
            rows
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "ssh_audit_data: SELECT failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let total = entries.len();
    Ok(Json(SshAuditData { entries, total }))
}

// ─── Export authorized_keys ───────────────────────────────────────────────────

async fn export_authorized_keys(State(state): State<AppState>, account: Account) -> Result<Response, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let keys: Vec<SshKey> = state
        .db
        .call(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, account_id, name, public_key, fingerprint, algo, comment,
                        target_user, added_at, last_used_at, revoked_at
                 FROM ssh_key WHERE revoked_at IS NULL ORDER BY added_at ASC",
            )?;
            let result: rusqlite::Result<Vec<SshKey>> =
                stmt.query_map(rusqlite::params![], SshKey::from_row)?.collect();
            result
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "export_authorized_keys: SELECT failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let body = ssh::render_authorized_keys(&keys);

    audit::event("ssh.export.authorized_keys", &account)
        .detail(serde_json::json!({ "key_count": keys.len() }))
        .record(&state.db)
        .await;

    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"authorized_keys\""),
        ],
        body,
    )
        .into_response())
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ssh", get(ssh_page))
        .route("/ssh/data", get(ssh_data))
        .route("/ssh/keys", post(add_key))
        .route("/ssh/keys/:id/revoke", post(revoke_key))
        .route("/ssh/keys/:id", delete(delete_key))
        .route("/ssh/tokens", get(list_tokens).post(issue_token))
        .route("/ssh/tokens/:id/revoke", post(revoke_token))
        .route("/ssh/tokens/:id", delete(delete_token))
        .route("/ssh/audit", get(ssh_audit_page))
        .route("/ssh/audit/data", get(ssh_audit_data))
        .route("/ssh/export/authorized_keys", get(export_authorized_keys))
}
