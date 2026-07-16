//! Persistence layer for reverse-proxy routes.

use crate::AppState;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    pub id: i64,
    pub subdomain: String,
    pub target_host: String,
    pub target_port: i64,
    pub target_scheme: String,
    pub container: Option<String>,
    pub ssl_managed: bool,
    pub cloudflare_proxied: bool,
    pub http_auth_user: Option<String>,
    /// Never serialised back to the client — only the presence is exposed
    /// via [`ProxyRoute::has_auth`].
    #[serde(skip_serializing)]
    pub http_auth_pass_hash: Option<String>,
    pub rate_limit_rps: Option<i64>,
    pub access_rules_json: Option<String>,
    pub extra_config: Option<String>,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl ProxyRoute {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            subdomain: row.get("subdomain")?,
            target_host: row.get("target_host")?,
            target_port: row.get("target_port")?,
            target_scheme: row.get("target_scheme")?,
            container: row.get("container")?,
            ssl_managed: row.get::<_, i64>("ssl_managed")? != 0,
            cloudflare_proxied: row.get::<_, i64>("cloudflare_proxied")? != 0,
            http_auth_user: row.get("http_auth_user")?,
            http_auth_pass_hash: row.get("http_auth_pass_hash")?,
            rate_limit_rps: row.get("rate_limit_rps")?,
            access_rules_json: row.get("access_rules_json")?,
            extra_config: row.get("extra_config")?,
            enabled: row.get::<_, i64>("enabled")? != 0,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }

    /// Whether this route has an HTTP basic-auth gate configured.
    pub fn has_auth(&self) -> bool {
        self.http_auth_user.is_some() && self.http_auth_pass_hash.is_some()
    }
}

/// Serialised form for the dashboard — strips the password hash and adds a
/// boolean flag instead.
#[derive(Debug, Clone, Serialize)]
pub struct RouteView {
    #[serde(flatten)]
    pub route: ProxyRoute,
    pub has_auth: bool,
}

impl From<ProxyRoute> for RouteView {
    fn from(route: ProxyRoute) -> Self {
        let has_auth = route.has_auth();
        RouteView { route, has_auth }
    }
}

const SELECT_COLS: &str = "id, subdomain, target_host, target_port, target_scheme,
                           container, ssl_managed, cloudflare_proxied,
                           http_auth_user, http_auth_pass_hash, rate_limit_rps,
                           access_rules_json, extra_config, enabled,
                           created_at, updated_at";

#[derive(Debug, Clone)]
pub struct NewRoute {
    pub subdomain: String,
    pub target_host: String,
    pub target_port: i64,
    pub target_scheme: String,
    pub container: Option<String>,
    pub ssl_managed: bool,
    pub cloudflare_proxied: bool,
    pub http_auth_user: Option<String>,
    /// `None` keeps the existing hash on update; `Some` replaces it.
    pub http_auth_pass_hash: Option<String>,
    pub rate_limit_rps: Option<i64>,
    pub access_rules_json: Option<String>,
    pub extra_config: Option<String>,
    pub enabled: bool,
}

pub async fn list_routes(state: &AppState) -> rusqlite::Result<Vec<ProxyRoute>> {
    state
        .db
        .call(|conn| -> rusqlite::Result<Vec<ProxyRoute>> {
            let mut stmt =
                conn.prepare_cached(&format!("SELECT {SELECT_COLS} FROM proxy_route ORDER BY subdomain ASC"))?;
            let rows: rusqlite::Result<Vec<ProxyRoute>> = stmt.query_map([], ProxyRoute::from_row)?.collect();
            rows
        })
        .await
}

pub async fn get_route(state: &AppState, id: i64) -> rusqlite::Result<Option<ProxyRoute>> {
    state
        .db
        .call(move |conn| -> rusqlite::Result<Option<ProxyRoute>> {
            let mut stmt = conn.prepare_cached(&format!("SELECT {SELECT_COLS} FROM proxy_route WHERE id = ?"))?;
            match stmt.query_row([id], ProxyRoute::from_row) {
                Ok(r) => Ok(Some(r)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
}

pub async fn create_route(state: &AppState, route: NewRoute) -> rusqlite::Result<i64> {
    state
        .db
        .call(move |conn| -> rusqlite::Result<i64> {
            conn.execute(
                "INSERT INTO proxy_route
                   (subdomain, target_host, target_port, target_scheme, container,
                    ssl_managed, cloudflare_proxied, http_auth_user, http_auth_pass_hash,
                    rate_limit_rps, access_rules_json, extra_config, enabled)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    route.subdomain,
                    route.target_host,
                    route.target_port,
                    route.target_scheme,
                    route.container,
                    if route.ssl_managed { 1 } else { 0 },
                    if route.cloudflare_proxied { 1 } else { 0 },
                    route.http_auth_user,
                    route.http_auth_pass_hash,
                    route.rate_limit_rps,
                    route.access_rules_json,
                    route.extra_config,
                    if route.enabled { 1 } else { 0 },
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

pub async fn update_route(state: &AppState, id: i64, route: NewRoute) -> rusqlite::Result<usize> {
    state
        .db
        .call(move |conn| -> rusqlite::Result<usize> {
            // When http_auth_pass_hash is None we keep whatever is already
            // stored (COALESCE) so editing a route without re-typing the
            // password doesn't wipe the credential.
            conn.execute(
                "UPDATE proxy_route SET
                    subdomain = ?, target_host = ?, target_port = ?, target_scheme = ?,
                    container = ?, ssl_managed = ?, cloudflare_proxied = ?,
                    http_auth_user = ?, http_auth_pass_hash = COALESCE(?, http_auth_pass_hash),
                    rate_limit_rps = ?, access_rules_json = ?, extra_config = ?,
                    enabled = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
                rusqlite::params![
                    route.subdomain,
                    route.target_host,
                    route.target_port,
                    route.target_scheme,
                    route.container,
                    if route.ssl_managed { 1 } else { 0 },
                    if route.cloudflare_proxied { 1 } else { 0 },
                    route.http_auth_user,
                    route.http_auth_pass_hash,
                    route.rate_limit_rps,
                    route.access_rules_json,
                    route.extra_config,
                    if route.enabled { 1 } else { 0 },
                    id,
                ],
            )
        })
        .await
}

/// Upserts a route discovered by importing a Cloudflare Tunnel's ingress.
/// Matches on the unique `subdomain`: a new hostname is inserted, an existing
/// one has only its upstream + cloudflare flag refreshed (the operator's
/// auth / rate-limit / access settings are preserved). Returns `true` when a
/// new row was inserted.
pub async fn upsert_imported_route(
    state: &AppState,
    subdomain: String,
    target_host: String,
    target_port: i64,
    target_scheme: String,
) -> rusqlite::Result<bool> {
    state
        .db
        .call(move |conn| -> rusqlite::Result<bool> {
            let existed: bool = conn
                .query_row(
                    "SELECT 1 FROM proxy_route WHERE subdomain = ?",
                    [&subdomain],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            conn.execute(
                "INSERT INTO proxy_route
                   (subdomain, target_host, target_port, target_scheme,
                    ssl_managed, cloudflare_proxied, enabled)
                 VALUES (?, ?, ?, ?, 0, 1, 1)
                 ON CONFLICT(subdomain) DO UPDATE SET
                    target_host        = excluded.target_host,
                    target_port        = excluded.target_port,
                    target_scheme      = excluded.target_scheme,
                    cloudflare_proxied = 1,
                    updated_at         = CURRENT_TIMESTAMP",
                rusqlite::params![subdomain, target_host, target_port, target_scheme],
            )?;
            Ok(!existed)
        })
        .await
}

pub async fn delete_route(state: &AppState, id: i64) -> rusqlite::Result<usize> {
    state
        .db
        .call(move |conn| conn.execute("DELETE FROM proxy_route WHERE id = ?", [id]))
        .await
}

pub async fn set_enabled(state: &AppState, id: i64, enabled: bool) -> rusqlite::Result<usize> {
    state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE proxy_route SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                rusqlite::params![if enabled { 1 } else { 0 }, id],
            )
        })
        .await
}
