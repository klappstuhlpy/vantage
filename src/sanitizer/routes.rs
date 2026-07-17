//! File sanitizer routes.
//!
//! GET    /sanitizer          — upload + history page
//! POST   /sanitizer/scan     — multipart upload; runs ClamAV + VT checks
//! GET    /sanitizer/history  — JSON scan history
//! DELETE /sanitizer/:id      — delete a history entry

use crate::session::Account;
use crate::AppState;
use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::Serialize;
use time::OffsetDateTime;

// ─── Model ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct FileScan {
    id: i64,
    filename: String,
    file_size: i64,
    sha256: String,
    clamav_clean: Option<i64>,
    clamav_virus: Option<String>,
    vt_status: Option<String>,
    vt_positives: Option<i64>,
    vt_total: Option<i64>,
    vt_url: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    scanned_at: OffsetDateTime,
}

impl FileScan {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            filename: row.get("filename")?,
            file_size: row.get("file_size")?,
            sha256: row.get("sha256")?,
            clamav_clean: row.get("clamav_clean")?,
            clamav_virus: row.get("clamav_virus")?,
            vt_status: row.get("vt_status")?,
            vt_positives: row.get("vt_positives")?,
            vt_total: row.get("vt_total")?,
            vt_url: row.get("vt_url")?,
            scanned_at: row.get("scanned_at")?,
        })
    }
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "sanitizer.html")]
struct SanitizerTemplate {
    account: Option<Account>,
    active_page: &'static str,
    clamav_enabled: bool,
    vt_enabled: bool,
}

async fn sanitizer_page(State(state): State<AppState>, account: Account) -> SanitizerTemplate {
    SanitizerTemplate {
        account: Some(account),
        active_page: "sanitizer",
        clamav_enabled: state.config.clamav_addr.is_some(),
        vt_enabled: state.config.virustotal_api_key.is_some(),
    }
}

// ─── History ─────────────────────────────────────────────────────────────────

async fn history(State(state): State<AppState>, _account: Account) -> Response {
    let scans: Vec<FileScan> = match state
        .database()
        .call(|conn| -> rusqlite::Result<Vec<FileScan>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, filename, file_size, sha256, clamav_clean, clamav_virus,
                        vt_status, vt_positives, vt_total, vt_url, scanned_at
                 FROM file_scan ORDER BY scanned_at DESC LIMIT 200",
            )?;
            let rows = stmt.query_map([], FileScan::from_row)?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "history query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    Json(serde_json::json!({ "scans": scans })).into_response()
}

// ─── Delete ──────────────────────────────────────────────────────────────────

async fn delete_scan(State(state): State<AppState>, _account: Account, Path(id): Path<i64>) -> Response {
    match state
        .database()
        .execute("DELETE FROM file_scan WHERE id = ?", (id,))
        .await
    {
        Ok(_) => {
            tracing::info!(scan_id = id, "sanitizer.scan.delete");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── Scan ────────────────────────────────────────────────────────────────────

async fn scan(State(state): State<AppState>, _account: Account, mut multipart: Multipart) -> Response {
    // Parse upload
    let (filename, data) = loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_owned();
                if name != "file" {
                    continue;
                }
                let fname = field.file_name().unwrap_or("upload").to_owned();
                match field.bytes().await {
                    Ok(b) => break (fname, b.to_vec()),
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        )
                            .into_response()
                    }
                }
            }
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "no file field in upload" })),
                )
                    .into_response()
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        }
    };

    // Scan (ClamAV + VirusTotal)
    let report = super::scan_bytes(&state, &data).await;
    let super::ScanReport {
        sha256,
        file_size,
        clamav_clean,
        clamav_virus,
        vt_status,
        vt_positives,
        vt_total,
        vt_url,
    } = report;

    // Convert bool to i64 for SQLite
    let clamav_clean_int = clamav_clean.map(|b| if b { 1i64 } else { 0i64 });

    // Clone values before moving into closure
    let filename_for_db = filename.clone();
    let sha256_for_db = sha256.clone();
    let clamav_virus_for_db = clamav_virus.clone();
    let vt_status_for_db = vt_status.clone();
    let vt_url_for_db = vt_url.clone();

    // Persist
    let row_id: i64 = match state
        .database()
        .call(move |conn| {
            conn.query_row(
                "INSERT INTO file_scan (filename, file_size, sha256, clamav_clean, clamav_virus,
                                        vt_status, vt_positives, vt_total, vt_url)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 RETURNING id",
                rusqlite::params![
                    filename_for_db,
                    file_size,
                    sha256_for_db,
                    clamav_clean_int,
                    clamav_virus_for_db,
                    vt_status_for_db,
                    vt_positives,
                    vt_total,
                    vt_url_for_db
                ],
                |row| row.get::<_, i64>(0),
            )
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "file_scan insert failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    tracing::info!(
        scan_id = row_id,
        filename = %filename,
        file_size = file_size,
        sha256 = %sha256,
        clamav_clean = ?clamav_clean,
        vt_status = ?vt_status,
        "sanitizer.scan"
    );

    Json(serde_json::json!({
        "id": row_id,
        "filename": filename,
        "file_size": file_size,
        "sha256": sha256,
        "clamav_clean": clamav_clean_int,
        "clamav_virus": clamav_virus,
        "vt_status": vt_status,
        "vt_positives": vt_positives,
        "vt_total": vt_total,
        "vt_url": vt_url,
    }))
    .into_response()
}

// ─── Router ──────────────────────────────────────────────────────────────────

/// The largest upload the scan endpoint accepts.
///
/// This has to be stated, not inherited: axum's default body limit is 2 MB, so
/// while the UI has always advertised 16 MB, every upload above 2 MB was in
/// fact rejected with a 413 that the page reported as a generic failure. The
/// limit is enforced here and rendered from the same constant, so the promise
/// and the behaviour cannot drift apart again.
pub const MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sanitizer", get(sanitizer_page))
        .route(
            "/sanitizer/scan",
            post(scan).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/sanitizer/history", get(history))
        .route("/sanitizer/:id", delete(delete_scan))
}

#[cfg(test)]
mod tests {
    use crate::{build_router, create_admin_account, AppState, Config};
    use axum::{
        body::Body,
        http::{
            header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
            Request as HttpRequest, StatusCode,
        },
    };
    use std::path::Path;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        crate::build_state_with(Config::test_default(), Path::new(":memory:"))
            .await
            .expect("build state")
    }

    fn set_cookie_pair(res: &axum::response::Response) -> String {
        res.headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    fn form_post_from(uri: &str, body: &'static str, peer: &str) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            peer.parse::<std::net::SocketAddr>().unwrap(),
        ));
        req
    }

    fn get_with_cookie(uri: &str, cookie_pair: &str) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder().uri(uri).body(Body::empty()).unwrap();
        req.headers_mut()
            .insert(COOKIE, axum::http::HeaderValue::from_str(cookie_pair).unwrap());
        req
    }

    #[tokio::test]
    async fn sanitizer_gates_and_serves_history() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out → redirect to /login
        let res = app
            .clone()
            .oneshot(HttpRequest::builder().uri("/sanitizer").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // Log in
        let res = app
            .clone()
            .oneshot(form_post_from(
                "/login",
                "username=root&password=hunter2!",
                "203.0.113.7:5555",
            ))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // Authenticated page renders
        let res = app
            .clone()
            .oneshot(get_with_cookie("/sanitizer", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("<h1>Sanitizer</h1>"), "page heading missing");
        assert!(html.contains("/static/js/pages/sanitizer.js"), "script not linked");
        // Neither backend is configured in the test config. The page must warn
        // that nothing is actually being checked rather than quietly accepting
        // uploads and reporting no threat.
        assert!(html.contains("No scanner is configured"), "no-backend warning missing");

        // History endpoint returns empty list from the migrated table
        let res = app
            .oneshot(get_with_cookie("/sanitizer/history", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["scans"].as_array().unwrap().len(), 0);
    }
}
