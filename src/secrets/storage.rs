use kls_web_core::Database;
use serde::Serialize;
use time::OffsetDateTime;

use super::scanner::Finding;

pub async fn record_scan(
    db: &Database,
    findings: Vec<Finding>,
    files_scanned: u64,
    bytes_scanned: u64,
    error: Option<String>,
) -> rusqlite::Result<i64> {
    db.call(move |conn| -> rusqlite::Result<i64> {
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO scan_run(files_scanned, bytes_scanned, error)
             VALUES (?, ?, ?)",
            rusqlite::params![files_scanned as i64, bytes_scanned as i64, error],
        )?;
        let run_id: i64 = tx.last_insert_rowid();

        let total = findings.len() as i64;
        let mut new_count: i64 = 0;
        {
            let mut insert_stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO secret_finding
                    (rule, severity, file_path, line, snippet, finding_hash, status,
                     first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?, 'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            )?;
            let mut bump_stmt =
                tx.prepare_cached("UPDATE secret_finding SET last_seen = CURRENT_TIMESTAMP WHERE finding_hash = ?")?;
            for f in findings {
                insert_stmt.execute(rusqlite::params![
                    f.rule,
                    f.severity.as_str(),
                    f.file_path.to_string_lossy().into_owned(),
                    f.line as i64,
                    f.snippet,
                    f.finding_hash,
                ])?;
                if tx.changes() > 0 {
                    new_count += 1;
                } else {
                    bump_stmt.execute([&f.finding_hash])?;
                }
            }
        }

        tx.execute(
            "UPDATE scan_run
             SET finished_at    = CURRENT_TIMESTAMP,
                 findings_new   = ?,
                 findings_total = ?
             WHERE id = ?",
            rusqlite::params![new_count, total, run_id],
        )?;
        tx.commit()?;
        Ok(new_count)
    })
    .await
}

#[derive(Debug, Serialize)]
pub struct FindingRow {
    pub id: i64,
    pub rule: String,
    pub severity: String,
    pub file_path: String,
    pub line: i64,
    pub snippet: String,
    pub status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

pub async fn list_findings(
    db: &Database,
    status_filter: Option<&str>,
    limit: i64,
) -> rusqlite::Result<Vec<FindingRow>> {
    let status = status_filter.map(|s| s.to_string());
    db.call(move |conn| -> rusqlite::Result<Vec<FindingRow>> {
        let sql = if status.is_some() {
            "SELECT id, rule, severity, file_path, line, snippet, status,
                    first_seen, last_seen
             FROM secret_finding
             WHERE status = ?
             ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                 last_seen DESC
             LIMIT ?"
        } else {
            "SELECT id, rule, severity, file_path, line, snippet, status,
                    first_seen, last_seen
             FROM secret_finding
             ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                 last_seen DESC
             LIMIT ?"
        };
        let mut stmt = conn.prepare_cached(sql)?;
        let row_map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<FindingRow> {
            Ok(FindingRow {
                id: row.get(0)?,
                rule: row.get(1)?,
                severity: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                snippet: row.get(5)?,
                status: row.get(6)?,
                first_seen: row.get(7)?,
                last_seen: row.get(8)?,
            })
        };
        let rows = if let Some(s) = status {
            stmt.query_map(rusqlite::params![s, limit], row_map)?.collect()
        } else {
            stmt.query_map(rusqlite::params![limit], row_map)?.collect()
        };
        rows
    })
    .await
}

#[derive(Debug, Serialize, Default)]
pub struct StatusCounts {
    pub open: i64,
    pub critical_open: i64,
    pub dismissed: i64,
    pub resolved: i64,
}

pub async fn status_counts(db: &Database) -> rusqlite::Result<StatusCounts> {
    db.call(|conn| -> rusqlite::Result<StatusCounts> {
        Ok(StatusCounts {
            open: conn.query_row("SELECT COUNT(*) FROM secret_finding WHERE status = 'open'", [], |r| {
                r.get(0)
            })?,
            critical_open: conn.query_row(
                "SELECT COUNT(*) FROM secret_finding WHERE status = 'open' AND severity = 'critical'",
                [],
                |r| r.get(0),
            )?,
            dismissed: conn.query_row(
                "SELECT COUNT(*) FROM secret_finding WHERE status = 'dismissed'",
                [],
                |r| r.get(0),
            )?,
            resolved: conn.query_row(
                "SELECT COUNT(*) FROM secret_finding WHERE status = 'resolved'",
                [],
                |r| r.get(0),
            )?,
        })
    })
    .await
}

#[derive(Debug, Serialize, Default)]
pub struct LastScan {
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub files_scanned: i64,
    pub findings_new: i64,
    pub findings_total: i64,
    pub error: Option<String>,
}

pub async fn last_scan(db: &Database) -> rusqlite::Result<Option<LastScan>> {
    db.call(|conn| -> rusqlite::Result<Option<LastScan>> {
        let mut stmt = conn.prepare_cached(
            "SELECT started_at, finished_at, files_scanned, findings_new,
                    findings_total, error
             FROM scan_run
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let result = stmt.query_row([], |row| {
            Ok(LastScan {
                started_at: row.get(0)?,
                finished_at: row.get(1)?,
                files_scanned: row.get(2)?,
                findings_new: row.get(3)?,
                findings_total: row.get(4)?,
                error: row.get(5)?,
            })
        });
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    })
    .await
}

pub async fn set_status(db: &Database, id: i64, status: &str) -> rusqlite::Result<usize> {
    let status = status.to_string();
    db.call(move |conn| -> rusqlite::Result<usize> {
        conn.execute(
            "UPDATE secret_finding SET status = ? WHERE id = ?",
            rusqlite::params![status, id],
        )
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;

    async fn test_db() -> Database {
        Database::file(":memory:")
            .connections(1)
            .with_init(migrations::migrate)
            .open()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn record_scan_and_list_roundtrip() {
        let db = test_db().await;

        let findings = vec![super::super::scanner::Finding {
            rule: "AWS Access Key".to_string(),
            severity: secretshape::Severity::Critical,
            file_path: "/home/user/.env".into(),
            line: 3,
            snippet: "AKIA****MPLE".to_string(),
            finding_hash: "abc123hash".to_string(),
        }];

        let new = record_scan(&db, findings, 42, 1024, None).await.unwrap();
        assert_eq!(new, 1);

        let rows = list_findings(&db, Some("open"), 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule, "AWS Access Key");
        assert_eq!(rows[0].severity, "critical");

        let counts = status_counts(&db).await.unwrap();
        assert_eq!(counts.open, 1);
        assert_eq!(counts.critical_open, 1);

        let scan = last_scan(&db).await.unwrap().unwrap();
        assert_eq!(scan.files_scanned, 42);
        assert_eq!(scan.findings_new, 1);
        assert_eq!(scan.findings_total, 1);
    }

    #[tokio::test]
    async fn duplicate_finding_bumps_last_seen_not_count() {
        let db = test_db().await;

        let findings = vec![super::super::scanner::Finding {
            rule: "Generic Secret".to_string(),
            severity: secretshape::Severity::High,
            file_path: "/app/config".into(),
            line: 1,
            snippet: "secr****cret".to_string(),
            finding_hash: "dedup-hash".to_string(),
        }];

        let new1 = record_scan(&db, findings.clone(), 1, 100, None).await.unwrap();
        assert_eq!(new1, 1);

        let new2 = record_scan(&db, findings, 1, 100, None).await.unwrap();
        assert_eq!(new2, 0);

        let rows = list_findings(&db, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn set_status_updates_finding() {
        let db = test_db().await;

        let findings = vec![super::super::scanner::Finding {
            rule: "Test".to_string(),
            severity: secretshape::Severity::Medium,
            file_path: "/test".into(),
            line: 1,
            snippet: "****".to_string(),
            finding_hash: "status-test".to_string(),
        }];
        record_scan(&db, findings, 1, 10, None).await.unwrap();

        let rows = list_findings(&db, Some("open"), 10).await.unwrap();
        let id = rows[0].id;

        set_status(&db, id, "dismissed").await.unwrap();
        let rows = list_findings(&db, Some("dismissed"), 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "dismissed");
    }
}
