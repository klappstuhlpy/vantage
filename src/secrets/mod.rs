pub mod routes;
pub mod scanner;
pub mod storage;

use std::path::PathBuf;
use std::time::Duration;

use kls_web_core::Database;
use tracing::{error, info};

use crate::AppState;

pub const SCAN_INTERVAL: Duration = Duration::from_secs(6 * 3600);

pub fn spawn_scheduler(state: AppState) {
    if state.config.secret_scan_paths.is_empty() {
        info!("secret scanner: no paths configured, scheduler disabled");
        return;
    }

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            if let Err(e) = run_scan(&state.db, &state.config.secret_scan_paths).await {
                error!(error = %e, "secret scan failed");
            }
            tokio::time::sleep(SCAN_INTERVAL).await;
        }
    });
}

pub async fn run_scan(db: &Database, roots: &[PathBuf]) -> anyhow::Result<()> {
    if roots.is_empty() {
        return Ok(());
    }

    info!(paths = ?roots, "starting secret scan");

    let roots_owned = roots.to_vec();
    let (findings, counters) = tokio::task::spawn_blocking(move || scanner::scan(&roots_owned)).await?;

    let total = findings.len();
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, secretshape::Severity::Critical))
        .count();

    let new_count = storage::record_scan(db, findings, counters.files_scanned, counters.bytes_scanned, None).await?;

    info!(
        files = counters.files_scanned,
        total,
        critical,
        new = new_count,
        "secret scan finished"
    );

    if new_count > 0 && critical > 0 {
        tracing::warn!(
            new_count,
            critical,
            "secrets.scan.alert: new critical findings detected"
        );
    }

    Ok(())
}
