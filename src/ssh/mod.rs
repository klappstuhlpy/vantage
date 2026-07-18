//! SSH key management — models, fingerprint parsing, and DB helpers.
//!
//! Fingerprint format matches OpenSSH's default (`SHA256:<base64url-no-pad>`),
//! so the value displayed in the UI is identical to `ssh-keygen -lf`.
pub mod routes; // HTTP handlers for this admin feature

use base64::{prelude::BASE64_STANDARD_NO_PAD, prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing;

use crate::AppState;

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Everything extracted from an OpenSSH public-key line.
#[derive(Debug, Clone)]
pub struct ParsedSshKey {
    pub algo: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

/// Errors returned by [`parse_public_key`].
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("key line is empty or has no type field")]
    MissingType,
    #[error("key line is missing the base64 key material")]
    MissingKeyData,
    #[error("base64 key material is invalid: {0}")]
    BadBase64(#[from] base64::DecodeError),
}

/// Parse a single-line OpenSSH public key and compute its SHA-256 fingerprint.
///
/// Accepts the standard `<type> <base64> [comment]` format.
/// Returns [`ParseError`] for anything that doesn't fit that shape.
pub fn parse_public_key(line: &str) -> Result<ParsedSshKey, ParseError> {
    let line = line.trim();
    let mut parts = line.splitn(3, ' ');

    let algo = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::MissingType)?;
    let b64 = parts.next().ok_or(ParseError::MissingKeyData)?;
    let comment = parts.next().filter(|s| !s.is_empty()).map(str::to_owned);

    // The base64 blob may use standard or URL-safe alphabet; try both.
    let raw = BASE64_STANDARD_NO_PAD
        .decode(b64)
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(b64))?;

    let digest = Sha256::digest(&raw);
    // OpenSSH fingerprint: "SHA256:" + standard base64 no-pad
    let fingerprint = format!("SHA256:{}", BASE64_STANDARD_NO_PAD.encode(digest));

    Ok(ParsedSshKey {
        algo: algo.to_owned(),
        fingerprint,
        comment,
    })
}

// ─── Models ──────────────────────────────────────────────────────────────────

/// A stored SSH public key authorized for a user.
#[derive(Debug, Clone, Serialize)]
pub struct SshKey {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    /// Full OpenSSH key line (type + base64 + optional comment).
    pub public_key: String,
    /// SHA-256 fingerprint: `SHA256:<base64>`.
    pub fingerprint: String,
    pub algo: String,
    pub comment: Option<String>,
    /// Host user the key authorizes — used to pick which `authorized_keys`
    /// file the filesystem sync writes this key to. NULL on legacy rows; such keys are
    /// not synced and surface as "not synced" in the admin UI.
    pub target_user: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

impl SshKey {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            account_id: row.get("account_id")?,
            name: row.get("name")?,
            public_key: row.get("public_key")?,
            fingerprint: row.get("fingerprint")?,
            algo: row.get("algo")?,
            comment: row.get("comment")?,
            target_user: row.get("target_user")?,
            added_at: row.get("added_at")?,
            last_used_at: row.get("last_used_at")?,
            revoked_at: row.get("revoked_at")?,
        })
    }
}

/// A short-lived access token (CI/CD, scripts) tied to an account.
#[derive(Debug, Clone, Serialize)]
pub struct SshToken {
    pub id: i64,
    pub account_id: i64,
    pub label: String,
    /// Comma-separated scope list (`""` = full access, same semantics as `Session.scopes`).
    pub scopes: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

impl SshToken {
    pub fn is_active(&self) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        self.expires_at
            .map(|exp| OffsetDateTime::now_utc() < exp)
            .unwrap_or(true)
    }

    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            account_id: row.get("account_id")?,
            label: row.get("label")?,
            scopes: row.get("scopes")?,
            expires_at: row.get("expires_at")?,
            created_at: row.get("created_at")?,
            used_at: row.get("used_at")?,
            revoked_at: row.get("revoked_at")?,
        })
    }
}

/// One row in the per-key action log.
#[derive(Debug, Clone, Serialize)]
pub struct SshSessionAudit {
    pub id: i64,
    pub account_id: Option<i64>,
    pub key_id: Option<i64>,
    pub action: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl SshSessionAudit {
    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            account_id: row.get("account_id")?,
            key_id: row.get("key_id")?,
            action: row.get("action")?,
            ip: row.get("ip")?,
            user_agent: row.get("user_agent")?,
            created_at: row.get("created_at")?,
        })
    }
}

// ─── DB helpers ──────────────────────────────────────────────────────────────

use std::time::Duration;

/// Alphabet for generated tokens: alphanumeric only (no lookalike chars).
const TOKEN_ALPHABET: [char; 62] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

/// Generate a new plaintext token (`sshtkn_<32 random chars>`).
pub fn generate_token() -> String {
    let rand = nanoid::nanoid!(32, &TOKEN_ALPHABET);
    format!("sshtkn_{rand}")
}

/// Background task: mark all expired `ssh_token` rows as revoked every hour.
/// Call once at startup — spawns a detached tokio task.
pub fn spawn_token_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let result = state
                .db
                .call(|conn| {
                    conn.execute(
                        "UPDATE ssh_token
                         SET    revoked_at = CURRENT_TIMESTAMP
                         WHERE  revoked_at IS NULL
                           AND  expires_at IS NOT NULL
                           AND  expires_at <= CURRENT_TIMESTAMP",
                        rusqlite::params![],
                    )
                })
                .await;
            match result {
                Ok(n) if n > 0 => tracing::info!(count = n, "swept expired SSH tokens"),
                Err(e) => tracing::warn!(error = %e, "SSH token sweeper error"),
                _ => {}
            }
        }
    });
}

/// Record one entry in `ssh_session_audit` (fire-and-forget).
pub fn audit(
    state: &AppState,
    account_id: Option<i64>,
    key_id: Option<i64>,
    action: &'static str,
    ip: Option<String>,
    user_agent: Option<String>,
) {
    let state = state.clone();
    tokio::spawn(async move {
        let _ = state
            .db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO ssh_session_audit(account_id, key_id, action, ip, user_agent)
                     VALUES (?, ?, ?, ?, ?)",
                    rusqlite::params![account_id, key_id, action, ip, user_agent],
                )
            })
            .await;
    });
}

/// Hash a raw token with SHA-256 and return the hex string used for storage.
pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("{:x}", digest)
}

// ─── authorized_keys file sync ───────────────────────────────────────────────

/// Render a list of active keys into a standard `authorized_keys` file body.
/// Each key gets a preceding `# <name> (added <rfc3339>)` comment so an admin
/// can trace each line back to a database row.
pub fn render_authorized_keys(keys: &[SshKey]) -> String {
    let mut body = String::from("# Generated by Vantage — do not edit manually\n");
    for key in keys {
        body.push_str(&format!(
            "# {} (added {})\n{}\n",
            key.name,
            key.added_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            key.public_key.trim(),
        ));
    }
    body
}

// ─── Host filesystem layout (convention) ─────────────────────────────────────
//
// The container expects two bind-mounts from the host:
//   /home   → /host-home   (every non-root user's home dir lives under here)
//   /root   → /host-root   (the root user's home dir is here directly)
//
// The path a given target user's authorized_keys gets written to is derived
// from the user's name only — no config map needed:
//
//   target_user == "root"   → /host-root/.ssh/authorized_keys
//   target_user == "<x>"    → /host-home/<x>/.ssh/authorized_keys
//
// On the host side these are /root/.ssh/authorized_keys and
// /home/<x>/.ssh/authorized_keys respectively, which is the standard layout
// sshd reads from.

const HOST_HOME_PARENT: &str = "/host-home";
const HOST_ROOT_HOME: &str = "/host-root";

/// Returns the in-container path to the target user's home directory under
/// the bind-mounted host filesystem. `root` is special-cased; everyone else
/// is assumed to live under `/host-home/<user>`.
fn target_home_dir(user: &str) -> std::path::PathBuf {
    if user == "root" {
        std::path::PathBuf::from(HOST_ROOT_HOME)
    } else {
        std::path::Path::new(HOST_HOME_PARENT).join(user)
    }
}

/// Errors `ensure_user_ssh_dir` can return.
///
/// `MountMissing` and `UserNotFound` are only constructed on the Unix
/// production path (see the `#[cfg(unix)]` impl below); the non-Unix dev stub
/// returns `Ok` and never builds them, so the compiler flags them as dead there.
/// Silence that only off-Unix — on Linux the lint stays live.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    /// The bind-mount parent (`/host-home` or `/host-root`) doesn't exist —
    /// the operator hasn't wired up docker-compose volumes for SSH sync.
    #[error("host filesystem mount missing at {path}")]
    MountMissing { path: std::path::PathBuf },
    /// The bind-mount is there but no directory exists for this user.
    #[error("user '{user}' has no home directory at {home}")]
    UserNotFound { user: String, home: std::path::PathBuf },
    /// Anything else — permission denied, EIO, etc.
    #[error("io error at {path}: {error}")]
    Io {
        path: std::path::PathBuf,
        error: std::io::Error,
    },
}

/// Ensure `~<user>/.ssh` exists with the right perms and ownership so sshd's
/// StrictModes check passes. Idempotent: leaves existing dirs untouched.
///
/// On non-Unix targets this is a stub that always succeeds — the feature
/// only does anything useful on the production Linux container.
pub fn ensure_user_ssh_dir(user: &str) -> Result<(), PrepareError> {
    ensure_user_ssh_dir_impl(user)
}

#[cfg(unix)]
fn ensure_user_ssh_dir_impl(user: &str) -> Result<(), PrepareError> {
    use std::os::unix::fs::{chown, PermissionsExt};

    // Sanity-check that the bind-mount parent itself is present. Without
    // it we'd happily create the home dir but it would only exist inside
    // the container, never reaching the host.
    let mount_parent = if user == "root" {
        std::path::PathBuf::from(HOST_ROOT_HOME)
    } else {
        std::path::PathBuf::from(HOST_HOME_PARENT)
    };
    if !mount_parent.exists() {
        return Err(PrepareError::MountMissing { path: mount_parent });
    }

    let home = target_home_dir(user);
    let meta = match std::fs::metadata(&home) {
        Ok(m) if m.is_dir() => m,
        Ok(_) => {
            return Err(PrepareError::UserNotFound {
                user: user.into(),
                home,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PrepareError::UserNotFound {
                user: user.into(),
                home,
            });
        }
        Err(error) => return Err(PrepareError::Io { path: home, error }),
    };

    use std::os::unix::fs::MetadataExt;
    let (uid, gid) = (meta.uid(), meta.gid());

    let ssh_dir = home.join(".ssh");
    match std::fs::metadata(&ssh_dir) {
        Ok(m) if m.is_dir() => {} // already there, leave perms alone
        Ok(_) => {
            return Err(PrepareError::Io {
                path: ssh_dir.clone(),
                error: std::io::Error::new(std::io::ErrorKind::AlreadyExists, ".ssh exists but is not a directory"),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&ssh_dir)
                .and_then(|_| std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)))
                .and_then(|_| chown(&ssh_dir, Some(uid), Some(gid)))
                .map_err(|error| PrepareError::Io {
                    path: ssh_dir.clone(),
                    error,
                })?;
            tracing::info!(path = %ssh_dir.display(), uid, gid, "created ~/.ssh");
        }
        Err(error) => return Err(PrepareError::Io { path: ssh_dir, error }),
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_user_ssh_dir_impl(_user: &str) -> Result<(), PrepareError> {
    // No-op on Windows dev. The feature only runs in the Linux container.
    Ok(())
}

/// Rewrite every host user's `authorized_keys` file from the current set of
/// active DB keys.
///
/// Groups active keys by their `target_user`, then for each user with at
/// least one key writes `~user/.ssh/authorized_keys` atomically (temp +
/// rename, mode 0600, chown'd to the home dir's owner UID/GID so sshd's
/// StrictModes check passes). Users whose home dir disappeared since the
/// key was added are logged at WARN and skipped.
///
/// Users with no remaining keys after a revoke get an empty (header-only)
/// file rewritten over their existing one so the revocation actually takes
/// effect. To know which users to clear out, we track a process-wide set
/// of users we've ever written for. That's fine because sync runs in-band
/// after every mutation — the set never gets stale within one process
/// lifetime, and at startup an empty set is harmless (no extra file
/// clears, the existing files still reflect the DB).
///
/// Fire-and-forget: errors are logged at WARN, not propagated, so a failing
/// disk sync never breaks the admin API call that triggered it.
pub fn sync_authorized_keys(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        let keys_result: Result<Vec<SshKey>, _> = state
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
            .await;

        let keys = match keys_result {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "authorized_keys sync: db read failed");
                return;
            }
        };

        // Bucket by target_user; legacy keys without one are skipped.
        use std::collections::HashMap;
        let mut by_user: HashMap<String, Vec<SshKey>> = HashMap::new();
        for key in keys {
            match key.target_user.clone() {
                Some(user) => by_user.entry(user).or_default().push(key),
                None => tracing::warn!(
                    key_id = key.id,
                    fingerprint = %key.fingerprint,
                    "authorized_keys sync: legacy key has no target_user — skipped \
                     (re-add the key to fix)"
                ),
            }
        }

        // Also clear any user we've previously written for but who no longer
        // has keys — otherwise a revoke wouldn't actually remove the line.
        let previously_written = take_previously_written();
        for user in previously_written.iter() {
            by_user.entry(user.clone()).or_default();
        }
        let mut now_writing: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (user, bucket) in by_user {
            let count = bucket.len();
            let body = render_authorized_keys(&bucket);
            let user_owned = user.clone();
            let write_result =
                tokio::task::spawn_blocking(move || write_user_authorized_keys(&user_owned, body.as_bytes()))
                    .await
                    .unwrap_or_else(|e| {
                        Err(PrepareError::Io {
                            path: std::path::PathBuf::new(),
                            error: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
                        })
                    });

            match write_result {
                Ok(path) => {
                    tracing::info!(
                        target_user = %user,
                        path = %path.display(),
                        count,
                        "authorized_keys synced"
                    );
                    if count > 0 {
                        now_writing.insert(user);
                    }
                }
                Err(e) => tracing::warn!(
                    target_user = %user,
                    error = %e,
                    "authorized_keys sync: write failed"
                ),
            }
        }

        // Remember who we wrote for so a future revoke can clear them.
        set_previously_written(now_writing);
    });
}

// In-process memory of "which users have we ever written authorized_keys for
// this session". Used to clear out users whose keys were all revoked.
static PREVIOUSLY_WRITTEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn take_previously_written() -> std::collections::HashSet<String> {
    let m = PREVIOUSLY_WRITTEN.get_or_init(|| std::sync::Mutex::new(Default::default()));
    m.lock().map(|g| g.clone()).unwrap_or_default()
}
fn set_previously_written(set: std::collections::HashSet<String>) {
    let m = PREVIOUSLY_WRITTEN.get_or_init(|| std::sync::Mutex::new(Default::default()));
    if let Ok(mut g) = m.lock() {
        *g = set;
    }
}

/// Write one user's authorized_keys file, creating ~/.ssh if needed.
/// Returns the path we wrote to so the caller can log it.
fn write_user_authorized_keys(user: &str, body: &[u8]) -> Result<std::path::PathBuf, PrepareError> {
    ensure_user_ssh_dir(user)?;
    let path = target_home_dir(user).join(".ssh").join("authorized_keys");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt};
        // Match ownership of the home dir so sshd's StrictModes is happy.
        let owner = std::fs::metadata(target_home_dir(user))
            .map(|m| (m.uid(), m.gid()))
            .map_err(|error| PrepareError::Io {
                path: target_home_dir(user),
                error,
            })?;

        write_atomic(&path, body)
            .and_then(|_| chown(&path, Some(owner.0), Some(owner.1)))
            .map_err(|error| PrepareError::Io {
                path: path.clone(),
                error,
            })?;
    }
    #[cfg(not(unix))]
    {
        write_atomic(&path, body).map_err(|error| PrepareError::Io {
            path: path.clone(),
            error,
        })?;
    }
    Ok(path)
}

// ─── sshd auth log watcher ───────────────────────────────────────────────────

/// Everything we extract from one successful `Accepted publickey` line.
#[derive(Debug, PartialEq, Eq)]
struct ParsedAccept<'a> {
    /// SHA-256 fingerprint of the key, in OpenSSH `SHA256:<base64>` form.
    fingerprint: &'a str,
    /// Algorithm string sshd printed, e.g. `ED25519`, `RSA`, `ECDSA`.
    algo: &'a str,
    /// Host user that was logged in as (`Accepted publickey for <X>`).
    user: &'a str,
    /// Client IP (`from <X> port N`). May be IPv4, IPv6, or rarely a hostname.
    ip: &'a str,
}

/// Parse one sshd log line. Returns the extracted fields iff the line is
/// a successful publickey authentication. Tolerant of leading
/// timestamp/hostname prefixes and rsyslog vs journald formats.
///
/// Matches OpenSSH's default `Accepted publickey` format:
///   `... sshd[1234]: Accepted publickey for user from 1.2.3.4 port 22 ssh2: ED25519 SHA256:abc…`
fn parse_publickey_accept(line: &str) -> Option<ParsedAccept<'_>> {
    let idx = line.find("Accepted publickey ")?;
    let rest = &line[idx + "Accepted publickey ".len()..];

    // `for <user> from <ip> port <n> ssh2: <algo> <fingerprint>`
    let rest = rest.strip_prefix("for ")?;
    let (user, rest) = rest.split_once(' ')?;
    let rest = rest.strip_prefix("from ")?;
    let (ip, rest) = rest.split_once(' ')?;

    let ssh2_idx = rest.find(" ssh2: ")?;
    let after = &rest[ssh2_idx + " ssh2: ".len()..];
    let mut parts = after.split_whitespace();
    let algo = parts.next()?;
    let fingerprint = parts.next()?;
    if !fingerprint.starts_with("SHA256:") {
        return None;
    }
    Some(ParsedAccept {
        fingerprint,
        algo,
        user,
        ip,
    })
}

/// Background task: tail the configured sshd auth log and update
/// `ssh_key.last_used_at` (+ write `ssh.key.use` to `ssh_session_audit`)
/// whenever a successful publickey auth matches a stored fingerprint.
///
/// No-op when `sshd_auth_log_path` is not configured. Resilient to log
/// rotation (detects inode change on Unix and file truncation everywhere)
/// and to the log file being temporarily absent. Runs on its own blocking
/// thread to keep the std::io BufReader code straightforward.
pub fn spawn_auth_log_watcher(state: AppState) {
    let Some(path) = state.config.sshd_auth_log_path.clone() else {
        tracing::info!("SSH auth log watcher disabled (sshd_auth_log_path not set)");
        return;
    };
    // Capture the current Tokio runtime handle while we're still on a
    // runtime worker. The watcher's std::thread has no runtime in TLS,
    // so any tokio::spawn / .await call from it would panic with
    // "there is no reactor running". Passing the handle in lets the
    // thread enter() the runtime for its entire lifetime, so the inner
    // tokio::spawn calls in record_key_use / audit() just work.
    let handle = tokio::runtime::Handle::current();
    let path = std::path::PathBuf::from(path);
    std::thread::Builder::new()
        .name("ssh-auth-log-watcher".into())
        .spawn(move || run_auth_log_watcher(state, path, handle))
        .expect("failed to spawn ssh-auth-log-watcher thread");
}

fn run_auth_log_watcher(state: AppState, path: std::path::PathBuf, handle: tokio::runtime::Handle) {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    // Keep the runtime current for this thread for the whole loop —
    // tokio::spawn, Handle::current(), and .await on Tokio futures all
    // need this. The guard drops on function return (i.e. never).
    let _runtime_guard = handle.enter();

    let mut reader: Option<BufReader<std::fs::File>> = None;
    let mut last_pos: u64 = 0;
    let mut current_inode: Option<u64> = None;

    loop {
        // (Re)open if we don't have an active reader.
        if reader.is_none() {
            match std::fs::File::open(&path) {
                Ok(mut f) => {
                    let end = f.seek(SeekFrom::End(0)).unwrap_or(0);
                    last_pos = end;
                    current_inode = inode_of(&f);
                    reader = Some(BufReader::new(f));
                    tracing::info!(path = %path.display(), "SSH auth log watcher attached");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e,
                        "SSH auth log open failed; retrying in 10s");
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            }
        }

        // Detect rotation: inode change (rename+create) or file shrank (truncate).
        let rotated = match std::fs::metadata(&path) {
            Ok(meta) => {
                let inode_changed = matches!(
                    (current_inode, inode_of_meta(&meta)),
                    (Some(a), Some(b)) if a != b
                );
                inode_changed || meta.len() < last_pos
            }
            Err(_) => true,
        };
        if rotated {
            tracing::info!(path = %path.display(), "SSH auth log rotated; reopening");
            reader = None;
            last_pos = 0;
            current_inode = None;
            continue;
        }

        // Drain any new lines.
        if let Some(r) = reader.as_mut() {
            let mut line = String::new();
            loop {
                line.clear();
                match r.read_line(&mut line) {
                    Ok(0) => break, // EOF — wait for more
                    Ok(n) => {
                        last_pos += n as u64;
                        if let Some(parsed) = parse_publickey_accept(line.trim_end()) {
                            // Synthesize a "user-agent" so the SSH audit page
                            // has something concrete to show in that column —
                            // SSH itself has no UA, so we encode the algo +
                            // the host user that was logged in as. Mirrors
                            // how web routes record actual User-Agent strings.
                            let user_agent = format!(
                                "ssh-publickey/{algo} target={user}",
                                algo = parsed.algo,
                                user = parsed.user,
                            );
                            record_key_use(
                                &state,
                                parsed.fingerprint.to_owned(),
                                Some(parsed.ip.to_owned()),
                                Some(user_agent),
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "SSH auth log read error; reopening");
                        reader = None;
                        break;
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(unix)]
fn inode_of(f: &std::fs::File) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    f.metadata().ok().map(|m| m.ino())
}
#[cfg(not(unix))]
fn inode_of(_f: &std::fs::File) -> Option<u64> {
    None
}

#[cfg(unix)]
fn inode_of_meta(m: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(m.ino())
}
#[cfg(not(unix))]
fn inode_of_meta(_m: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Update last_used_at for the matching key (if any) and fire an audit entry.
fn record_key_use(state: &AppState, fingerprint: String, ip: Option<String>, user_agent: Option<String>) {
    let state = state.clone();
    tokio::spawn(async move {
        // Atomic: update + look up the key id/account in one DB hop so we
        // can attribute the audit entry properly.
        let fp_for_call = fingerprint.clone();
        let result = state
            .db
            .call(move |conn| -> rusqlite::Result<Option<(i64, i64)>> {
                let rows = conn.execute(
                    "UPDATE ssh_key
                     SET    last_used_at = CURRENT_TIMESTAMP
                     WHERE  fingerprint = ? AND revoked_at IS NULL",
                    rusqlite::params![fp_for_call],
                )?;
                if rows == 0 {
                    return Ok(None);
                }
                let row = conn.query_row(
                    "SELECT id, account_id FROM ssh_key WHERE fingerprint = ?",
                    rusqlite::params![fp_for_call],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )?;
                Ok(Some(row))
            })
            .await;

        match result {
            Ok(Some((key_id, account_id))) => {
                tracing::debug!(fingerprint = %fingerprint, key_id, ?ip, "ssh key used");
                audit(&state, Some(account_id), Some(key_id), "ssh.key.use", ip, user_agent);
            }
            Ok(None) => {
                tracing::debug!(fingerprint = %fingerprint,
                    "sshd accept for unknown or revoked key");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to update ssh_key.last_used_at");
            }
        }
    });
}

/// Atomic write: temp sibling + rename, with 0600 perms on Unix.
fn write_atomic(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent directory"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);

    std::fs::write(&tmp, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ed25519_key() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxDPXFO8BFiTL6Z5XB9D1fBXaJPkPFDZI5y6d5X1234 user@host";
        let parsed = parse_public_key(line).expect("should parse");
        assert_eq!(parsed.algo, "ssh-ed25519");
        assert!(parsed.fingerprint.starts_with("SHA256:"));
        assert_eq!(parsed.comment.as_deref(), Some("user@host"));
    }

    #[test]
    fn parse_key_no_comment() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxDPXFO8BFiTL6Z5XB9D1fBXaJPkPFDZI5y6d5X1234";
        let parsed = parse_public_key(line).expect("should parse");
        assert!(parsed.comment.is_none());
    }

    #[test]
    fn parse_empty_fails() {
        assert!(parse_public_key("").is_err());
    }

    #[test]
    fn parse_publickey_accept_rsyslog() {
        let line = "May 27 10:12:34 host sshd[1234]: Accepted publickey for parzival from 1.2.3.4 port 51234 ssh2: ED25519 SHA256:abcDEF123/xyz";
        assert_eq!(
            parse_publickey_accept(line),
            Some(ParsedAccept {
                fingerprint: "SHA256:abcDEF123/xyz",
                algo: "ED25519",
                user: "parzival",
                ip: "1.2.3.4",
            }),
        );
    }

    #[test]
    fn parse_publickey_accept_journald() {
        let line = "sshd[1234]: Accepted publickey for root from ::1 port 51234 ssh2: RSA SHA256:ZZZ";
        assert_eq!(
            parse_publickey_accept(line),
            Some(ParsedAccept {
                fingerprint: "SHA256:ZZZ",
                algo: "RSA",
                user: "root",
                ip: "::1",
            }),
        );
    }

    #[test]
    fn parse_publickey_accept_ignores_password() {
        let line = "sshd[1234]: Accepted password for parzival from 1.2.3.4 port 22 ssh2";
        assert_eq!(parse_publickey_accept(line), None);
    }

    #[test]
    fn parse_publickey_accept_ignores_failed() {
        let line = "sshd[1234]: Failed publickey for root from 1.2.3.4 port 22 ssh2: ED25519 SHA256:xyz";
        assert_eq!(parse_publickey_accept(line), None);
    }

    #[test]
    fn parse_publickey_accept_missing_fingerprint() {
        // sshd with LogLevel below VERBOSE — no fp in line.
        let line = "sshd[1234]: Accepted publickey for parzival from 1.2.3.4 port 22 ssh2";
        assert_eq!(parse_publickey_accept(line), None);
    }
}
