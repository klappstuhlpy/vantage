//! The account & security slice: password, second factor, sessions, sudo mode.
//!
//! This is the half of authentication the login path never needed. `session.rs`
//! answers "is this request signed in?"; this module answers everything an
//! operator does *about* their own identity once they are — change the password,
//! enroll or drop a second factor, see which sessions exist and cut one off, and
//! prove it is still them before a destructive action.
//!
//! ## Sudo mode
//!
//! A signed-in session is not automatically trusted to do the irreversible.
//! Sessions last 12 hours, and an unlocked laptop is a real threat model for a
//! box whose UI can stop your containers and rewrite your firewall. So the
//! destructive routes take [`Sudo`] instead of [`Account`]: same session, but it
//! must have re-authenticated within [`SUDO_WINDOW_MINUTES`]. The stamp lives on
//! the session row (`sudo_at`), so it is per-session and dies with it — signing
//! in elsewhere does not hand that browser a fresh sudo window.
//!
//! ## What is *not* here
//!
//! Passkeys. `webauthn-rs` has not landed in `kls-web-core`, and the account page
//! renders a placeholder for the section rather than pretending. When it lands,
//! credential CRUD joins this module and the reauth modal grows a third method.

pub mod routes;

use anyhow::Context;
use kls_web_core::Database;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::session::Account;

/// How long a re-authentication stays good for. Ten minutes is long enough to
/// carry out the batch of work you re-authenticated *for* (apply a ruleset, then
/// confirm it) and short enough that a walked-away-from browser is not a
/// standing grant.
pub const SUDO_WINDOW_MINUTES: i64 = 10;

/// How many recovery codes an enrollment mints.
const RECOVERY_CODE_COUNT: usize = 10;

/// Characters recovery codes are drawn from: Crockford base32 minus the
/// look-alikes (I/L/O/U are absent), so a code read off a printout and typed
/// back in cannot be ambiguous between 1/I/L or 0/O.
const RECOVERY_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Length of one recovery code, in characters. Ten characters over a 32-symbol
/// alphabet is 50 bits — far past anything guessable, which is what lets these
/// be stored as a plain digest (see sql/9.sql).
const RECOVERY_CODE_LEN: usize = 10;

// ─── Passwords ───────────────────────────────────────────────────────────────

/// The shortest password Vantage accepts.
///
/// Length is the only rule. Composition rules ("one uppercase, one symbol")
/// measurably push people toward `Password1!` and are not worth the theatre;
/// this account is protected by Argon2, a per-IP lockout, an optional second
/// factor, and — in the default posture — by not being reachable from the
/// internet at all.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Validates a proposed password. `Err` carries text meant for the operator.
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("Use at least {MIN_PASSWORD_LEN} characters."));
    }
    Ok(())
}

/// Replaces an account's password hash.
pub async fn set_password(db: &Database, account_id: i64, hash: String) -> anyhow::Result<()> {
    db.execute("UPDATE account SET password = ? WHERE id = ?", (hash, account_id))
        .await
        .context("could not update the password")?;
    Ok(())
}

// ─── Profile: the account name ───────────────────────────────────────────────

/// Bounds on the account name. It is the login identifier, not a display label,
/// so it has to stay something a person can type at a sign-in prompt on a
/// console with no clipboard.
pub const MIN_NAME_LEN: usize = 2;
pub const MAX_NAME_LEN: usize = 32;

/// Validates a proposed account name, returning the trimmed form to store.
///
/// Surrounding whitespace is trimmed rather than rejected — a name pasted with a
/// trailing space is a name whose owner cannot sign in and cannot see why.
/// Control characters are refused outright for the same reason.
pub fn validate_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    let len = name.chars().count();
    if len < MIN_NAME_LEN {
        return Err(format!("Use at least {MIN_NAME_LEN} characters."));
    }
    if len > MAX_NAME_LEN {
        return Err(format!("Use at most {MAX_NAME_LEN} characters."));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("That name contains a character that cannot be typed at a login prompt.".into());
    }
    Ok(name.to_owned())
}

/// Whether a rename collided with an existing account name.
pub struct NameTaken;

/// Renames an account. `Err(NameTaken)` when the name already belongs to someone
/// — enforced by the column's UNIQUE constraint rather than by a check-then-
/// write, which two concurrent renames could both pass.
pub async fn set_name(db: &Database, account_id: i64, name: &str) -> anyhow::Result<Result<(), NameTaken>> {
    let result = db
        .execute(
            "UPDATE account SET name = ? WHERE id = ?",
            (name.to_string(), account_id),
        )
        .await;
    match result {
        Ok(_) => Ok(Ok(())),
        // The pool erases the rusqlite error type, so the constraint is
        // recognised by its message. A UNIQUE violation is the only way this
        // statement fails on an already-validated name.
        Err(e) if e.to_string().to_lowercase().contains("unique") => Ok(Err(NameTaken)),
        Err(e) => Err(anyhow::Error::new(e).context("could not change the account name")),
    }
}

// ─── Profile: the avatar ─────────────────────────────────────────────────────

/// The largest avatar accepted. Generous for a picture rendered at 32px and
/// small enough that the row stays cheap to read and to back up.
pub const MAX_AVATAR_BYTES: usize = 256 * 1024;

/// Identifies an image by its leading bytes, or `None` if it is not one of the
/// three formats every browser renders.
///
/// The upload's own `Content-Type` is never consulted. This value is echoed back
/// as the `Content-Type` of `GET /account/avatar`, so trusting the client here
/// would let it serve `image/svg+xml` — a scriptable document — from Vantage's
/// own origin.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    // RIFF....WEBP — the four length bytes between the two tags are skipped.
    if bytes.len() > 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

/// Stores an avatar, replacing any previous one.
pub async fn set_avatar(db: &Database, account_id: i64, bytes: Vec<u8>, mime: &'static str) -> anyhow::Result<()> {
    db.execute(
        "UPDATE account SET avatar = ?, avatar_type = ? WHERE id = ?",
        (bytes, mime, account_id),
    )
    .await
    .context("could not save the picture")?;
    Ok(())
}

/// Removes an avatar, falling the UI back to the initial.
pub async fn clear_avatar(db: &Database, account_id: i64) -> anyhow::Result<()> {
    db.execute(
        "UPDATE account SET avatar = NULL, avatar_type = NULL WHERE id = ?",
        (account_id,),
    )
    .await
    .context("could not remove the picture")?;
    Ok(())
}

/// Reads an avatar back. `None` when the account has none.
///
/// Deliberately *not* carried on [`Account`]: that struct is loaded by the
/// extractor on every authenticated request, and dragging a quarter-megabyte of
/// image through every one of them to draw a 32px circle would be absurd. The
/// extractor loads `avatar_type` alone — enough to know whether to point an
/// `<img>` at this route.
pub async fn load_avatar(db: &Database, account_id: i64) -> Option<(Vec<u8>, String)> {
    db.get_row(
        "SELECT avatar, avatar_type FROM account WHERE id = ? AND avatar IS NOT NULL",
        (account_id,),
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .await
    .ok()
}

// ─── Sessions ────────────────────────────────────────────────────────────────

/// One row of the session list.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    /// The session id — the *unsigned* token payload, which is what the cookie
    /// carries before its `.hmac` suffix. Safe to hand to the page: possessing
    /// it without the signing key does not let you mint the cookie.
    pub id: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    /// True for the session making the request — the UI must never offer to
    /// revoke it under the same wording as the others.
    pub current: bool,
}

/// Lists an account's browser sessions, newest first, flagging `current_id`.
///
/// API keys (`api_key = 1`) are excluded: they are not sessions in any sense the
/// operator means when they ask "where am I signed in?", and they get their own
/// surface when that slice lands.
pub async fn list_sessions(db: &Database, account_id: i64, current_id: &str) -> anyhow::Result<Vec<SessionInfo>> {
    let current = current_id.to_owned();
    let rows = db
        .call(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, created_at, last_seen_at, user_agent, ip \
                 FROM session WHERE account_id = ? AND api_key = 0 \
                 ORDER BY created_at DESC",
            )?;
            let rows: rusqlite::Result<Vec<SessionInfo>> = stmt
                .query_map((account_id,), |row| {
                    let id: String = row.get(0)?;
                    Ok(SessionInfo {
                        current: id == current,
                        id,
                        created_at: row.get(1)?,
                        last_seen_at: row.get(2)?,
                        user_agent: row.get(3)?,
                        ip: row.get(4)?,
                    })
                })?
                .collect();
            rows
        })
        .await
        .context("could not read the session list")?;
    Ok(rows)
}

/// Names a session in the audit log without copying the whole id into it.
///
/// A session id is the signed cookie's payload. It is not enough to forge a
/// cookie on its own (that needs the HMAC, and so the signing key), but an audit
/// row outlives the session it names by ninety days, and there is no reason for
/// a long-lived table to hold a short-lived credential's full value. Eight
/// characters tell two rows apart, which is all the log needs to do.
pub fn session_label(session_id: &str) -> String {
    format!("session:{}", session_id.chars().take(8).collect::<String>())
}

/// Revokes one session belonging to `account_id`. Returns whether a row went.
///
/// The `account_id` clause is the whole point: without it this is an endpoint
/// that deletes any session id you can name.
pub async fn revoke_session(db: &Database, account_id: i64, session_id: &str) -> anyhow::Result<bool> {
    let affected = db
        .execute(
            "DELETE FROM session WHERE id = ? AND account_id = ? AND api_key = 0",
            (session_id.to_string(), account_id),
        )
        .await
        .context("could not revoke the session")?;
    Ok(affected > 0)
}

/// Revokes every session for `account_id` except `keep_id`. Returns the count.
///
/// Called on its own ("sign out everywhere") and after a password change, where
/// it is not a nicety: if the password was changed *because* it leaked, leaving
/// the thief's session alive defeats the exercise.
pub async fn revoke_other_sessions(db: &Database, account_id: i64, keep_id: &str) -> anyhow::Result<usize> {
    let affected = db
        .execute(
            "DELETE FROM session WHERE account_id = ? AND id != ? AND api_key = 0",
            (account_id, keep_id.to_string()),
        )
        .await
        .context("could not revoke the other sessions")?;
    Ok(affected)
}

/// Records provenance on a freshly minted session (best-effort).
///
/// Split from `session::save_session` rather than folded into it because it must
/// not be able to fail a login: a login that works but whose row says "unknown
/// device" is strictly better than a login that 500s because the User-Agent
/// header was strange.
pub async fn stamp_provenance(db: &Database, session_id: &str, ip: Option<String>, user_agent: Option<String>) {
    let _ = db
        .execute(
            "UPDATE session SET ip = ?, user_agent = ?, last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
             WHERE id = ?",
            (ip, user_agent, session_id.to_string()),
        )
        .await;
}

/// How stale `last_seen_at` may get before a request refreshes it.
const TOUCH_INTERVAL_SECONDS: i64 = 60;

/// Bumps `last_seen_at` for a session (best-effort), at most once a minute.
///
/// Called from the [`Account`] extractor, so it runs on every authenticated
/// request — hence the staleness clause in the WHERE rather than a read-then-
/// write. It is one write attempt that usually matches no rows, which is far
/// cheaper than the round trip it replaces, and "last seen" to the minute is all
/// the precision the session list can honestly claim anyway.
pub async fn touch_session(db: &Database, session_id: &str) {
    let _ = db
        .execute(
            "UPDATE session SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
             WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?))",
            (session_id.to_string(), format!("-{TOUCH_INTERVAL_SECONDS} seconds")),
        )
        .await;
}

// ─── Sudo stamps ─────────────────────────────────────────────────────────────

/// Marks a session as freshly re-authenticated.
pub async fn stamp_sudo(db: &Database, session_id: &str) -> anyhow::Result<()> {
    db.execute(
        "UPDATE session SET sudo_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
        (session_id.to_string(),),
    )
    .await
    .context("could not record the re-authentication")?;
    Ok(())
}

/// Whether a session's sudo stamp is inside [`SUDO_WINDOW_MINUTES`].
///
/// Evaluated in SQL against SQLite's clock rather than by parsing the stamp in
/// Rust, so the comparison uses the same clock and format that wrote it.
pub async fn has_sudo(db: &Database, session_id: &str) -> bool {
    db.get_row(
        "SELECT 1 FROM session \
         WHERE id = ? AND sudo_at IS NOT NULL AND sudo_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
        (session_id.to_string(), format!("-{SUDO_WINDOW_MINUTES} minutes")),
        |row| row.get::<_, i64>(0),
    )
    .await
    .is_ok()
}

/// Drops a session's sudo stamp — used when the thing it authorised is done, and
/// on password change (the old proof should not survive the credential).
pub async fn clear_sudo(db: &Database, account_id: i64) {
    let _ = db
        .execute("UPDATE session SET sudo_at = NULL WHERE account_id = ?", (account_id,))
        .await;
}

// ─── TOTP enrollment ─────────────────────────────────────────────────────────

/// Generates a 20-byte (160-bit) TOTP shared secret — the RFC 4226 recommended
/// size, and what every authenticator app expects from an otpauth URI.
pub fn generate_totp_secret() -> anyhow::Result<Vec<u8>> {
    let mut secret = vec![0u8; 20];
    getrandom::getrandom(&mut secret).context("could not generate a TOTP secret")?;
    Ok(secret)
}

/// RFC 4648 base32, uppercase, unpadded.
///
/// Hand-rolled rather than pulled in as a dependency: this is the only base32 in
/// the codebase, an otpauth URI is the only consumer, and the encoder is fifteen
/// lines. Padding is omitted because `otpauth://` secrets are conventionally
/// unpadded and every authenticator accepts that form.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        // Left-align the tail into the top of a 5-bit group, zero-filling.
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Builds the `otpauth://` provisioning URI an authenticator scans.
///
/// The label is `issuer:account` and `issuer` is *also* a query parameter —
/// belt-and-braces required by the de-facto Key URI Format, since some apps read
/// one and some the other, and an app that reads neither files the entry under a
/// bare username with no hint which machine it unlocks.
pub fn provisioning_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let label = urlencode(&format!("{issuer}:{account}"));
    let issuer_param = urlencode(issuer);
    let secret = base32_encode(secret);
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer_param}&algorithm=SHA1&digits={}&period={}",
        crate::totp::DIGITS,
        crate::totp::STEP,
    )
}

/// Percent-encodes everything outside the unreserved set.
///
/// Deliberately conservative — an account name is operator-chosen and may hold a
/// space, a colon or a `#`, each of which breaks the URI in its own way.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A QR code as a module matrix, ready for the client to draw.
///
/// The *encoding* is done here (there is no QR encoder in the browser bundle and
/// vendoring one to redo work the server already did would be silly), but the
/// drawing is not: handing back a bitmap or a blob of SVG markup would mean the
/// page either injects server HTML with `innerHTML` or renders a QR that ignores
/// the theme. A matrix is neither — the page builds one `<path>` from it with DOM
/// calls, in the current colours.
#[derive(Debug, Clone, Serialize)]
pub struct QrMatrix {
    /// Modules per side.
    pub width: usize,
    /// Row-major, `'1'` = dark. A string rather than a bool array because
    /// `width²` JSON booleans is ~30 KB of `true,` for a payload that is 1 KB
    /// this way.
    pub modules: String,
}

/// Encodes `data` as a QR matrix.
pub fn qr_matrix(data: &str) -> anyhow::Result<QrMatrix> {
    use qrcode::{Color, QrCode};

    let code = QrCode::new(data.as_bytes()).context("could not encode the QR code")?;
    let width = code.width();
    let modules = code
        .into_colors()
        .into_iter()
        .map(|c| if c == Color::Dark { '1' } else { '0' })
        .collect();
    Ok(QrMatrix { width, modules })
}

/// Stores a verified secret and turns the second factor on.
pub async fn enable_totp(db: &Database, account_id: i64, encrypted_secret: String) -> anyhow::Result<()> {
    db.execute(
        "UPDATE account SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
        (encrypted_secret, account_id),
    )
    .await
    .context("could not enable two-factor authentication")?;
    Ok(())
}

/// Turns the second factor off and forgets the secret.
///
/// The secret is nulled, not merely disabled: leaving a disabled-but-present
/// secret behind means "disable then re-enable" silently resurrects a factor the
/// operator may have disabled *because* it was compromised.
pub async fn disable_totp(db: &Database, account_id: i64) -> anyhow::Result<()> {
    db.execute(
        "UPDATE account SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
        (account_id,),
    )
    .await
    .context("could not disable two-factor authentication")?;
    clear_recovery_codes(db, account_id).await?;
    Ok(())
}

// ─── Recovery codes ──────────────────────────────────────────────────────────

/// Generates a fresh batch of recovery codes in plaintext.
pub fn generate_recovery_codes() -> anyhow::Result<Vec<String>> {
    (0..RECOVERY_CODE_COUNT).map(|_| generate_recovery_code()).collect()
}

fn generate_recovery_code() -> anyhow::Result<String> {
    let mut bytes = [0u8; RECOVERY_CODE_LEN];
    getrandom::getrandom(&mut bytes).context("could not generate a recovery code")?;
    // Rejection-free because 32 divides 256 evenly — `% 32` over uniform bytes
    // stays uniform, with no modulo bias to correct for.
    let code: String = bytes
        .iter()
        .map(|b| RECOVERY_ALPHABET[(*b as usize) % RECOVERY_ALPHABET.len()] as char)
        .collect();
    // Grouped for transcription: five characters is what a person can hold in
    // their head between glancing at the paper and hitting the keyboard.
    Ok(format!("{}-{}", &code[..5], &code[5..]))
}

/// Hashes a recovery code for storage/lookup, normalising how it was typed.
///
/// The separating dash is presentation, and case is not meaningful in the
/// alphabet, so both are stripped before hashing — otherwise a code typed
/// lowercase, or without the dash, is a valid code that does not work.
pub fn hash_recovery_code(code: &str) -> String {
    let normalised: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    format!("{:x}", Sha256::digest(normalised.as_bytes()))
}

/// Replaces an account's recovery codes with a fresh batch.
pub async fn store_recovery_codes(db: &Database, account_id: i64, codes: &[String]) -> anyhow::Result<()> {
    let hashes: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();
    db.call(move |conn| {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM recovery_code WHERE account_id = ?", (account_id,))?;
        {
            let mut stmt = tx.prepare("INSERT INTO recovery_code(account_id, code_hash) VALUES (?, ?)")?;
            for hash in &hashes {
                stmt.execute(rusqlite::params![account_id, hash])?;
            }
        }
        tx.commit()
    })
    .await
    .context("could not store the recovery codes")?;
    Ok(())
}

async fn clear_recovery_codes(db: &Database, account_id: i64) -> anyhow::Result<()> {
    db.execute("DELETE FROM recovery_code WHERE account_id = ?", (account_id,))
        .await
        .context("could not clear the recovery codes")?;
    Ok(())
}

/// How many unused recovery codes remain.
pub async fn recovery_codes_remaining(db: &Database, account_id: i64) -> i64 {
    db.get_row(
        "SELECT COUNT(*) FROM recovery_code WHERE account_id = ? AND used_at IS NULL",
        (account_id,),
        |row| row.get(0),
    )
    .await
    .unwrap_or(0)
}

/// Redeems a recovery code: true if it matched an unused one, which is then
/// spent. Single-use is enforced by the `used_at IS NULL` clause in the UPDATE,
/// so two racing requests with the same code cannot both win.
pub async fn redeem_recovery_code(db: &Database, account_id: i64, code: &str) -> bool {
    let hash = hash_recovery_code(code);
    db.execute(
        "UPDATE recovery_code SET used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE account_id = ? AND code_hash = ? AND used_at IS NULL",
        (account_id, hash),
    )
    .await
    .map(|affected| affected > 0)
    .unwrap_or(false)
}

// ─── Shared view helpers ─────────────────────────────────────────────────────

/// Second-factor state for the account page.
#[derive(Debug, Clone, Serialize)]
pub struct TotpStatus {
    pub enabled: bool,
    pub recovery_remaining: i64,
    pub recovery_total: usize,
}

pub async fn totp_status(db: &Database, account: &Account) -> TotpStatus {
    TotpStatus {
        enabled: account.has_totp(),
        recovery_remaining: recovery_codes_remaining(db, account.id).await,
        recovery_total: RECOVERY_CODE_COUNT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 §10, minus the padding we deliberately omit.
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn provisioning_uri_is_scannable_and_escapes_the_label() {
        let uri = provisioning_uri("Vantage", "root@box", b"12345678901234567890");
        assert!(uri.starts_with("otpauth://totp/Vantage%3Aroot%40box?"));
        // The secret must be base32 of the raw bytes — an app scanning this and
        // an app fed the same bytes must land on the same code.
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Vantage"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn a_generated_secret_produces_a_code_that_verifies() {
        // The point of the enrollment path: what we hand the authenticator and
        // what we later check a code against must be the same secret.
        let secret = generate_totp_secret().unwrap();
        assert_eq!(secret.len(), 20);
        let code = crate::totp::current_code(&secret);
        assert!(crate::totp::verify(&secret, &code));
    }

    #[test]
    fn recovery_codes_are_unique_and_hash_past_formatting() {
        let codes = generate_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODE_COUNT, "generated a duplicate code");

        for code in &codes {
            assert_eq!(code.len(), RECOVERY_CODE_LEN + 1, "expected XXXXX-XXXXX");
            assert!(!code.contains(['I', 'L', 'O', 'U']), "ambiguous character in {code}");
        }

        // Typed lowercase, without the dash, with a stray space — all the same code.
        let code = &codes[0];
        let hash = hash_recovery_code(code);
        assert_eq!(hash_recovery_code(&code.to_lowercase()), hash);
        assert_eq!(hash_recovery_code(&code.replace('-', "")), hash);
        assert_eq!(hash_recovery_code(&format!(" {code} ")), hash);
        assert_ne!(hash_recovery_code(&codes[1]), hash);
    }

    #[test]
    fn qr_matrix_is_square_and_dense() {
        let uri = provisioning_uri("Vantage", "admin", b"12345678901234567890");
        let qr = qr_matrix(&uri).unwrap();
        assert_eq!(qr.modules.len(), qr.width * qr.width);
        assert!(qr.modules.chars().all(|c| c == '0' || c == '1'));
        // A finder pattern alone guarantees dark modules; an all-light matrix
        // would mean we serialised the wrong thing.
        assert!(qr.modules.contains('1'));
    }

    #[test]
    fn a_name_is_trimmed_and_bounded() {
        assert_eq!(validate_name("  root  ").unwrap(), "root");
        assert_eq!(validate_name(&"a".repeat(MAX_NAME_LEN)).unwrap().len(), MAX_NAME_LEN);
        assert!(validate_name("a").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
        // A name that cannot be typed at a console login is not a name.
        assert!(validate_name("ro\not").is_err());
        assert!(validate_name("ro\tot").is_err());
    }

    #[test]
    fn only_real_browser_renderable_images_are_accepted() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\n\x00\x00"), Some("image/png"));
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"RIFF\x24\x00\x00\x00WEBPVP8 "), Some("image/webp"));

        // The one that matters: SVG is a scriptable document, and this response's
        // Content-Type comes from here.
        assert_eq!(sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\">"), None);
        assert_eq!(sniff_image(b"GIF89a"), None);
        assert_eq!(sniff_image(b""), None);
        // A truncated RIFF header must not index past the end.
        assert_eq!(sniff_image(b"RIFF\x24\x00\x00\x00WEB"), None);
    }

    #[test]
    fn password_policy_is_length_only() {
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"a".repeat(MIN_PASSWORD_LEN - 1)).is_err());
        assert!(validate_password(&"a".repeat(MIN_PASSWORD_LEN)).is_ok());
        // Counted in characters, not bytes: a 12-character passphrase of
        // multi-byte characters is 12 characters.
        assert!(validate_password("🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑").is_ok());
    }
}
