//! TOTP (RFC 6238) second-factor verification.
//!
//! The login-side subset of the site's `auth/totp.rs`: HOTP/TOTP code
//! verification (±1 step skew) and the ChaCha20-Poly1305 at-rest decryption of
//! the shared secret (keyed by the app [`SecretKey`], so a leaked `admin.db` or
//! backup does not expose usable 2FA secrets). Byte-identical to the site's
//! construction, so a secret enrolled there — or by a future Vantage
//! enrollment flow — verifies the same way.
//!
//! Enrollment (secret generation, QR provisioning, recovery codes) arrives with
//! the account-shell UI; only what the login path needs lives here.

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use kls_web_core::key::SecretKey;

type HmacSha1 = Hmac<Sha1>;

/// Number of digits in a generated code.
pub const DIGITS: u32 = 6;
/// Time step in seconds.
pub const STEP: u64 = 30;
/// How many steps of clock skew to tolerate on each side.
const SKEW: i64 = 1;

/// RFC 4226 HOTP for a given counter.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let bin = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    bin % 10u32.pow(digits)
}

fn format_code(value: u32, digits: u32) -> String {
    format!("{value:0width$}", width = digits as usize)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The current 6-digit code for a secret. Used by the (future) enrollment flow
/// and the login tests.
#[cfg_attr(not(test), allow(dead_code))]
pub fn current_code(secret: &[u8]) -> String {
    format_code(hotp(secret, now_unix() / STEP, DIGITS), DIGITS)
}

/// Verifies a user-supplied code against the secret, tolerating ±[`SKEW`] time
/// steps. Whitespace and separating spaces are ignored.
pub fn verify(secret: &[u8], code: &str) -> bool {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let base = (now_unix() / STEP) as i64;
    for delta in -SKEW..=SKEW {
        let counter = (base + delta).max(0) as u64;
        if format_code(hotp(secret, counter, DIGITS), DIGITS) == code {
            return true;
        }
    }
    false
}

/// Reverses [`encrypt_secret`]. Returns `None` on any decode/auth failure.
pub fn decrypt_secret(key: &SecretKey, stored: &str) -> Option<Vec<u8>> {
    let blob = STANDARD.decode(stored).ok()?;
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

/// Encrypts a secret with ChaCha20-Poly1305 (key = app secret key). Output is
/// `base64(nonce ‖ ciphertext)`. Used by the (future) enrollment flow and the
/// round-trip test; kept here so encrypt/decrypt stay in lock-step.
#[cfg_attr(not(test), allow(dead_code))]
pub fn encrypt_secret(key: &SecretKey, secret: &[u8]) -> anyhow::Result<String> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| anyhow::anyhow!("invalid cipher key length"))?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret)
        .map_err(|_| anyhow::anyhow!("TOTP secret encryption failed"))?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA-1, seed = ASCII "12345678901234567890").
    const SEED: &[u8] = b"12345678901234567890";

    fn code8_at(t: u64) -> String {
        format_code(hotp(SEED, t / STEP, 8), 8)
    }

    #[test]
    fn rfc6238_vectors() {
        assert_eq!(code8_at(59), "94287082");
        assert_eq!(code8_at(1111111109), "07081804");
        assert_eq!(code8_at(2000000000), "69279037");
    }

    #[test]
    fn verify_accepts_current_and_rejects_garbage() {
        // The code for the current step must verify; junk must not.
        let secret = b"a-shared-secret-1234";
        let code = format_code(hotp(secret, now_unix() / STEP, DIGITS), DIGITS);
        assert!(verify(secret, &code));
        assert!(verify(secret, &format!(" {code} ")));
        assert!(!verify(secret, "000000") || code == "000000");
        assert!(!verify(secret, "12"));
        assert!(!verify(secret, "abcdef"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip_and_wrong_key_fails() {
        let key = SecretKey::random().unwrap();
        let secret = b"top-secret-totp-seed";
        let blob = encrypt_secret(&key, secret).unwrap();
        assert_ne!(blob.as_bytes(), &secret[..]);
        assert_eq!(decrypt_secret(&key, &blob).unwrap(), secret.to_vec());
        let other = SecretKey::random().unwrap();
        assert!(decrypt_secret(&other, &blob).is_none());
    }
}
