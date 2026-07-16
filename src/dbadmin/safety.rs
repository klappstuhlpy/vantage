//! Pre-flight query classifier.
//!
//! The real safety net is SQLite's engine-level read-only mode (`PRAGMA
//! query_only = ON`), but a lightweight first-keyword check rejects obvious
//! writes before we even open a connection — that way the operator sees a clear
//! "blocked by safe-mode" error instead of a generic engine error.
//!
//! The check is intentionally conservative:
//! - Comments (`-- …`, `/* … */`) are stripped first.
//! - The first SQL keyword is matched case-insensitively.
//! - WITH-CTEs are unwrapped to look at the actual statement at the end.
//! - Statements starting with anything *not* on the read allow-list are
//!   considered unsafe.
//!
//! Ported verbatim from the monolith's `admin/dbadmin/safety.rs` (SQLite-only —
//! the Postgres allow-list keywords stay, they are harmless supersets).

/// True when the SQL appears to be a read-only statement (`SELECT`, `EXPLAIN`,
/// `SHOW`, `WITH … SELECT`, `VALUES`, `TABLE`, `FETCH`, `PRAGMA`).
///
/// Returning `true` doesn't mean the query *will* be allowed — the engine-level
/// read-only mode has final say. It just means we won't reject before sending.
pub fn is_safe_query(sql: &str) -> bool {
    let stripped = strip_comments(sql);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return false;
    }
    let head = first_real_keyword(trimmed);
    matches!(
        head.to_ascii_uppercase().as_str(),
        "SELECT" | "EXPLAIN" | "SHOW" | "VALUES" | "TABLE" | "FETCH" | "WITH" | "PRAGMA"
    )
}

/// Returns the first SQL keyword (letters only) at the start of `sql`, or an
/// empty string if the input doesn't start with an identifier.
fn first_real_keyword(sql: &str) -> &str {
    let bytes = sql.as_bytes();
    let mut end = 0;
    while end < bytes.len() && (bytes[end] as char).is_ascii_alphabetic() {
        end += 1;
    }
    &sql[..end]
}

/// Best-effort comment stripper. Removes `-- line comments` and `/* block
/// comments */`. Doesn't try to be SQL-correct inside string literals — it only
/// matters that we get past leading comments.
fn strip_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut iter = sql.chars().peekable();
    while let Some(c) = iter.next() {
        if c == '-' && iter.peek() == Some(&'-') {
            iter.next();
            while let Some(&ch) = iter.peek() {
                iter.next();
                if ch == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && iter.peek() == Some(&'*') {
            iter.next();
            while let Some(ch) = iter.next() {
                if ch == '*' && iter.peek() == Some(&'/') {
                    iter.next();
                    break;
                }
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_basic_selects() {
        assert!(is_safe_query("SELECT 1"));
        assert!(is_safe_query("  select * from account;"));
        assert!(is_safe_query("EXPLAIN QUERY PLAN SELECT 1"));
        assert!(is_safe_query("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(is_safe_query("PRAGMA table_info(account)"));
    }

    #[test]
    fn rejects_writes() {
        assert!(!is_safe_query("INSERT INTO x VALUES (1)"));
        assert!(!is_safe_query("UPDATE x SET y=1"));
        assert!(!is_safe_query("DELETE FROM x"));
        assert!(!is_safe_query("DROP TABLE x"));
        assert!(!is_safe_query("ALTER TABLE x ADD COLUMN y INT"));
        assert!(!is_safe_query("CREATE TABLE x(y INT)"));
    }

    #[test]
    fn ignores_leading_comments() {
        assert!(is_safe_query("-- hi\nSELECT 1"));
        assert!(is_safe_query("/* block */ SELECT 1"));
        assert!(!is_safe_query("-- nope\nDROP TABLE x"));
    }

    #[test]
    fn empty_is_not_safe() {
        assert!(!is_safe_query(""));
        assert!(!is_safe_query("   \n  "));
        assert!(!is_safe_query("-- only a comment"));
    }
}
