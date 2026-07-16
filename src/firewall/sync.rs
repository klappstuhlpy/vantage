//! Live-ruleset import / reconciliation.
//!
//! The `firewall_rule` table is normally a one-way mirror: the UI writes
//! rows and we shell out to apply them. That means a host whose firewall was
//! configured out-of-band (e.g. someone ran `ufw allow OpenSSH` by hand)
//! shows an empty dashboard even though rules are live.
//!
//! [`sync_live`] closes that gap for ufw: on each dashboard load we dump the
//! live `ufw status`, parse it, and reconcile the parsed rules into the
//! mirror under a `{"source":"ufw",...}` marker. Rows we previously imported
//! that no longer appear live are pruned; hand-made UI rows (no marker) are
//! left untouched.
//!
//! Caveats (accepted):
//!   * A UI-created rule that's also live in ufw can appear twice — once as
//!     the UI row, once as an imported row.
//!   * Imported rows are a read-only reflection; deleting/toggling one in the
//!     UI may not map cleanly to a ufw delete and it will simply re-import on
//!     the next sync.
//!   * Only ufw is supported; nft/iptables imports return early.

use tracing::{info, warn};

use super::storage::{self, NewRule};
use crate::AppState;

/// A single parsed ufw rule plus the normalized signature used to dedupe it
/// against the mirror.
struct ParsedRule {
    rule: NewRule,
    /// Whitespace-normalized source line; the identity key for reconciliation.
    signature: String,
}

/// Read the live ufw ruleset and reconcile it into the `firewall_rule`
/// mirror. Best-effort: any failure (no backend, command error, parse miss)
/// is logged and swallowed so the dashboard still renders.
pub async fn sync_live(state: &AppState) {
    let Some(backend) = state.firewall_backend() else {
        info!("firewall sync: no backend configured, skipping");
        return;
    };
    info!(backend = %backend.kind.label(), "firewall sync: starting");

    // Only ufw exposes a stable, parsable status dump for now.
    let Some(argv) = backend.import_command() else {
        info!(backend = %backend.kind.label(), "firewall sync: backend has no import command, skipping");
        return;
    };

    info!(cmd = %crate::firewall::Backend::render(&argv), "firewall sync: running import command");
    let output = match backend.exec(argv).await {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            warn!(
                status = %o.status,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                stdout = %String::from_utf8_lossy(&o.stdout).trim(),
                "firewall sync: ufw status exited non-zero"
            );
            return;
        }
        Err(e) => {
            warn!(error = %e, "firewall sync: failed to run ufw status");
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!(raw_output = %stdout.trim(), "firewall sync: raw ufw output");
    let parsed = parse_ufw_status(&stdout);
    info!(count = parsed.len(), "firewall sync: parsed rules from ufw output");

    // What's currently in the mirror under our marker.
    let existing = match storage::list_imported_ufw(state).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "firewall sync: failed to list imported rules");
            return;
        }
    };
    info!(
        existing_count = existing.len(),
        "firewall sync: existing imported rows in DB"
    );

    // Map existing signature -> row id (extracted from the stored meta_json).
    let mut existing_by_sig: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for (id, meta) in &existing {
        if let Some(sig) = meta.as_deref().and_then(extract_signature) {
            existing_by_sig.insert(sig, *id);
        }
    }

    let live_sigs: std::collections::HashSet<&str> = parsed.iter().map(|p| p.signature.as_str()).collect();

    // Insert rules that are live but not yet mirrored.
    let mut inserted = 0usize;
    for p in &parsed {
        if existing_by_sig.contains_key(&p.signature) {
            continue;
        }
        info!(sig = %p.signature, "firewall sync: inserting new imported rule");
        let meta = serde_json::json!({ "source": "ufw", "raw": p.signature }).to_string();
        match storage::create_imported_rule(state, p.rule.clone(), meta).await {
            Ok(id) => {
                info!(id, sig = %p.signature, "firewall sync: inserted rule");
                inserted += 1;
            }
            Err(e) => warn!(error = %e, sig = %p.signature, "firewall sync: failed to insert imported rule"),
        }
    }

    // Prune imported rows whose signature no longer appears live.
    let mut pruned = 0usize;
    for (sig, id) in &existing_by_sig {
        if !live_sigs.contains(sig.as_str()) {
            info!(id, sig = %sig, "firewall sync: pruning stale imported rule");
            match storage::delete_rule(state, *id).await {
                Ok(_) => pruned += 1,
                Err(e) => warn!(error = %e, "firewall sync: failed to prune stale imported rule"),
            }
        }
    }

    info!(inserted, pruned, "firewall sync: done");
}

/// Pull the `"raw"` signature back out of a stored meta_json blob.
fn extract_signature(meta: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(meta).ok()?;
    v.get("raw")?.as_str().map(|s| s.to_string())
}

/// `(needle, action, direction)` — the action combos ufw prints, longest /
/// most-specific first so we match e.g. "ALLOW IN" before a hypothetical
/// "ALLOW".
const COMBOS: &[(&str, &str, &str)] = &[
    ("ALLOW IN", "allow", "in"),
    ("ALLOW OUT", "allow", "out"),
    ("ALLOW FWD", "allow", "any"),
    ("DENY IN", "deny", "in"),
    ("DENY OUT", "deny", "out"),
    ("DENY FWD", "deny", "any"),
    ("REJECT IN", "deny", "in"),
    ("REJECT OUT", "deny", "out"),
    ("LIMIT IN", "rate_limit", "in"),
    ("LIMIT OUT", "rate_limit", "out"),
];

/// Parse the output of `ufw status` (numbered or not) into rules.
fn parse_ufw_status(stdout: &str) -> Vec<ParsedRule> {
    let mut out = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip headers: "Status: active", the "To  Action  From" column row,
        // and the "--  ------  ----" underline.
        if line.starts_with("Status:") || line.starts_with("To ") || line.starts_with("--") {
            continue;
        }

        // Strip a leading "[ N]" numbered prefix if present.
        let line = strip_index_prefix(line);

        // Locate the earliest action combo in the line.
        let Some((combo, action, direction, idx)) = find_combo(line) else {
            continue;
        };

        let to_part = line[..idx].trim();
        let rest = line[idx + combo.len()..].trim();

        // The remainder is "<from>  # <comment>" (comment optional).
        let (from_part, comment) = match rest.split_once('#') {
            Some((f, c)) => (f.trim(), Some(c.trim().to_string())),
            None => (rest, None),
        };

        let (port, proto, profile_note) = parse_to(to_part);
        let source = if from_part.eq_ignore_ascii_case("Anywhere")
            || from_part.is_empty()
            || from_part.starts_with("Anywhere")
        {
            None
        } else {
            Some(from_part.to_string())
        };

        // Build a human note out of the profile name, the inline comment and
        // a "(v6)" marker.
        let mut note_parts: Vec<String> = Vec::new();
        if let Some(p) = profile_note {
            note_parts.push(p);
        }
        if let Some(c) = comment {
            note_parts.push(c);
        }
        if line.contains("(v6)") {
            note_parts.push("(v6)".to_string());
        }
        let note = if note_parts.is_empty() {
            None
        } else {
            Some(note_parts.join(" "))
        };

        let signature = normalize_ws(line);

        out.push(ParsedRule {
            rule: NewRule {
                action: action.to_string(),
                direction: direction.to_string(),
                proto,
                source,
                port,
                country: None,
                rate_per_s: None,
                note,
                enabled: true,
            },
            signature,
        });
    }
    out
}

/// Remove a leading `[ N]` / `[N]` index prefix from a ufw numbered line.
fn strip_index_prefix(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[end + 1..].trim_start();
        }
    }
    line
}

/// Find the first action combo present in the line, returning
/// `(combo_str, action, direction, byte_index)`.
fn find_combo(line: &str) -> Option<(&'static str, &'static str, &'static str, usize)> {
    let mut best: Option<(&'static str, &'static str, &'static str, usize)> = None;
    for (needle, action, direction) in COMBOS {
        if let Some(idx) = line.find(needle) {
            match best {
                Some((_, _, _, bi)) if bi <= idx => {}
                _ => best = Some((needle, action, direction, idx)),
            }
        }
    }
    best
}

/// Parse the "To" column into `(port, proto, profile_note)`.
fn parse_to(to: &str) -> (Option<i64>, String, Option<String>) {
    let to = to.replace("(v6)", "");
    let to = to.trim();
    if to.eq_ignore_ascii_case("Anywhere") || to.is_empty() {
        return (None, "any".to_string(), None);
    }
    // "3310/tcp" → port 3310, proto tcp.
    if let Some((num, proto)) = to.split_once('/') {
        if let Ok(p) = num.trim().parse::<i64>() {
            let proto = proto.trim().to_ascii_lowercase();
            let proto = if matches!(proto.as_str(), "tcp" | "udp") {
                proto
            } else {
                "any".to_string()
            };
            return (Some(p), proto, None);
        }
    }
    // A bare port number.
    if let Ok(p) = to.parse::<i64>() {
        return (Some(p), "any".to_string(), None);
    }
    // Otherwise it's an application profile name (e.g. "OpenSSH").
    (None, "any".to_string(), Some(format!("ufw: {to}")))
}

/// Collapse runs of whitespace to a single space.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numbered_status() {
        let sample = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 5432                       ALLOW IN    Anywhere
[ 3] 3310/tcp                   ALLOW IN    172.16.0.0/12              # clamd from docker
[ 4] OpenSSH (v6)               ALLOW IN    Anywhere (v6)
[ 5] 5432 (v6)                  ALLOW IN    Anywhere (v6)";
        let rules = parse_ufw_status(sample);
        assert_eq!(rules.len(), 5);

        // [1] OpenSSH profile → no port, note carries profile name.
        assert_eq!(rules[0].rule.action, "allow");
        assert_eq!(rules[0].rule.direction, "in");
        assert_eq!(rules[0].rule.port, None);
        assert_eq!(rules[0].rule.source, None);
        assert!(rules[0].rule.note.as_deref().unwrap().contains("OpenSSH"));

        // [2] bare port.
        assert_eq!(rules[1].rule.port, Some(5432));

        // [3] port/proto + CIDR source + comment.
        assert_eq!(rules[2].rule.port, Some(3310));
        assert_eq!(rules[2].rule.proto, "tcp");
        assert_eq!(rules[2].rule.source.as_deref(), Some("172.16.0.0/12"));
        assert!(rules[2].rule.note.as_deref().unwrap().contains("clamd"));

        // signatures are distinct per row.
        let sigs: std::collections::HashSet<_> = rules.iter().map(|r| r.signature.clone()).collect();
        assert_eq!(sigs.len(), 5);
    }

    #[test]
    fn skips_headers_and_blank_lines() {
        let sample = "Status: active\n\n     To  Action  From\n     --  ------  ----\n";
        assert!(parse_ufw_status(sample).is_empty());
    }

    #[test]
    fn parses_unnumbered_status() {
        let sample = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     DENY IN     203.0.113.5";
        let rules = parse_ufw_status(sample);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule.action, "deny");
        assert_eq!(rules[0].rule.port, Some(22));
        assert_eq!(rules[0].rule.proto, "tcp");
        assert_eq!(rules[0].rule.source.as_deref(), Some("203.0.113.5"));
    }
}
