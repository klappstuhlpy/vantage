//! Firewall backend abstraction — emits the raw shell commands needed to
//! apply / remove a [`FirewallRule`] for each of the three supported
//! backends.
//!
//! All three backends share one quirk: they need root or `sudo`. We assume
//! the process is running with `CAP_NET_ADMIN` (Docker `--cap-add=NET_ADMIN`
//! when host network is shared) or as root. When the binary is missing,
//! the [`Backend::Disabled`] variant is selected; rules are still persisted
//! but `apply` is a no-op so the UI keeps working in dev.
//!
//! ## Every applied rule is tagged with its Vantage id
//!
//! Each backend gets a comment carrying `vantage:<rule id>` (`comment "…"` for
//! nft and ufw, `-m comment --comment` for iptables). That tag is the rule's
//! identity on the host, and it exists because removal needs one:
//!
//! * **nftables cannot delete a rule by its match spec.** `nft delete rule`
//!   takes a *handle* and nothing else. The old code emitted
//!   `nft delete rule inet filter input ip saddr … drop`, which is not valid
//!   syntax — so on nftables, the default backend, deleting or disabling a rule
//!   removed it from the dashboard and left it live on the host, silently
//!   (both call sites discarded the error). [`Backend::remove`] now looks the
//!   handle up by tag via `nft -j list chain` and deletes that.
//! * iptables and ufw *can* delete by spec, and still do — but the tag has to
//!   match the one used at apply time or the delete finds nothing, so it is part
//!   of the spec for them too.
//!
//! The tag is also what makes a rule's presence on the host checkable at all,
//! which is what a revert timer will need.

use kls_agent::exec::{HostCommand, Tool};
use serde::{Deserialize, Serialize};

use super::storage::FirewallRule;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Nftables,
    Ufw,
    Iptables,
    Disabled,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::Nftables => "nftables",
            BackendKind::Ufw => "ufw",
            BackendKind::Iptables => "iptables",
            BackendKind::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "nft" | "nftables" => Some(BackendKind::Nftables),
            "ufw" => Some(BackendKind::Ufw),
            "iptables" | "ipt" => Some(BackendKind::Iptables),
            "disabled" | "off" | "none" => Some(BackendKind::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub kind: BackendKind,
    /// Optional `sudo`/`doas` prefix.
    pub elevation: Option<String>,
}

impl Backend {
    /// Probe the host: pick the first backend whose binary responds to its
    /// "are you alive" command.
    pub async fn detect(override_kind: Option<&str>) -> Self {
        let elevation = if which("sudo").await {
            Some("sudo".to_string())
        } else {
            None
        };

        if let Some(forced) = override_kind.and_then(BackendKind::parse) {
            return Backend {
                kind: forced,
                elevation,
            };
        }

        // Order matters: nftables is the modern default, ufw wraps either
        // nft or iptables, raw iptables is the legacy fallback.
        for kind in [BackendKind::Nftables, BackendKind::Ufw, BackendKind::Iptables] {
            if probe(kind).await {
                return Backend { kind, elevation };
            }
        }
        Backend {
            kind: BackendKind::Disabled,
            elevation,
        }
    }

    /// Generate the apply command for a single rule. Returns None for
    /// the disabled backend.
    pub fn apply_command(&self, rule: &FirewallRule) -> Option<Vec<String>> {
        match self.kind {
            BackendKind::Disabled => None,
            BackendKind::Ufw => Some(self.ufw_command(rule, false)),
            BackendKind::Iptables => Some(self.iptables_command(rule, "-A")),
            BackendKind::Nftables => Some(self.nft_command(rule, false)),
        }
    }

    /// Command that dumps the current live ruleset for import/sync.
    /// Only ufw is supported for now (its status output is stable and
    /// human-parsable); the others return None.
    pub fn import_command(&self) -> Option<Vec<String>> {
        match self.kind {
            BackendKind::Ufw => Some(self.wrap(vec!["ufw", "status", "numbered"])),
            _ => None,
        }
    }

    /// The tag written into every applied rule's comment: the rule's identity on
    /// the host, and the only way back from a live rule to the row that made it.
    pub fn tag(rule: &FirewallRule) -> String {
        format!("vantage:{}", rule.id)
    }

    /// Generate the matching remove command.
    ///
    /// `None` for nftables as well as for the disabled backend — nft has no
    /// delete-by-spec form at all, so there is no command to hand back here.
    /// Removing an nft rule needs a handle lookup first; use [`Backend::remove`],
    /// which is the path every caller should take anyway.
    pub fn remove_command(&self, rule: &FirewallRule) -> Option<Vec<String>> {
        match self.kind {
            BackendKind::Disabled | BackendKind::Nftables => None,
            BackendKind::Ufw => Some(self.ufw_command(rule, true)),
            BackendKind::Iptables => Some(self.iptables_command(rule, "-D")),
        }
    }

    /// Lists the live rules in the filter input chain as `(handle, comment)`.
    ///
    /// nftables only. Uses `-j` rather than parsing the human-readable dump: the
    /// text output is for people, the JSON output is the documented interface,
    /// and a firewall is the last place to guess at a regex.
    async fn nft_handles(&self) -> std::io::Result<Vec<(u64, String)>> {
        let argv = self.wrap(vec!["nft", "-j", "list", "chain", "inet", "filter", "input"]);
        let output = self.exec(argv).await?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "nft list chain exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(parse_nft_handles(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Removes a rule from the live ruleset.
    ///
    /// `Ok(false)` means the rule was not there to remove — which is not an
    /// error: a rule that was never applied, or was already removed by hand, is
    /// already in the state the caller wants.
    ///
    /// **Every** copy goes, not just the first. Apply is `add`/`-A`, which
    /// appends unconditionally, so a chain can hold several copies of one rule
    /// (see [`live_tags`](Self::live_tags) for how that is now avoided) — and a
    /// remove that took one of them away would report success over a rule that
    /// is still dropping packets.
    pub async fn remove(&self, rule: &FirewallRule) -> std::io::Result<bool> {
        if self.kind == BackendKind::Disabled {
            return Ok(false);
        }

        if self.kind == BackendKind::Nftables {
            let tag = Self::tag(rule);
            let handles: Vec<u64> = self
                .nft_handles()
                .await?
                .into_iter()
                .filter(|(_, c)| *c == tag)
                .map(|(h, _)| h)
                .collect();
            if handles.is_empty() {
                return Ok(false);
            }
            // Handles are stable identities, so deleting one does not renumber
            // the rest — they can be walked in one pass.
            for handle in &handles {
                let argv = self.wrap(vec![
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    "filter",
                    "input",
                    "handle",
                    &handle.to_string(),
                ]);
                self.run(argv).await?;
            }
            return Ok(true);
        }

        if self.kind == BackendKind::Iptables {
            // `-C` asks "is this rule there?", which is what makes the answer
            // trustworthy: a bare `-D` that fails cannot tell "it was not there"
            // (fine) from "the delete failed" (very much not fine), and both
            // exit 1. Loop, because `-D` removes one match at a time.
            let mut removed = false;
            while self
                .exec(self.iptables_command(rule, "-C"))
                .await
                .is_ok_and(|o| o.status.success())
            {
                self.run(self.iptables_command(rule, "-D")).await?;
                removed = true;
            }
            return Ok(removed);
        }

        let Some(argv) = self.remove_command(rule) else {
            return Ok(false);
        };
        // ufw: one shot, and a non-zero exit is a real failure. ufw answers a
        // delete for a rule it does not have with "Could not delete non-existent
        // rule" and exit 0, so the ambiguity iptables has does not arise.
        self.run(argv).await.map(|()| true)
    }

    /// The set of `vantage:*` tags currently live on the host, or `None` when the
    /// backend cannot be asked (everything but nftables today).
    ///
    /// `None` means "unknown", and callers must treat it as such rather than as
    /// "nothing is live".
    pub async fn live_tags(&self) -> Option<std::collections::HashSet<String>> {
        if self.kind != BackendKind::Nftables {
            return None;
        }
        self.nft_handles()
            .await
            .ok()
            .map(|rules| rules.into_iter().map(|(_, c)| c).collect())
    }

    /// Generate a stateful lockout block. Hot path: this runs synchronously
    /// from the audit-trigger pipeline so a brute-forcer is dropped before
    /// they finish their next request.
    pub fn lockout_command(&self, ip: &str, add: bool) -> Option<Vec<String>> {
        match self.kind {
            BackendKind::Disabled => None,
            BackendKind::Ufw => {
                // ufw insert needs a position; pin to 1 so blocks beat allowlists.
                if add {
                    Some(self.wrap(vec!["ufw", "insert", "1", "deny", "from", ip]))
                } else {
                    Some(self.wrap(vec!["ufw", "delete", "deny", "from", ip]))
                }
            }
            BackendKind::Iptables => {
                // -I inserts at the top for the same reason ufw pins to 1.
                let verb = if add { "-I" } else { "-D" };
                Some(self.wrap(vec![
                    "iptables",
                    verb,
                    "INPUT",
                    "-s",
                    ip,
                    "-m",
                    "comment",
                    "--comment",
                    &Self::lockout_tag(ip),
                    "-j",
                    "DROP",
                ]))
            }
            BackendKind::Nftables if add => {
                // `insert`, not `add`: nft's `add` appends to the end of the
                // chain, so a block would be evaluated *after* any earlier
                // accept rule and quietly never fire. ufw and iptables both pin
                // blocks to the top; this one used to be the odd one out, which
                // made an nft lockout a button that looked like it worked.
                Some(self.wrap(vec![
                    "nft",
                    "insert",
                    "rule",
                    "inet",
                    "filter",
                    "input",
                    "ip",
                    "saddr",
                    ip,
                    "drop",
                    "comment",
                    &Self::lockout_tag(ip),
                ]))
            }
            // Removal needs a handle. See `remove_lockout`.
            BackendKind::Nftables => None,
        }
    }

    /// The comment tag on a lockout rule — the same identity trick the numbered
    /// rules use, so a lockout can be found again and lifted.
    pub fn lockout_tag(ip: &str) -> String {
        format!("vantage:lockout:{ip}")
    }

    /// Adds or lifts a kernel block for `ip`, reporting what actually happened.
    ///
    /// `Ok(false)` means there was nothing to do: no backend command for this
    /// kind, or a lift for a block that is not there.
    pub async fn set_lockout(&self, ip: &str, add: bool) -> std::io::Result<bool> {
        if self.kind == BackendKind::Nftables && !add {
            let tag = Self::lockout_tag(ip);
            let Some((handle, _)) = self.nft_handles().await?.into_iter().find(|(_, c)| *c == tag) else {
                return Ok(false);
            };
            let argv = self.wrap(vec![
                "nft",
                "delete",
                "rule",
                "inet",
                "filter",
                "input",
                "handle",
                &handle.to_string(),
            ]);
            return self.run(argv).await.map(|()| true);
        }

        let Some(argv) = self.lockout_command(ip, add) else {
            return Ok(false);
        };
        self.run(argv).await.map(|()| true)
    }

    /// Runs a command and turns a non-zero exit into an error.
    ///
    /// [`exec`](Self::exec) returns `Ok` for a command that ran and *failed* —
    /// which is how "the rule was never removed" got reported as success at every
    /// call site in this module.
    async fn run(&self, argv: Vec<String>) -> std::io::Result<()> {
        let rendered = Self::render(&argv);
        let output = self.exec(argv).await?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "{rendered} → exit {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn ufw_command(&self, rule: &FirewallRule, remove: bool) -> Vec<String> {
        let mut argv: Vec<String> = vec!["ufw".to_string()];
        if remove {
            argv.push("delete".to_string());
        }
        match rule.action.as_str() {
            "allow" => argv.push("allow".to_string()),
            "deny" => argv.push("deny".to_string()),
            "rate_limit" => argv.push("limit".to_string()),
            "geo_block" => argv.push("deny".to_string()), // ufw has no geo; just deny source
            _ => argv.push("deny".to_string()),
        }
        if let Some(src) = rule.source.as_deref() {
            argv.push("from".to_string());
            argv.push(src.to_string());
        }
        if let Some(port) = rule.port {
            argv.push("to".to_string());
            argv.push("any".to_string());
            argv.push("port".to_string());
            argv.push(port.to_string());
        }
        match rule.proto.as_str() {
            "tcp" | "udp" => {
                argv.push("proto".to_string());
                argv.push(rule.proto.clone());
            }
            _ => {}
        }
        argv.push("comment".to_string());
        argv.push(Self::tag(rule));
        self.elevate(argv)
    }

    /// `verb` is `-A` (append), `-D` (delete) or `-C` (check). All three take the
    /// identical spec — that is the whole point of iptables' interface, and the
    /// reason the comment has to be part of the spec rather than a note on it.
    fn iptables_command(&self, rule: &FirewallRule, verb: &str) -> Vec<String> {
        let target = match rule.action.as_str() {
            "allow" => "ACCEPT",
            "rate_limit" => "ACCEPT",
            _ => "DROP",
        };
        let mut argv: Vec<String> = vec!["iptables".into(), verb.to_string(), "INPUT".into()];
        if let Some(src) = rule.source.as_deref() {
            argv.push("-s".into());
            argv.push(src.into());
        }
        match rule.proto.as_str() {
            "tcp" | "udp" => {
                argv.push("-p".into());
                argv.push(rule.proto.clone());
            }
            "icmp" => {
                argv.push("-p".into());
                argv.push("icmp".into());
            }
            _ => {}
        }
        if let Some(port) = rule.port {
            argv.push("--dport".into());
            argv.push(port.to_string());
        }
        if let Some(rps) = rule.rate_per_s {
            argv.push("-m".into());
            argv.push("limit".into());
            argv.push("--limit".into());
            argv.push(format!("{rps}/sec"));
        }
        // Part of the match spec, not decoration: iptables deletes by spec, and
        // a `-D` whose comment does not match the `-A` deletes nothing.
        argv.push("-m".into());
        argv.push("comment".into());
        argv.push("--comment".into());
        argv.push(Self::tag(rule));
        argv.push("-j".into());
        argv.push(target.into());
        self.elevate(argv)
    }

    fn nft_command(&self, rule: &FirewallRule, remove: bool) -> Vec<String> {
        let verb = if remove { "delete" } else { "add" };
        let action = match rule.action.as_str() {
            "allow" => "accept",
            "rate_limit" => "accept",
            _ => "drop",
        };
        let mut argv: Vec<String> = vec![
            "nft".into(),
            verb.into(),
            "rule".into(),
            "inet".into(),
            "filter".into(),
            "input".into(),
        ];
        if let Some(src) = rule.source.as_deref() {
            argv.push("ip".into());
            argv.push("saddr".into());
            argv.push(src.into());
        }
        match rule.proto.as_str() {
            "tcp" | "udp" => {
                argv.push(rule.proto.clone());
            }
            _ => {}
        }
        if let Some(port) = rule.port {
            argv.push("dport".into());
            argv.push(port.to_string());
        }
        if let Some(rps) = rule.rate_per_s {
            argv.push("limit".into());
            argv.push("rate".into());
            argv.push(format!("{rps}/second"));
        }
        argv.push(action.into());
        // The tag goes on `add` only: for nft there is no delete-by-spec form to
        // match it against, and the delete path finds the rule by this comment.
        if !remove {
            argv.push("comment".into());
            argv.push(Self::tag(rule));
        }
        self.elevate(argv)
    }

    fn wrap(&self, argv: Vec<&str>) -> Vec<String> {
        self.elevate(argv.into_iter().map(String::from).collect())
    }

    fn elevate(&self, mut argv: Vec<String>) -> Vec<String> {
        if let Some(prefix) = self.elevation.as_deref() {
            let mut out = vec![prefix.to_string(), "-n".to_string()];
            out.append(&mut argv);
            out
        } else {
            argv
        }
    }

    /// Convenience: render the argv as a single shell-friendly string for
    /// the UI's "Preview" feature and audit metadata.
    pub fn render(argv: &[String]) -> String {
        argv.iter()
            .map(|s| {
                if s.chars().any(char::is_whitespace) {
                    format!("'{}'", s.replace('\'', "'\\''"))
                } else {
                    s.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Runs a fully-assembled backend command through kls-agent's allowlisted
    /// executor — which refuses any program that is not a permitted host tool,
    /// so a malformed rule can never spawn something off the allowlist.
    pub async fn exec(&self, argv: Vec<String>) -> std::io::Result<std::process::Output> {
        Ok(HostCommand::from_argv(&argv)?.output().await?)
    }
}

/// Pulls `(handle, comment)` out of `nft -j list chain` output.
///
/// The shape is `{"nftables":[{"metainfo":…},{"rule":{"handle":4,"comment":"…"}}]}`.
/// Rules without a comment are skipped: they are not ours, and this function's
/// only job is to find the ones that are.
fn parse_nft_handles(json: &str) -> Vec<(u64, String)> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(items) = value.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let rule = item.get("rule")?;
            let handle = rule.get("handle")?.as_u64()?;
            let comment = rule.get("comment")?.as_str()?.to_string();
            Some((handle, comment))
        })
        .collect()
}

async fn probe(kind: BackendKind) -> bool {
    let (tool, sub): (Tool, &[&str]) = match kind {
        BackendKind::Nftables => (Tool::Nft, &["list", "tables"]),
        BackendKind::Ufw => (Tool::Ufw, &["status"]),
        BackendKind::Iptables => (Tool::Iptables, &["--version"]),
        BackendKind::Disabled => return false,
    };
    let output = HostCommand::new(tool).args(sub.iter().copied()).output().await;
    matches!(output, Ok(o) if o.status.success())
}

async fn which(bin: &str) -> bool {
    let Some(tool) = Tool::parse(bin) else {
        return false;
    };
    HostCommand::new(tool)
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn backend(kind: BackendKind) -> Backend {
        Backend { kind, elevation: None }
    }

    fn rule(id: i64) -> FirewallRule {
        FirewallRule {
            id,
            action: "deny".into(),
            direction: "in".into(),
            proto: "tcp".into(),
            source: Some("203.0.113.0/24".into()),
            port: Some(22),
            country: None,
            rate_per_s: None,
            note: None,
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            meta_json: None,
        }
    }

    /// The tag is what makes a live rule findable again. Without it on the
    /// `add`, nothing downstream can remove that rule — ever.
    #[test]
    fn every_backend_tags_the_rule_it_applies() {
        for kind in [BackendKind::Nftables, BackendKind::Ufw, BackendKind::Iptables] {
            let argv = backend(kind).apply_command(&rule(42)).expect("a command");
            assert!(
                argv.iter().any(|a| a == "vantage:42"),
                "{} applied a rule it could never find again: {:?}",
                kind.label(),
                argv
            );
        }
    }

    /// nft has no delete-by-spec form. Emitting one produced a command that
    /// always failed, and the failure was discarded — so the rule stayed live
    /// while the dashboard said it was gone.
    #[test]
    fn nftables_has_no_remove_command_because_nft_has_no_such_syntax() {
        assert!(backend(BackendKind::Nftables).remove_command(&rule(1)).is_none());
        // The two that *can* delete by spec still do.
        assert!(backend(BackendKind::Ufw).remove_command(&rule(1)).is_some());
        assert!(backend(BackendKind::Iptables).remove_command(&rule(1)).is_some());
        assert!(backend(BackendKind::Disabled).remove_command(&rule(1)).is_none());
    }

    /// iptables deletes by matching the spec, so `-D` has to be `-A` with the
    /// verb swapped — including the comment, or it matches nothing.
    #[test]
    fn the_iptables_delete_spec_mirrors_the_add_spec() {
        let b = backend(BackendKind::Iptables);
        let add = b.apply_command(&rule(7)).unwrap();
        let del = b.remove_command(&rule(7)).unwrap();
        assert_eq!(add.len(), del.len());
        for (a, d) in add.iter().zip(del.iter()) {
            if a == "-A" {
                assert_eq!(d, "-D");
            } else {
                assert_eq!(a, d, "the delete spec drifted from the add spec");
            }
        }
    }

    /// A block appended to the end of the chain is evaluated after any earlier
    /// accept — so it can silently never fire.
    #[test]
    fn a_lockout_is_inserted_at_the_top_not_appended() {
        let nft = backend(BackendKind::Nftables)
            .lockout_command("198.51.100.9", true)
            .unwrap();
        assert_eq!(nft[1], "insert", "nft `add` appends; a block must go first");
        assert!(nft.iter().any(|a| a == "vantage:lockout:198.51.100.9"));

        let ufw = backend(BackendKind::Ufw).lockout_command("198.51.100.9", true).unwrap();
        assert_eq!(ufw[1..3], ["insert", "1"]);

        let ipt = backend(BackendKind::Iptables)
            .lockout_command("198.51.100.9", true)
            .unwrap();
        assert_eq!(ipt[1], "-I");

        // Lifting an nft block needs a handle, so there is no bare command.
        assert!(backend(BackendKind::Nftables)
            .lockout_command("198.51.100.9", false)
            .is_none());
    }

    #[test]
    fn nft_handles_are_read_from_the_json_dump() {
        // Trimmed shape of `nft -j list chain inet filter input`.
        let json = r#"{"nftables":[
            {"metainfo":{"version":"1.0.6","json_schema_version":1}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,
                     "comment":"vantage:42","expr":[{"drop":null}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,
                     "expr":[{"accept":null}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":11,
                     "comment":"vantage:lockout:198.51.100.9","expr":[{"drop":null}]}}
        ]}"#;
        let handles = parse_nft_handles(json);
        // The un-commented rule is somebody else's and is not ours to touch.
        assert_eq!(
            handles,
            vec![
                (4, "vantage:42".to_string()),
                (11, "vantage:lockout:198.51.100.9".to_string())
            ]
        );
    }

    #[test]
    fn a_dump_that_cannot_be_parsed_yields_nothing_rather_than_panicking() {
        // Better a removal that reports "not found" than a worker that dies
        // mid-request holding a firewall change.
        assert!(parse_nft_handles("not json").is_empty());
        assert!(parse_nft_handles(r#"{"nftables":[]}"#).is_empty());
        assert!(parse_nft_handles(r#"{"something":"else"}"#).is_empty());
    }

    #[test]
    fn elevation_wraps_the_whole_command() {
        let b = Backend {
            kind: BackendKind::Nftables,
            elevation: Some("sudo".into()),
        };
        let argv = b.apply_command(&rule(1)).unwrap();
        assert_eq!(argv[0..2], ["sudo", "-n"]);
        assert_eq!(argv[2], "nft");
    }
}
