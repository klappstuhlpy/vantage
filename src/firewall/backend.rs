//! Firewall backend abstraction — emits the raw shell commands needed to
//! apply / remove a [`FirewallRule`] for each of the three supported
//! backends.
//!
//! All three backends share one quirk: they need root or `sudo`. We assume
//! the process is running with `CAP_NET_ADMIN` (Docker `--cap-add=NET_ADMIN`
//! when host network is shared) or as root. When the binary is missing,
//! the [`Backend::Disabled`] variant is selected; rules are still persisted
//! but `apply` is a no-op so the UI keeps working in dev.

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
            BackendKind::Iptables => Some(self.iptables_command(rule, false)),
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

    /// Generate the matching remove command.
    pub fn remove_command(&self, rule: &FirewallRule) -> Option<Vec<String>> {
        match self.kind {
            BackendKind::Disabled => None,
            BackendKind::Ufw => Some(self.ufw_command(rule, true)),
            BackendKind::Iptables => Some(self.iptables_command(rule, true)),
            BackendKind::Nftables => Some(self.nft_command(rule, true)),
        }
    }

    /// Generate a stateful lockout block. Hot path: this runs synchronously
    /// from the audit-trigger pipeline so a brute-forcer is dropped before
    /// they finish their next request.
    pub fn lockout_command(&self, ip: &str, add: bool) -> Option<Vec<String>> {
        let action = if add { "insert" } else { "delete" };
        match self.kind {
            BackendKind::Disabled => None,
            BackendKind::Ufw => {
                let verb = if add { "insert" } else { "delete" };
                // ufw insert needs a position; pin to 1 so blocks beat allowlists.
                if add {
                    Some(self.wrap(vec!["ufw", verb, "1", "deny", "from", ip]))
                } else {
                    Some(self.wrap(vec!["ufw", "delete", "deny", "from", ip]))
                }
            }
            BackendKind::Iptables => {
                let verb = if add { "-I" } else { "-D" };
                Some(self.wrap(vec!["iptables", verb, "INPUT", "-s", ip, "-j", "DROP"]))
            }
            BackendKind::Nftables => {
                // Requires a table/chain named "filter"/"input" — nft is happy
                // to no-op the delete if it isn't there.
                let _ = action;
                if add {
                    Some(self.wrap(vec![
                        "nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop",
                    ]))
                } else {
                    // The user has to know the handle to remove a single rule
                    // exactly; the cleaner approach is a named set. We delete
                    // by matching the source IP instead.
                    Some(self.wrap(vec![
                        "nft", "flush", "rule", "inet", "filter", "input", "ip", "saddr", ip,
                    ]))
                }
            }
        }
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
        self.elevate(argv)
    }

    fn iptables_command(&self, rule: &FirewallRule, remove: bool) -> Vec<String> {
        let verb = if remove { "-D" } else { "-A" };
        let target = match rule.action.as_str() {
            "allow" => "ACCEPT",
            "rate_limit" => "ACCEPT",
            _ => "DROP",
        };
        let mut argv: Vec<String> = vec!["iptables".into(), verb.into(), "INPUT".into()];
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
