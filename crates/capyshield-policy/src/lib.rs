//! `capyshield.yaml` model, parser and validator.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

/// Named host groups for `egress.allow_presets`, from `presets.yaml`.
pub static PRESETS: LazyLock<BTreeMap<String, Vec<String>>> =
    LazyLock::new(|| serde_yaml::from_str(include_str!("presets.yaml")).expect("presets.yaml is valid"));

/// Starter config written by `capyshield init`.
pub const TEMPLATE: &str = r#"version: 1
mode: enforce # audit | enforce
fail_mode: fail_closed # fail_open | fail_closed

egress:
  tls_inspection: sni # sni | mitm (mitm needs the local CA from `capyshield init`)
  tls_bypass_hosts:
    - "*.apple.com"
  # Named host groups maintained with capyshield (see `capyshield presets`):
  #   npm, nodejs, github*, gitlab*, bitbucket*, chrome-for-testing*, python, pytorch, rust, go, docker, anthropic, openai
  #   (* serve user-uploaded content, so only add them if your build needs them)
  # Or run `capyshield watch --emit-policy capyshield.allow.yaml -- <build>` to list what your build uses.
  allow_presets: ["npm", "python", "openai"]
  allow_hosts: [] # extra hosts, e.g. a private registry: "npm.pkg.example.com"
  deny_hosts:
    - "*.ngrok-free.app"
    - "webhook.site"
  max_outbound_bytes: 131072 # 128 KB, applies to hosts outside allow_hosts
  scan:
    builtin_secret_patterns: true
    runtime_env_fingerprints: true
    env_include: [] # extra ENV names to fingerprint besides *KEY*/*SECRET*/*TOKEN*/*PASSWORD*
    env_exclude: ["PATH", "HOME", "PWD", "LANG"]
    high_entropy: true
    pii_patterns: ["credit_card", "private_key"] # also: email, ssn, nik
    # A secret may only travel to the hosts listed for it.
    secret_allow:
      OPENAI_API_KEY: ["api.openai.com"]

# Per-agent overrides, selected by the X-Agent-ID header or --agent-id.
agents: {}
#  coding-agent:
#    allow_hosts: ["api.anthropic.com"]
#    max_outbound_bytes: 65536

vex:
  ecosystems: ["node", "python"]
  exclude_paths: ["tests/**", "**/__tests__/**", "docs/**"]
  redact_paths: true
  local_rules_file: ".capyshield/vex-rules.yaml"
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspection {
    #[default]
    Sni,
    Mitm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pii {
    Email,
    CreditCard,
    Ssn,
    Nik,
    PrivateKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub version: u32,
    pub mode: Mode,
    pub fail_mode: FailMode,
    pub egress: Egress,
    pub agents: BTreeMap<String, AgentRules>,
    pub vex: Vex,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            mode: Mode::default(),
            fail_mode: FailMode::default(),
            egress: Egress::default(),
            agents: BTreeMap::new(),
            vex: Vex::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Egress {
    pub tls_inspection: TlsInspection,
    pub tls_bypass_hosts: Vec<String>,
    /// Names from `PRESETS`; expanded into `allow_hosts` when the config is parsed.
    pub allow_presets: Vec<String>,
    pub allow_hosts: Vec<String>,
    pub deny_hosts: Vec<String>,
    pub max_outbound_bytes: Option<u64>,
    pub scan: Scan,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scan {
    pub builtin_secret_patterns: bool,
    pub runtime_env_fingerprints: bool,
    pub env_include: Vec<String>,
    pub env_exclude: Vec<String>,
    pub high_entropy: bool,
    pub entropy_threshold: f64,
    pub pii_patterns: Vec<Pii>,
    /// Secret id (ENV name or builtin pattern id) -> hosts it may be sent to.
    pub secret_allow: BTreeMap<String, Vec<String>>,
}

impl Default for Scan {
    fn default() -> Self {
        Scan {
            builtin_secret_patterns: true,
            runtime_env_fingerprints: true,
            env_include: vec![],
            env_exclude: vec![],
            high_entropy: true,
            entropy_threshold: 4.2,
            pii_patterns: vec![Pii::CreditCard, Pii::PrivateKey],
            secret_allow: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentRules {
    /// Replaces the global allow list for this agent when set.
    pub allow_hosts: Option<Vec<String>>,
    /// Added to the global deny list.
    pub deny_hosts: Vec<String>,
    pub max_outbound_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Vex {
    pub ecosystems: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub redact_paths: bool,
    pub local_rules_file: String,
}

impl Default for Vex {
    fn default() -> Self {
        Vex {
            ecosystems: vec!["node".into(), "python".into()],
            exclude_paths: vec![],
            redact_paths: false,
            local_rules_file: ".capyshield/vex-rules.yaml".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg: Config = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        cfg.validate()?;
        for name in &cfg.egress.allow_presets {
            cfg.egress.allow_hosts.extend(PRESETS[name].iter().cloned());
        }
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported version {} (expected 1)", self.version));
        }
        let e = &self.egress;
        if let Some(p) = e.allow_presets.iter().find(|p| !PRESETS.contains_key(*p)) {
            let known: Vec<&str> = PRESETS.keys().map(String::as_str).collect();
            return Err(format!("unknown allow_presets entry {p:?} (available: {})", known.join(", ")));
        }
        let agent_hosts = self
            .agents
            .values()
            .flat_map(|a| a.allow_hosts.iter().flatten().chain(&a.deny_hosts));
        let secret_hosts = e.scan.secret_allow.values().flatten();
        for h in e
            .allow_hosts
            .iter()
            .chain(&e.deny_hosts)
            .chain(&e.tls_bypass_hosts)
            .chain(agent_hosts)
            .chain(secret_hosts)
        {
            let rest = h.strip_prefix("*.").unwrap_or(h);
            if h != "*" && (rest.is_empty() || rest.contains(['*', ' ', '/', ':'])) {
                return Err(format!("invalid host pattern {h:?} (use \"host\", \"*.domain\" or \"*\")"));
            }
        }
        let limits = e
            .max_outbound_bytes
            .iter()
            .chain(self.agents.values().filter_map(|a| a.max_outbound_bytes.as_ref()));
        if limits.into_iter().any(|&n| n == 0) {
            return Err("max_outbound_bytes must be > 0".into());
        }
        if !(0.0..=8.0).contains(&e.scan.entropy_threshold) {
            return Err("entropy_threshold must be between 0 and 8".into());
        }
        if let Some(eco) = self.vex.ecosystems.iter().find(|x| !matches!(x.as_str(), "node" | "python")) {
            return Err(format!("unsupported vex ecosystem {eco:?} (node, python)"));
        }
        Ok(())
    }
}

/// `*` matches everything, `*.example.com` matches subdomains, anything else is exact. Case-insensitive.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.');
    match pattern.strip_prefix("*.") {
        _ if pattern == "*" => true,
        Some(suffix) => {
            host.len() > suffix.len() + 1
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        }
        None => pattern.eq_ignore_ascii_case(host),
    }
}

pub fn any_host_matches(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| host_matches(p, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid() {
        let c = Config::parse(TEMPLATE).unwrap();
        assert_eq!(c.mode, Mode::Enforce);
        assert_eq!(c.egress.max_outbound_bytes, Some(131072));
        assert!(any_host_matches(&c.egress.allow_hosts, "files.pythonhosted.org"));
        assert!(!any_host_matches(&c.egress.allow_hosts, "github.com"));
        assert!(c.vex.redact_paths);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Config::parse("version: 2").is_err());
        assert!(Config::parse("bogus: 1").is_err());
        assert!(Config::parse("egress:\n  allow_hosts: ['a*b.com']").is_err());
        assert!(Config::parse("mode: yolo").is_err());
        assert!(
            Config::parse("egress:\n  allow_presets: ['nope']")
                .unwrap_err()
                .contains("available: anthropic")
        );
    }

    #[test]
    fn presets_are_valid_hosts() {
        let all: Vec<String> = PRESETS.values().flatten().cloned().collect();
        let mut c = Config::default();
        c.egress.allow_hosts = all;
        c.validate().unwrap();
        assert!(PRESETS.len() >= 11);
    }

    #[test]
    fn host_globs() {
        assert!(host_matches("*.apple.com", "gs.apple.com"));
        assert!(host_matches("*.apple.com", "A.B.Apple.COM."));
        assert!(!host_matches("*.apple.com", "apple.com"));
        assert!(!host_matches("*.apple.com", "evilapple.com"));
        assert!(host_matches("pypi.org", "PyPI.org"));
        assert!(!host_matches("pypi.org", "x.pypi.org"));
        assert!(host_matches("*", "anything"));
    }
}
