use capyshield_policy::*;

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
fn team_egress_unions_into_local_policy() {
    let mut c = Config::parse("egress:\n  allow_hosts: ['npm.pkg.example.com']").unwrap();
    c.merge_team_egress(r#"{"allow_presets":["npm"],"allow_hosts":["api.example.com"],"deny_hosts":["webhook.site"]}"#)
        .unwrap();
    for h in ["npm.pkg.example.com", "registry.npmjs.org", "api.example.com"] {
        assert!(any_host_matches(&c.egress.allow_hosts, h), "{h}");
    }
    assert_eq!(c.egress.deny_hosts, ["webhook.site"]);
    let mut c = Config::default();
    assert!(c.merge_team_egress(r#"{"allow_hosts":["a*b.com"]}"#).is_err());
    assert!(c.merge_team_egress(r#"{"allow_presets":["nope"]}"#).is_err());
    assert!(c.merge_team_egress(r#"{"block_all":true}"#).is_err(), "unknown fields are rejected");
    assert!(c.egress.allow_hosts.is_empty(), "a rejected policy changes nothing");
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
