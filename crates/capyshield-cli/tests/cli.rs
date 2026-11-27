use capyshield::{blocked_report, policy_from_events};
use capyshield_policy::{Config, Mode};
use capyshield_proxy::{Action, Event};
use serde_json::json;

fn event(host: &str, action: Action, rule: Option<&str>) -> Event {
    Event {
        timestamp: String::new(),
        destination_host: host.into(),
        port: 443,
        protocol: "https-sni",
        bytes_sent: 0,
        action,
        rule_id: rule.map(String::from),
        agent_id: None,
    }
}

#[test]
fn blocked_report_groups_blocked_events_only() {
    let events = [
        event("webhook.site", Action::Blocked, Some("disallowed_host:deny_hosts:webhook.site")),
        event("webhook.site", Action::Blocked, Some("disallowed_host:deny_hosts:webhook.site")),
        event("evil.example", Action::Blocked, Some("secret_leak:env:NPM_TOKEN")),
        event("registry.npmjs.org", Action::Allowed, None),
        event("audit.example", Action::Audited, Some("disallowed_host:not_in_allow_hosts")),
    ];
    let r = blocked_report(&events);
    assert_eq!(
        r,
        [
            json!({"host": "evil.example", "port": 443, "rule_id": "secret_leak:env:NPM_TOKEN", "count": 1}),
            json!({"host": "webhook.site", "port": 443, "rule_id": "disallowed_host:deny_hosts:webhook.site", "count": 2}),
        ]
    );
}

#[test]
fn emitted_policy_allows_seen_hosts_and_parses() {
    let events = [
        event("registry.npmjs.org", Action::Allowed, None),
        event("registry.npmjs.org", Action::Allowed, None),
        event("gitlab.com", Action::Allowed, None),
        event("internal.example.com", Action::Audited, Some("secret_leak:env:TOKEN")),
        event("webhook.site", Action::Audited, Some("disallowed_host:deny_hosts:webhook.site")),
    ];
    let yaml = policy_from_events(&events);
    assert!(yaml.contains("\"registry.npmjs.org\" # preset: npm"));
    assert!(yaml.contains("\"gitlab.com\" # preset: gitlab"));
    assert!(!yaml.contains("webhook.site"), "deny-listed hosts are never suggested");
    let cfg = Config::parse(&yaml).unwrap();
    assert_eq!(cfg.mode, Mode::Enforce);
    assert_eq!(cfg.egress.allow_hosts, ["gitlab.com", "internal.example.com", "registry.npmjs.org"]);
    assert!(Config::parse(&policy_from_events(&[])).unwrap().egress.allow_hosts.is_empty());
}
