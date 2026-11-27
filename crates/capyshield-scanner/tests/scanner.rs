use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use capyshield_policy::{Pii, Scan};
use capyshield_scanner::*;
use std::collections::BTreeSet;

fn scanner(env: &[(&str, &str)]) -> Scanner {
    let cfg = Scan {
        pii_patterns: vec![Pii::Email, Pii::CreditCard, Pii::Ssn, Pii::Nik, Pii::PrivateKey],
        ..Scan::default()
    };
    Scanner::new(&cfg, env.iter().map(|(k, v)| (k.to_string(), v.to_string())))
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn ids(s: &Scanner, data: &str) -> Vec<String> {
    s.scan(data.as_bytes()).into_iter().map(|f| f.rule_id()).collect()
}

#[test]
fn builtin_rules_compile_and_count() {
    scanner(&[]);
    assert!(RULES.len() >= 150, "only {} rules", RULES.len());
    let unique: BTreeSet<_> = RULES.iter().map(|r| r.0).collect();
    assert_eq!(unique.len(), RULES.len(), "duplicate rule ids");
}

#[test]
fn detects_known_formats() {
    let s = scanner(&[]);
    let cases = [
        ("key=AKIAIOSFODNN7EXAMPLE", "secret_leak:aws_access_key_id"),
        ("token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "secret_leak:github_pat"),
        ("x glpat-abcdefghij0123456789", "secret_leak:gitlab_pat"), // gitleaks:allow (fake fixture)
        ("sk_live_4eC39HqLyjWDarjtT1zdp7dc", "secret_leak:stripe_secret_key"), // gitleaks:allow (fake fixture)
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "secret_leak:private_key"),
        ("postgres://admin:hunter22@db.internal:5432/app", "secret_leak:postgres_uri"),
        ("AIzaSyA-1234567890abcdefghijklmnopqrstu", "secret_leak:gcp_api_key"), // gitleaks:allow (fake fixture)
    ];
    for (data, want) in cases {
        assert!(ids(&s, data).contains(&want.to_string()), "{data:?} -> {:?}", ids(&s, data));
    }
    let ant = format!("sk-ant-api03-{}", "A".repeat(93));
    assert!(ids(&s, &ant).contains(&"secret_leak:anthropic_api_key".into()));
    assert!(ids(&s, "hello world, nothing here").is_empty());
}

#[test]
fn env_fingerprints_in_all_encodings() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let s = scanner(&[
        ("AWS_SECRET_ACCESS_KEY", secret),
        ("PATH", "/usr/bin:/bin:/x/y"),
        ("SHORT_TOKEN", "abc"),
    ]);
    assert_eq!(s.env_fingerprint_count(), 1);
    let want = "secret_leak:env:AWS_SECRET_ACCESS_KEY".to_string();
    for enc in [
        secret.to_string(),
        STANDARD.encode(secret),
        url_encode(secret),
        hex::encode(secret),
        hex::encode_upper(secret),
    ] {
        assert!(ids(&s, &format!("payload={enc}&x=1")).contains(&want), "{enc}");
    }
    assert!(!ids(&s, "/usr/bin:/bin:/x/y").iter().any(|i| i.contains("env:")));
}

#[test]
fn pii_and_entropy() {
    let s = scanner(&[]);
    assert!(ids(&s, "card 4111 1111 1111 1111").contains(&"pii_detected:credit_card".into()));
    assert!(!ids(&s, "order 4111 1111 1111 1112").contains(&"pii_detected:credit_card".into()));
    assert!(ids(&s, "mail bob@example.com").contains(&"pii_detected:email".into()));
    assert!(ids(&s, "ssn 123-45-6789").contains(&"pii_detected:ssn".into()));
    assert!(ids(&s, "nik 3201011508900001").contains(&"pii_detected:nik".into()));
    assert!(s.scan_entropy("Zx81kQp0LmN2vB7cYt4rW9sJ3hG6fD5a").is_some());
    assert!(s.scan_entropy("npm/10.8.2 node/v22.11.0 darwin arm64").is_none());
    assert!(s.scan_entropy("sha512-Zx81kQp0LmN2vB7cYt4rW9sJ3hG6fD5a+Qq==").is_none());
}
