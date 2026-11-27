use capyshield_reach::{Ecosystem, Repo};
use capyshield_vex::*;

const TRIVY: &str = r#"{"SchemaVersion":2,"Results":[{"Target":"package-lock.json","Type":"npm","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","FixedVersion":"4.17.21","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.20"}},
    {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","FixedVersion":"4.17.21","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.20"}},
    {"VulnerabilityID":"CVE-2022-0001","PkgName":"@scope/ui","InstalledVersion":"1.0.0","Severity":"LOW"}]}]}"#;

#[test]
fn parses_trivy_and_grype() {
    let (kind, f) = parse_report(TRIVY, None).unwrap();
    assert_eq!((kind, f.len()), ("trivy", 3));
    assert_eq!(f[2].purl, "pkg:npm/%40scope/ui@1.0.0");
    let grype = r#"{"matches":[{"vulnerability":{"id":"GHSA-x","severity":"Critical","fix":{"versions":["2.0"]}},"artifact":{"name":"PyYAML","version":"5.3","type":"python"}}]}"#;
    let (kind, f) = parse_report(grype, None).unwrap();
    assert_eq!(
        (kind, f[0].ecosystem, f[0].purl.as_str(), f[0].severity.as_str()),
        ("grype", Some(Ecosystem::Python), "pkg:pypi/pyyaml@5.3", "critical")
    );
}

#[test]
fn rules_override_and_openvex_shape() {
    let (_, findings) = parse_report(TRIVY, Some("trivy")).unwrap();
    let rules = parse_rules("rules:\n  - vulnerability: cve-2022-0001\n    package: '@scope/ui'\n    status: not_affected\n    justification: inline_mitigations_already_exist\n").unwrap();
    let items = evaluate(findings, &Repo::default(), &rules, &[]);
    assert_eq!(items.len(), 2, "duplicates collapse");
    let ui = items.iter().find(|a| a.finding.package == "@scope/ui").unwrap();
    assert_eq!((ui.status, ui.decided_by), (Status::NotAffected, "local_rule"));
    let lodash = items.iter().find(|a| a.finding.package == "lodash").unwrap();
    assert_eq!(lodash.status, Status::UnderInvestigation); // not in this (empty) repo

    let doc = openvex(&items, "test", "2026-01-01T00:00:00Z");
    assert_eq!(doc["@context"], OPENVEX_CONTEXT);
    assert_eq!(doc["statements"].as_array().unwrap().len(), 2);
    assert_eq!(openvex(&items, "test", "2026-01-01T00:00:00Z")["@id"], doc["@id"], "deterministic");
    assert!(parse_rules("rules:\n  - vulnerability: X\n    status: not_affected\n").is_err());
}

#[test]
fn redaction_is_deterministic() {
    assert_eq!(redact("src/a.ts"), redact("src/a.ts"));
    assert!(redact("src/a.ts").starts_with("sha256:") && !redact("src/a.ts").contains("src"));
}
