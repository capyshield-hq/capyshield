//! Trivy/Grype ingestion, reachability-based triage, local VEX rules and OpenVEX v0.2.0 output.

use capyshield_reach::{Ecosystem, Facts, Repo, Scope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPENVEX_CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub vulnerability: String,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    /// Lowercase: critical, high, medium, low, negligible, unknown.
    pub severity: String,
    pub ecosystem: Option<Ecosystem>,
    pub purl: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Justification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

/// A user-maintained triage decision (`.capyshield/vex-rules.yaml`, or pulled from the cloud).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub vulnerability: String,
    /// Package name or purl; omitted or `*` matches any package.
    #[serde(default)]
    pub package: Option<String>,
    pub status: Status,
    #[serde(default)]
    pub justification: Option<Justification>,
    #[serde(default)]
    pub impact_statement: Option<String>,
    #[serde(default)]
    pub action_statement: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analyzed {
    pub finding: Finding,
    pub facts: Option<Facts>,
    pub status: Status,
    pub justification: Option<Justification>,
    pub impact_statement: Option<String>,
    pub action_statement: Option<String>,
    /// `reachability`, `local_rule` or `cloud_rule`.
    pub decided_by: &'static str,
}

pub fn parse_rules(text: &str) -> Result<Vec<Rule>, String> {
    let file: RulesFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    for r in &file.rules {
        if r.status == Status::NotAffected && r.justification.is_none() && r.impact_statement.is_none() {
            return Err(format!(
                "rule for {}: not_affected needs a justification or impact_statement",
                r.vulnerability
            ));
        }
    }
    Ok(file.rules)
}

/// Parse a Trivy (`--format json`) or Grype (`-o json`) report. `scanner` = None auto-detects.
pub fn parse_report(text: &str, scanner: Option<&str>) -> Result<(&'static str, Vec<Finding>), String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let kind = match scanner {
        Some("trivy") => "trivy",
        Some("grype") => "grype",
        Some(other) => return Err(format!("unknown scanner {other:?} (trivy, grype)")),
        None if v.get("matches").is_some() => "grype",
        None if v.get("Results").is_some() || v.get("SchemaVersion").is_some() => "trivy",
        None => return Err("cannot detect scanner format; pass --scanner".into()),
    };
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut out = vec![];
    if kind == "trivy" {
        for result in v.get("Results").and_then(Value::as_array).into_iter().flatten() {
            let ty = s(result, "Type");
            for vuln in result.get("Vulnerabilities").and_then(Value::as_array).into_iter().flatten() {
                let purl = vuln.pointer("/PkgIdentifier/PURL").and_then(Value::as_str).map(str::to_string);
                out.push(finding(
                    s(vuln, "VulnerabilityID"),
                    s(vuln, "PkgName"),
                    s(vuln, "InstalledVersion"),
                    Some(s(vuln, "FixedVersion")),
                    s(vuln, "Severity"),
                    &ty,
                    purl,
                ));
            }
        }
    } else {
        for m in v.get("matches").and_then(Value::as_array).into_iter().flatten() {
            let (vuln, art) = (
                m.get("vulnerability").unwrap_or(&Value::Null),
                m.get("artifact").unwrap_or(&Value::Null),
            );
            let fixed = vuln
                .pointer("/fix/versions")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_string);
            let purl = art.get("purl").and_then(Value::as_str).map(str::to_string);
            out.push(finding(
                s(vuln, "id"),
                s(art, "name"),
                s(art, "version"),
                fixed,
                s(vuln, "severity"),
                &s(art, "type"),
                purl,
            ));
        }
    }
    out.retain(|f| !f.vulnerability.is_empty() && !f.package.is_empty());
    Ok((kind, out))
}

fn finding(
    vulnerability: String,
    package: String,
    version: String,
    fixed: Option<String>,
    severity: String,
    ty: &str,
    purl: Option<String>,
) -> Finding {
    let purl = purl.filter(|p| !p.is_empty());
    let ecosystem = match ty {
        "npm" | "yarn" | "pnpm" | "bun" | "node-pkg" => Some(Ecosystem::Node),
        "pip" | "pipenv" | "poetry" | "uv" | "python" | "python-pkg" | "conda-pkg" => Some(Ecosystem::Python),
        _ => match purl.as_deref() {
            Some(p) if p.starts_with("pkg:npm/") => Some(Ecosystem::Node),
            Some(p) if p.starts_with("pkg:pypi/") => Some(Ecosystem::Python),
            _ => None,
        },
    };
    let purl = purl.unwrap_or_else(|| match ecosystem {
        Some(Ecosystem::Node) => format!("pkg:npm/{}@{version}", package.replace('@', "%40")),
        Some(Ecosystem::Python) => format!("pkg:pypi/{}@{version}", capyshield_reach::pep503(&package)),
        None => format!("pkg:generic/{package}@{version}"),
    });
    let severity = if severity.is_empty() {
        "unknown".into()
    } else {
        severity.to_ascii_lowercase()
    };
    Finding {
        vulnerability,
        package,
        version,
        fixed_version: fixed.filter(|f| !f.is_empty()),
        severity,
        ecosystem,
        purl,
    }
}

/// Triage every finding: rules first (local before cloud), then reachability facts.
pub fn evaluate(findings: Vec<Finding>, repo: &Repo, local: &[Rule], cloud: &[Rule]) -> Vec<Analyzed> {
    let mut seen = BTreeMap::new();
    for f in findings {
        seen.entry((f.vulnerability.clone(), f.purl.clone())).or_insert(f);
    }
    seen.into_values()
        .map(|f| {
            let facts = f.ecosystem.map(|eco| repo.facts(eco, &f.package));
            let rule = [(local, "local_rule"), (cloud, "cloud_rule")]
                .into_iter()
                .find_map(|(rules, src)| rules.iter().find(|r| rule_matches(r, &f)).map(|r| (r, src)));
            if let Some((r, src)) = rule {
                let action = r
                    .action_statement
                    .clone()
                    .or_else(|| (r.status == Status::Affected).then(|| default_action(&f)));
                return Analyzed {
                    status: r.status,
                    justification: r.justification,
                    impact_statement: r.impact_statement.clone(),
                    action_statement: action,
                    decided_by: src,
                    facts,
                    finding: f,
                };
            }
            let (status, justification, impact) = match facts.as_ref() {
                None => (Status::UnderInvestigation, None, None),
                Some(x) => match (x.dependency_scope, x.imported_in_prod) {
                    (Scope::DevOnly, _) => (
                        Status::NotAffected,
                        Some(Justification::VulnerableCodeNotInExecutePath),
                        Some("Development-only dependency; not part of the production dependency graph.".to_string()),
                    ),
                    (Scope::Direct, false) => (
                        Status::NotAffected,
                        Some(Justification::VulnerableCodeNotInExecutePath),
                        Some("Declared dependency that no production source file imports (static import analysis).".to_string()),
                    ),
                    (Scope::Direct | Scope::Transitive, true) => (Status::Affected, None, None),
                    (Scope::Transitive | Scope::NotFound, false) => (Status::UnderInvestigation, None, None),
                    (Scope::NotFound, true) => (Status::Affected, None, None),
                },
            };
            let action = (status == Status::Affected).then(|| default_action(&f));
            Analyzed {
                status,
                justification,
                impact_statement: impact,
                action_statement: action,
                decided_by: "reachability",
                facts,
                finding: f,
            }
        })
        .collect()
}

fn rule_matches(r: &Rule, f: &Finding) -> bool {
    r.vulnerability.eq_ignore_ascii_case(&f.vulnerability)
        && r.package
            .as_deref()
            .is_none_or(|p| p == "*" || p.eq_ignore_ascii_case(&f.package) || p == f.purl)
}

fn default_action(f: &Finding) -> String {
    match &f.fixed_version {
        Some(v) => format!("Upgrade {} to {v} or later.", f.package),
        None => format!("No fixed version published; remove {} or mitigate its use.", f.package),
    }
}

pub fn status_notes(f: &Facts) -> String {
    format!(
        "capyshield reachability: in_lockfile={} dependency_scope={} imported_in_prod={} matched_files_count={}",
        f.in_lockfile,
        serde_json::to_value(f.dependency_scope).unwrap().as_str().unwrap(),
        f.imported_in_prod,
        f.matched_files_count
    )
}

/// OpenVEX v0.2.0 document. Deterministic for a given input and timestamp.
pub fn openvex(items: &[Analyzed], author: &str, timestamp: &str) -> Value {
    let statements: Vec<Value> = items
        .iter()
        .map(|a| {
            let mut s = json!({
                "vulnerability": { "name": a.finding.vulnerability },
                "products": [{ "@id": a.finding.purl }],
                "status": a.status,
            });
            let o = s.as_object_mut().unwrap();
            if let Some(j) = a.justification {
                o.insert("justification".into(), json!(j));
            }
            if let Some(i) = &a.impact_statement {
                o.insert("impact_statement".into(), json!(i));
            }
            if let Some(x) = &a.action_statement {
                o.insert("action_statement".into(), json!(x));
            }
            if let Some(f) = &a.facts {
                o.insert("status_notes".into(), json!(status_notes(f)));
            }
            s
        })
        .collect();
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&statements).unwrap()));
    json!({
        "@context": OPENVEX_CONTEXT,
        "@id": format!("urn:capyshield:vex:sha256:{digest}"),
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": concat!("capyshield/", env!("CARGO_PKG_VERSION")),
        "statements": statements,
    })
}

/// Deterministic path hash for `--redact-paths`.
pub fn redact(path: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(path.as_bytes())))
}

/// Number of `affected` findings whose severity is in `fail_on`.
pub fn violations(items: &[Analyzed], fail_on: &[String]) -> usize {
    items
        .iter()
        .filter(|a| a.status == Status::Affected && fail_on.iter().any(|s| s.eq_ignore_ascii_case(&a.finding.severity)))
        .count()
}

pub fn status_str(s: Status) -> &'static str {
    match s {
        Status::NotAffected => "not_affected",
        Status::Affected => "affected",
        Status::Fixed => "fixed",
        Status::UnderInvestigation => "under_investigation",
    }
}

pub fn markdown(items: &[Analyzed], redact_paths: bool) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for a in items {
        *counts.entry(status_str(a.status)).or_default() += 1;
    }
    let mut md = String::from("# CapyShield VEX summary\n\n");
    md += &format!(
        "{} findings: {}\n\n",
        items.len(),
        counts.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", ")
    );
    md += "| Vulnerability | Package | Severity | Status | Scope | Imported in prod | Files |\n|---|---|---|---|---|---|---|\n";
    for a in items {
        let (scope, imported, files) = match &a.facts {
            Some(f) => {
                let files: Vec<String> = f
                    .matched_files
                    .iter()
                    .take(3)
                    .map(|p| if redact_paths { redact(p) } else { format!("`{p}`") })
                    .collect();
                let more = f.matched_files.len().saturating_sub(3);
                let files = if more > 0 {
                    format!("{} (+{more})", files.join(", "))
                } else {
                    files.join(", ")
                };
                (
                    serde_json::to_value(f.dependency_scope).unwrap().as_str().unwrap().to_string(),
                    f.imported_in_prod.to_string(),
                    files,
                )
            }
            None => ("-".into(), "-".into(), String::new()),
        };
        md += &format!(
            "| {} | {}@{} | {} | {}{} | {scope} | {imported} | {files} |\n",
            a.finding.vulnerability,
            a.finding.package,
            a.finding.version,
            a.finding.severity,
            status_str(a.status),
            if a.decided_by == "reachability" { "" } else { " (rule)" },
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
