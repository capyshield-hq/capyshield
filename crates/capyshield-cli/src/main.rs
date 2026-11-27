use capyshield::{blocked_report, policy_from_events};
use capyshield_policy::{Config, FailMode, Mode, TlsInspection};
use capyshield_proxy::{Action, Ca, Event, Guard};
use capyshield_scanner::Scanner;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_ERROR: u8 = 1;
const EXIT_EGRESS_VIOLATION: u8 = 2;
const EXIT_VULNERABLE: u8 = 3;

const VEX_RULES_TEMPLATE: &str = r#"# Local VEX triage decisions, committed with your repo. They take precedence over reachability analysis.
rules: []
#  - vulnerability: CVE-2024-12345
#    package: lodash            # name or purl; omit to match any package
#    status: not_affected       # not_affected | affected | fixed | under_investigation
#    justification: vulnerable_code_not_in_execute_path
#    impact_statement: "We never call _.template with user-controlled input."
"#;

#[derive(Parser)]
#[command(
    name = "capyshield",
    version,
    about = "Deterministic zero-trust egress guard and local VEX/reachability engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Zero-config egress audit: run a command and list every outbound destination
    Watch {
        /// Optional capyshield.yaml (mode is always forced to audit)
        #[arg(long)]
        config: Option<PathBuf>,
        /// TLS handling: sni (no decryption) or mitm (inspect HTTPS payloads with an ephemeral/local CA)
        #[arg(long)]
        tls: Option<String>,
        /// Write all connection events as JSON
        #[arg(long)]
        report: Option<PathBuf>,
        /// Write an enforce-mode capyshield.yaml whose allow_hosts are the hosts this run reached
        #[arg(long)]
        emit_policy: Option<PathBuf>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// List the host presets usable in egress.allow_presets
    Presets,
    /// Enforce capyshield.yaml egress policy on a command (exit 2 on blocked egress)
    Guard {
        /// Policy file (default: ./capyshield.yaml if present)
        #[arg(long)]
        config: Option<PathBuf>,
        /// audit | enforce | enforce_fail_open | enforce_fail_closed
        #[arg(long)]
        mode: Option<String>,
        /// fail_open | fail_closed
        #[arg(long)]
        fail_mode: Option<String>,
        /// sni | mitm
        #[arg(long)]
        tls: Option<String>,
        /// Agent identity for per-agent rules (the X-Agent-ID header wins when present)
        #[arg(long)]
        agent_id: Option<String>,
        /// Write all connection events as JSON
        #[arg(long)]
        report: Option<PathBuf>,
        /// Pull the team egress policy from and report blocked hosts to CapyShield Cloud (needs CAPYSHIELD_TOKEN)
        #[arg(long)]
        sync: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Triage a Trivy/Grype report with local reachability and emit OpenVEX JSON
    Vex {
        /// trivy | grype (auto-detected when omitted)
        #[arg(long)]
        scanner: Option<String>,
        /// Scanner JSON report
        #[arg(long)]
        input: PathBuf,
        /// Repository root to analyze
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// OpenVEX output file (stdout when omitted)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Also write a Markdown summary
        #[arg(long)]
        summary: Option<PathBuf>,
        /// Exit 3 when an affected finding has one of these severities, e.g. high,critical
        #[arg(long, value_delimiter = ',')]
        fail_on: Vec<String>,
        /// Replace file paths with sha256 hashes in reports and sync payloads
        #[arg(long)]
        redact_paths: bool,
        /// Pull team VEX rules from and push results to CapyShield Cloud (needs CAPYSHIELD_TOKEN)
        #[arg(long)]
        sync: bool,
        /// Print the exact sync payload instead of sending it
        #[arg(long)]
        dry_run: bool,
        /// Policy file (default: <repo>/capyshield.yaml if present)
        #[arg(long)]
        config: Option<PathBuf>,
        /// OpenVEX author
        #[arg(long, default_value = "capyshield")]
        author: String,
    },
    /// Write a capyshield.yaml template, .capyshield/vex-rules.yaml and a local root CA (~/.capyshield)
    Init {
        /// Overwrite an existing capyshield.yaml
        #[arg(long)]
        force: bool,
        /// Skip creating the local root CA
        #[arg(long)]
        no_ca: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("CAPYSHIELD_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let result = match Cli::parse().cmd {
        Cmd::Watch {
            config,
            tls,
            report,
            emit_policy,
            command,
        } => watch(config, tls, report, emit_policy, command).await,
        Cmd::Presets => {
            for (name, hosts) in capyshield_policy::PRESETS.iter() {
                println!("{name:<20} {}", hosts.join(", "));
            }
            Ok(0)
        }
        Cmd::Guard {
            config,
            mode,
            fail_mode,
            tls,
            agent_id,
            report,
            sync,
            command,
        } => guard(config, mode, fail_mode, tls, agent_id, report, sync, command).await,
        Cmd::Vex {
            scanner,
            input,
            repo,
            output,
            summary,
            fail_on,
            redact_paths,
            sync,
            dry_run,
            config,
            author,
        } => {
            vex(
                scanner,
                input,
                repo,
                output,
                summary,
                fail_on,
                redact_paths,
                sync,
                dry_run,
                config,
                author,
            )
            .await
        }
        Cmd::Init { force, no_ca } => init(force, no_ca),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{} {e}", "capyshield: error:".red().bold());
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Explicit path must load; otherwise `<dir>/capyshield.yaml` if present, else None.
fn load_config(explicit: Option<PathBuf>, dir: &Path) -> Result<Option<Config>, String> {
    match explicit {
        Some(p) => Config::load(&p).map(Some),
        None if dir.join("capyshield.yaml").exists() => Config::load(&dir.join("capyshield.yaml")).map(Some),
        None => Ok(None),
    }
}

fn parse_tls(tls: Option<String>, cfg: &mut Config) -> Result<(), String> {
    match tls.as_deref() {
        None => {}
        Some("sni") => cfg.egress.tls_inspection = TlsInspection::Sni,
        Some("mitm") => cfg.egress.tls_inspection = TlsInspection::Mitm,
        Some(x) => return Err(format!("--tls {x:?}: expected sni or mitm")),
    }
    Ok(())
}

async fn watch(
    config: Option<PathBuf>,
    tls: Option<String>,
    report: Option<PathBuf>,
    emit_policy: Option<PathBuf>,
    command: Vec<String>,
) -> Result<u8, String> {
    let mut cfg = load_config(config, Path::new("."))?.unwrap_or_default();
    cfg.mode = Mode::Audit;
    cfg.fail_mode = FailMode::FailOpen;
    parse_tls(tls, &mut cfg)?;
    run_guarded(cfg, None, report, emit_policy, None, command).await
}

#[allow(clippy::too_many_arguments)]
async fn guard(
    config: Option<PathBuf>,
    mode: Option<String>,
    fail_mode: Option<String>,
    tls: Option<String>,
    agent_id: Option<String>,
    report: Option<PathBuf>,
    sync: bool,
    command: Vec<String>,
) -> Result<u8, String> {
    // Without a policy file, guard still enforces the builtin secret/ENV/PII checks.
    let mut cfg = load_config(config, Path::new("."))?.unwrap_or_else(|| Config {
        mode: Mode::Enforce,
        ..Config::default()
    });
    match mode.as_deref() {
        None => {}
        Some("audit") => cfg.mode = Mode::Audit,
        Some("enforce") => cfg.mode = Mode::Enforce,
        Some("enforce_fail_open") => (cfg.mode, cfg.fail_mode) = (Mode::Enforce, FailMode::FailOpen),
        Some("enforce_fail_closed") => (cfg.mode, cfg.fail_mode) = (Mode::Enforce, FailMode::FailClosed),
        Some(x) => {
            return Err(format!(
                "--mode {x:?}: expected audit, enforce, enforce_fail_open or enforce_fail_closed"
            ));
        }
    }
    match fail_mode.as_deref() {
        None => {}
        Some("fail_open") => cfg.fail_mode = FailMode::FailOpen,
        Some("fail_closed") => cfg.fail_mode = FailMode::FailClosed,
        Some(x) => return Err(format!("--fail-mode {x:?}: expected fail_open or fail_closed")),
    }
    parse_tls(tls, &mut cfg)?;
    let cloud = if sync {
        let client = capyshield_sync::Client::from_env().ok_or("--sync needs CAPYSHIELD_TOKEN (or CAPYSHIELD_API_KEY)")?;
        let project = project_slug(Path::new("."));
        match client.pull_egress_policy(&project).await {
            Ok(t) => cfg.merge_team_egress(&t).map_err(|e| format!("cloud egress policy: {e}"))?,
            Err(e) => eprintln!("capyshield: could not pull the team egress policy ({e}); continuing with the local policy"),
        }
        Some((client, project))
    } else {
        None
    };
    run_guarded(cfg, agent_id, report, None, cloud, command).await
}

/// Repo directory name as a URL-safe project id.
fn project_slug(dir: &Path) -> String {
    let name = std::fs::canonicalize(dir)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "repo".into());
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '-' })
        .collect()
}

/// RFC 3339 UTC now, or SOURCE_DATE_EPOCH for reproducible output.
fn now_rfc3339() -> String {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .unwrap_or_else(time::OffsetDateTime::now_utc)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn ca_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".capyshield"))
        .ok_or_else(|| "HOME is not set".to_string())
}

fn load_or_ephemeral_ca() -> Result<Ca, String> {
    let dir = ca_dir()?;
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    if cert.exists() && key.exists() {
        let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
        return Ca::load(&read(&cert)?, &read(&key)?).map_err(|e| format!("local CA in {}: {e}", dir.display()));
    }
    eprintln!(
        "capyshield: no local CA found, using an ephemeral one (run `capyshield init` to create {})",
        cert.display()
    );
    Ca::generate().map_err(|e| e.to_string())
}

/// System trust store + our CA, for tools whose CA env var *replaces* the default bundle.
fn ca_bundle(ca_pem: &str) -> String {
    let system = std::env::var("SSL_CERT_FILE").ok().into_iter().chain(
        [
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/opt/homebrew/etc/openssl@3/cert.pem",
        ]
        .map(String::from),
    );
    let base = system.filter_map(|p| std::fs::read_to_string(p).ok()).next().unwrap_or_default();
    format!("{base}\n{ca_pem}")
}

async fn run_guarded(
    cfg: Config,
    agent_id: Option<String>,
    report: Option<PathBuf>,
    emit_policy: Option<PathBuf>,
    cloud: Option<(capyshield_sync::Client, String)>,
    command: Vec<String>,
) -> Result<u8, String> {
    let scanner = Scanner::new(&cfg.egress.scan, std::env::vars());
    let mitm = cfg.egress.tls_inspection == TlsInspection::Mitm;
    let ca = if mitm { Some(load_or_ephemeral_ca()?) } else { None };
    let tmp = std::env::temp_dir().join(format!("capyshield-{}", std::process::id()));
    let mut ca_env = vec![];
    if let Some(ca) = &ca {
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let (pem, bundle) = (tmp.join("ca.pem"), tmp.join("bundle.pem"));
        std::fs::write(&pem, &ca.cert_pem)
            .and_then(|_| std::fs::write(&bundle, ca_bundle(&ca.cert_pem)))
            .map_err(|e| e.to_string())?;
        ca_env.push(("NODE_EXTRA_CA_CERTS", pem));
        for k in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "PIP_CERT",
            "GIT_SSL_CAINFO",
            "AWS_CA_BUNDLE",
            "CARGO_HTTP_CAINFO",
            "DENO_CERT",
        ] {
            ca_env.push((k, bundle.clone()));
        }
    }
    let (mode, fail_mode) = (cfg.mode, cfg.fail_mode);
    let fingerprints = scanner.env_fingerprint_count();
    let guard = Guard::new(cfg, scanner, ca, agent_id);
    let addr = match guard.listen(([127, 0, 0, 1], 0).into()).await {
        Ok(a) => Some(a),
        Err(e) if fail_mode == FailMode::FailOpen || mode == Mode::Audit => {
            eprintln!("capyshield: proxy failed to start ({e}); fail_open: running the command UNGUARDED");
            None
        }
        Err(e) => return Err(format!("proxy failed to start: {e} (fail_closed)")),
    };

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    // The Cloud token is ours alone: install scripts and agents never see it.
    for k in capyshield_sync::TOKEN_VARS {
        cmd.env_remove(k);
    }
    if let Some(addr) = addr {
        let url = format!("http://{addr}");
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            cmd.env(k, &url);
        }
        cmd.env("NO_PROXY", "localhost,127.0.0.1,::1")
            .env("no_proxy", "localhost,127.0.0.1,::1");
        cmd.envs(ca_env);
        eprintln!(
            "{} {} mode, {} TLS, {fingerprints} sensitive ENV value(s) fingerprinted, proxy {url}",
            "capyshield:".cyan().bold(),
            if mode == Mode::Enforce { "enforce" } else { "audit" },
            if mitm { "mitm" } else { "sni" },
        );
    }
    // Ctrl-C reaches the child through the process group; we stay alive to print the summary.
    tokio::spawn(async {
        loop {
            let _ = tokio::signal::ctrl_c().await;
        }
    });
    let status = cmd.status().await.map_err(|e| format!("{}: {e}", command[0]))?;
    let _ = std::fs::remove_dir_all(&tmp);

    let events = guard.events();
    print_events(&events, mitm);
    if let Some((client, project)) = cloud {
        let blocked = blocked_report(&events);
        let n: usize = blocked.iter().map(|r| r["count"].as_u64().unwrap_or(0) as usize).sum();
        let payload = json!({
            "project": project, "generated_at": now_rfc3339(),
            "cli_version": env!("CARGO_PKG_VERSION"), "blocked": blocked,
        });
        match client.push_egress_report(&payload).await {
            Ok(_) => eprintln!("capyshield: synced {n} blocked connection(s) to CapyShield Cloud"),
            Err(e) => eprintln!("capyshield: could not report blocked hosts to CapyShield Cloud ({e})"),
        }
    }
    if let Some(path) = report {
        let body = serde_json::to_string_pretty(&json!({ "events": events })).unwrap();
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if let Some(path) = emit_policy {
        std::fs::write(&path, policy_from_events(&events)).map_err(|e| format!("{}: {e}", path.display()))?;
        eprintln!(
            "{} wrote {} (review it, then: capyshield guard --config {} -- ...)",
            "capyshield:".cyan().bold(),
            path.display(),
            path.display()
        );
    }
    if events.iter().any(|e| e.action == Action::Blocked) {
        return Ok(EXIT_EGRESS_VIOLATION);
    }
    Ok(status.code().map_or(EXIT_ERROR, |c| c.clamp(0, 255) as u8))
}

fn human_bytes(n: u64) -> String {
    match n {
        0..1024 => format!("{n} B"),
        1024..1_048_576 => format!("{:.1} KB", n as f64 / 1024.0),
        _ => format!("{:.1} MB", n as f64 / 1_048_576.0),
    }
}

/// (host, port, protocol, action, rule) -> (connections, bytes sent)
type EventRows<'a> = BTreeMap<(String, u16, &'a str, &'a str, String), (usize, u64)>;

fn print_events(events: &[Event], mitm: bool) {
    let mut rows = EventRows::new();
    for e in events {
        let action = match e.action {
            Action::Allowed => "allowed",
            Action::Blocked => "blocked",
            Action::Audited => "audited",
        };
        let row = rows
            .entry((
                e.destination_host.clone(),
                e.port,
                e.protocol,
                action,
                e.rule_id.clone().unwrap_or_default(),
            ))
            .or_default();
        row.0 += 1;
        row.1 += e.bytes_sent;
    }
    eprintln!();
    if rows.is_empty() {
        eprintln!("{} no outbound connections", "capyshield:".cyan().bold());
        return;
    }
    let w = rows.keys().map(|k| k.0.len() + 6).max().unwrap_or(20).max(20);
    eprintln!(
        "{}",
        format!(
            "{:<8} {:<w$} {:<10} {:>5} {:>10}  RULE",
            "ACTION", "DESTINATION", "PROTOCOL", "CONNS", "SENT"
        )
        .bold()
    );
    for ((host, port, proto, action, rule), (count, bytes)) in &rows {
        let a = match *action {
            "blocked" => action.red().bold(),
            "audited" => action.yellow().bold(),
            _ => action.green(),
        };
        eprintln!(
            "{a:<8} {:<w$} {proto:<10} {count:>5} {:>10}  {rule}",
            format!("{host}:{port}"),
            human_bytes(*bytes)
        );
    }
    let hosts: std::collections::BTreeSet<_> = events.iter().map(|e| &e.destination_host).collect();
    eprintln!(
        "{} {} connection(s) to {} host(s)",
        "capyshield:".cyan().bold(),
        events.len(),
        hosts.len()
    );
    for e in events
        .iter()
        .filter(|e| e.rule_id.as_deref().is_some_and(|r| r.starts_with("secret_leak:env:")))
    {
        let name = e.rule_id.as_deref().unwrap().trim_start_matches("secret_leak:env:");
        eprintln!(
            "{} sensitive ENV value {} appeared in an outbound request to {} ({:?})",
            "WARNING:".red().bold(),
            name.bold(),
            e.destination_host,
            e.action
        );
    }
    if !mitm && events.iter().any(|e| e.protocol == "https-sni") {
        eprintln!(
            "{} HTTPS payloads were not decrypted; use --tls mitm to scan them for secrets",
            "note:".dimmed()
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn vex(
    scanner: Option<String>,
    input: PathBuf,
    repo: PathBuf,
    output: Option<PathBuf>,
    summary: Option<PathBuf>,
    fail_on: Vec<String>,
    redact_paths: bool,
    sync: bool,
    dry_run: bool,
    config: Option<PathBuf>,
    author: String,
) -> Result<u8, String> {
    let cfg = load_config(config, &repo)?.unwrap_or_default();
    let text = std::fs::read_to_string(&input).map_err(|e| format!("{}: {e}", input.display()))?;
    let (kind, findings) = capyshield_vex::parse_report(&text, scanner.as_deref())?;
    let analysis = capyshield_reach::analyze(&repo, &cfg.vex.exclude_paths, &cfg.vex.ecosystems)?;
    let rules_path = repo.join(&cfg.vex.local_rules_file);
    let local_rules = match std::fs::read_to_string(&rules_path) {
        Ok(t) => capyshield_vex::parse_rules(&t).map_err(|e| format!("{}: {e}", rules_path.display()))?,
        Err(_) => vec![],
    };
    let redact = redact_paths || cfg.vex.redact_paths;
    let name = std::fs::canonicalize(&repo)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "repo".into());
    let project = if redact {
        capyshield_vex::redact(&name)
    } else {
        project_slug(&repo)
    };

    let client = if sync && !dry_run {
        Some(capyshield_sync::Client::from_env().ok_or("--sync needs CAPYSHIELD_TOKEN (or CAPYSHIELD_API_KEY); use --dry-run to preview")?)
    } else {
        None
    };
    let cloud_rules = match &client {
        Some(c) => match c.pull_vex_rules(&project).await {
            Ok(t) => capyshield_vex::parse_rules(&t).map_err(|e| format!("cloud rules: {e}"))?,
            Err(e) => {
                eprintln!("capyshield: could not pull cloud VEX rules ({e}); continuing with local rules");
                vec![]
            }
        },
        None => vec![],
    };

    let items = capyshield_vex::evaluate(findings, &analysis, &local_rules, &cloud_rules);
    let ts = now_rfc3339();
    let doc = capyshield_vex::openvex(&items, &author, &ts);
    let doc_text = serde_json::to_string_pretty(&doc).unwrap();
    match &output {
        Some(p) => std::fs::write(p, &doc_text).map_err(|e| format!("{}: {e}", p.display()))?,
        None if !dry_run => println!("{doc_text}"),
        None => {}
    }
    let md = capyshield_vex::markdown(&items, redact);
    if let Some(p) = &summary {
        std::fs::write(p, &md).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    print_vex_summary(kind, &items, analysis.files_scanned, output.as_deref());

    if sync || dry_run {
        let facts: Vec<_> = items
            .iter()
            .map(|a| {
                let mut v = json!({
                    "vulnerability": a.finding.vulnerability, "purl": a.finding.purl, "severity": a.finding.severity,
                    "status": a.status, "decided_by": a.decided_by,
                });
                if let Some(f) = &a.facts {
                    let files: Vec<String> = f
                        .matched_files
                        .iter()
                        .map(|p| if redact { capyshield_vex::redact(p) } else { p.clone() })
                        .collect();
                    v["reachability"] = json!({ "facts": f, "matched_files": files });
                }
                v
            })
            .collect();
        let payload = json!({
            "project": project, "scanner": kind, "generated_at": ts,
            "cli_version": env!("CARGO_PKG_VERSION"), "openvex": doc, "findings": facts,
        });
        let size = capyshield_sync::check_size(&payload).map_err(|e| e.to_string())?.len();
        if dry_run {
            eprintln!("capyshield: --dry-run, this exact payload ({size} bytes) would be sent:");
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        } else if let Some(c) = &client {
            c.push_vex(&payload).await.map_err(|e| format!("sync failed: {e}"))?;
            eprintln!("capyshield: synced {} statements ({size} bytes) to CapyShield Cloud", items.len());
        }
    }

    let bad = capyshield_vex::violations(&items, &fail_on);
    if bad > 0 {
        eprintln!(
            "{} {bad} affected finding(s) at severity {}",
            "capyshield: FAIL".red().bold(),
            fail_on.join(",")
        );
        return Ok(EXIT_VULNERABLE);
    }
    Ok(0)
}

fn print_vex_summary(kind: &str, items: &[capyshield_vex::Analyzed], files: usize, output: Option<&Path>) {
    use capyshield_vex::{Status, status_str};
    let count = |s: Status| items.iter().filter(|a| a.status == s).count();
    eprintln!(
        "{} {} {kind} finding(s), {files} source file(s) analyzed: {} affected, {} not_affected, {} under_investigation, {} fixed",
        "capyshield:".cyan().bold(),
        items.len(),
        count(Status::Affected).to_string().red().bold(),
        count(Status::NotAffected).to_string().green().bold(),
        count(Status::UnderInvestigation).to_string().yellow(),
        count(Status::Fixed),
    );
    for a in items.iter().filter(|a| a.status == Status::Affected) {
        let files = a.facts.as_ref().map_or(0, |f| f.matched_files_count);
        eprintln!(
            "  {} {} {}@{} ({}, imported in {files} file(s))",
            status_str(a.status).red(),
            a.finding.vulnerability,
            a.finding.package,
            a.finding.version,
            a.finding.severity
        );
    }
    if let Some(p) = output {
        eprintln!("{} wrote {}", "capyshield:".cyan().bold(), p.display());
    }
}

fn write_new(path: &Path, body: &str, force: bool) -> Result<bool, String> {
    if path.exists() && !force {
        return Ok(false);
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

fn init(force: bool, no_ca: bool) -> Result<u8, String> {
    let say = |created: bool, p: &Path| {
        let verb = if created { "created".green() } else { "exists ".yellow() };
        eprintln!("  {verb} {}", p.display());
    };
    let cfg = Path::new("capyshield.yaml");
    say(write_new(cfg, capyshield_policy::TEMPLATE, force)?, cfg);
    let rules = Path::new(".capyshield/vex-rules.yaml");
    say(write_new(rules, VEX_RULES_TEMPLATE, false)?, rules);
    if no_ca {
        return Ok(0);
    }
    let dir = ca_dir()?;
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    if cert.exists() && key.exists() {
        say(false, &cert);
        return Ok(0);
    }
    let ca = Ca::generate().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        opts.open(&key)
            .and_then(|mut f| f.write_all(ca.key_pem.as_bytes()))
            .map_err(|e| format!("{}: {e}", key.display()))?;
    }
    std::fs::write(&cert, &ca.cert_pem).map_err(|e| format!("{}: {e}", cert.display()))?;
    say(true, &cert);
    say(true, &key);
    eprintln!(
        "\nThe local CA is only used for `tls_inspection: mitm`. capyshield injects it into the wrapped\n\
         process (NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, ...); you do not\n\
         need to trust it system-wide. The private key never leaves {}.",
        dir.display()
    );
    Ok(0)
}
