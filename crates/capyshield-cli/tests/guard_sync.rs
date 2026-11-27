//! `guard --sync` end to end against a fake CapyShield Cloud: team policy pull, blocked-host report,
//! and the Cloud token never reaching the wrapped command.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// (request head, body) per call.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// Serves the egress endpoints and records each call.
fn fake_cloud() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut r = BufReader::new(&stream);
            let (mut head, mut len) = (String::new(), 0);
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" {
                    break;
                }
                head += &line;
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let resp = if head.starts_with("GET /v1/egress/policy") {
                r#"{"allow_hosts":["registry.npmjs.org"]}"#
            } else {
                "{}"
            };
            log.lock().unwrap().push((head, String::from_utf8(body).unwrap()));
            write!(
                &stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp}",
                resp.len()
            )
            .unwrap();
        }
    });
    (url, seen)
}

#[test]
fn guard_sync_pulls_policy_reports_blocks_and_hides_token() {
    let (url, seen) = fake_cloud();
    let dir = std::env::temp_dir().join(format!("capyshield-sync-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_capyshield"))
        .current_dir(&dir)
        .env("CAPYSHIELD_API_URL", &url)
        .env("CAPYSHIELD_TOKEN", "cs_test_token")
        .env("CAPYSHIELD_API_KEY", "cs_test_key")
        .args(["guard", "--sync", "--", "sh", "-c"])
        .arg(r#"curl -s -o /dev/null http://blocked.example/; echo "token=[$CAPYSHIELD_TOKEN$CAPYSHIELD_API_KEY]""#)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));

    assert!(stdout.contains("token=[]"), "token leaked to the wrapped command: {stdout}");
    assert_eq!(out.status.code(), Some(2), "team allowlist blocks the host: {stderr}");
    assert!(
        stderr.contains("capyshield: synced 1 blocked connection(s) to CapyShield Cloud"),
        "{stderr}"
    );

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
    let (pull, _) = &seen[0];
    assert!(pull.starts_with("GET /v1/egress/policy?project=capyshield-sync-"), "{pull}");
    assert!(pull.contains("authorization: Bearer cs_test_token"), "{pull}");
    let (push, body) = &seen[1];
    assert!(push.starts_with("POST /v1/egress/report "), "{push}");
    let body: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        body["blocked"],
        serde_json::json!([{"host": "blocked.example", "port": 80, "rule_id": "disallowed_host:not_in_allow_hosts", "count": 1}])
    );
    for k in ["project", "generated_at", "cli_version"] {
        assert!(body[k].is_string(), "{k} missing: {body}");
    }
}

#[test]
fn guard_sync_without_token_is_an_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_capyshield"))
        .env_remove("CAPYSHIELD_TOKEN")
        .env_remove("CAPYSHIELD_API_KEY")
        .args(["guard", "--sync", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--sync needs CAPYSHIELD_TOKEN"));
}
