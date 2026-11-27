use capyshield_policy::Config;
use capyshield_policy::Scan;
use capyshield_proxy::sni;
use capyshield_proxy::*;
use capyshield_scanner::Scanner;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

async fn upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

async fn guard(yaml: &str) -> (Arc<Guard>, SocketAddr) {
    let cfg = Config::parse(yaml).unwrap();
    let scanner = Scanner::new(&Scan::default(), [("AWS_SECRET_ACCESS_KEY".to_string(), SECRET.to_string())]);
    let g = Guard::new(cfg, scanner, None, None);
    let addr = g.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (g, addr)
}

async fn raw(proxy: SocketAddr, req: String) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
    out
}

fn post(up: SocketAddr, host: &str, body: &str) -> String {
    format!(
        "POST http://{up}/upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn enforce_blocks_env_secret_and_allows_clean_traffic() {
    let up = upstream().await;
    let (g, proxy) = guard("mode: enforce").await;
    let ok = raw(proxy, post(up, &up.to_string(), "hello")).await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    let leaked = raw(
        proxy,
        post(
            up,
            &up.to_string(),
            &format!("k={}", SECRET.replace('/', "%2F").replace('+', "%2B")),
        ),
    )
    .await;
    assert!(leaked.starts_with("HTTP/1.1 403"), "{leaked}");
    let ev = g.events();
    assert_eq!(ev[1].action, Action::Blocked);
    assert_eq!(ev[1].rule_id.as_deref(), Some("secret_leak:env:AWS_SECRET_ACCESS_KEY"));
}

#[tokio::test]
async fn allowlist_deny_and_audit_mode() {
    let up = upstream().await;
    let (g, proxy) = guard("mode: enforce\negress:\n  allow_hosts: ['registry.npmjs.org']").await;
    assert!(raw(proxy, post(up, &up.to_string(), "x")).await.starts_with("HTTP/1.1 403"));
    assert_eq!(g.events()[0].rule_id.as_deref(), Some("disallowed_host:not_in_allow_hosts"));
    let connect = raw(
        proxy,
        "CONNECT webhook.site:443 HTTP/1.1\r\nHost: webhook.site:443\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert!(connect.starts_with("HTTP/1.1 403"), "{connect}");

    let (g, proxy) = guard("mode: audit\negress:\n  allow_hosts: ['registry.npmjs.org']").await;
    assert!(raw(proxy, post(up, &up.to_string(), SECRET)).await.starts_with("HTTP/1.1 200"));
    assert_eq!(g.events()[0].action, Action::Audited);
}

#[tokio::test]
async fn payload_limit_applies_to_unknown_hosts() {
    let up = upstream().await;
    let (_, proxy) = guard("mode: enforce\negress:\n  max_outbound_bytes: 10").await;
    assert!(
        raw(proxy, post(up, &up.to_string(), &"a".repeat(11)))
            .await
            .starts_with("HTTP/1.1 403")
    );
    assert!(raw(proxy, post(up, &up.to_string(), "short")).await.starts_with("HTTP/1.1 200"));
}

#[test]
fn parses_real_client_hello() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let cfg = Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    let mut conn = rustls::ClientConnection::new(cfg, "example.com".try_into().unwrap()).unwrap();
    let mut hello = vec![];
    conn.write_tls(&mut hello).unwrap();
    assert_eq!(sni::parse(&hello), sni::Hello::Sni(Some("example.com".into())));
    assert_eq!(sni::parse(&hello[..3]), sni::Hello::NeedMore);
    assert_eq!(sni::parse(b"GET / HTTP/1.1\r\n"), sni::Hello::NotTls);
}

#[test]
fn ca_issues_leaf_certs() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = Ca::generate().unwrap();
    let reloaded = Ca::load(&ca.cert_pem, &ca.key_pem).unwrap();
    let (a, _) = reloaded.leaf("example.com").unwrap();
    let (b, _) = reloaded.leaf("127.0.0.1").unwrap();
    assert_ne!(a, b);
}
