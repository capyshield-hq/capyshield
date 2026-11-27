//! Local HTTP/HTTPS forward proxy enforcing `capyshield.yaml` egress policy.
//!
//! * plain HTTP: host + URL + headers + body are inspected.
//! * CONNECT, `sni` mode: CONNECT target and TLS SNI are checked, bytes are counted, nothing is decrypted.
//! * CONNECT, `mitm` mode: TLS is terminated with a leaf cert from the local CA and every request is inspected.

mod ca;
pub mod sni;

pub use ca::Ca;

use bytes::Bytes;
use capyshield_policy::{AgentRules, Config, FailMode, Mode, TlsInspection, any_host_matches};
use capyshield_scanner::{Finding, Scanner};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderValue, TRANSFER_ENCODING};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Body = BoxBody<Bytes, hyper::Error>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

const AGENT_HEADER: &str = "x-agent-id";
/// Credentials in these headers to an allow-listed host are authentication, not exfiltration.
const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
    "private-token",
    "cookie",
];
/// Headers never worth an entropy check.
const BENIGN_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "connection",
    "if-none-match",
    "if-modified-since",
    "etag",
    "referer",
    "origin",
    "range",
];
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allowed,
    Blocked,
    Audited,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub timestamp: String,
    pub destination_host: String,
    pub port: u16,
    pub protocol: &'static str,
    pub bytes_sent: u64,
    pub action: Action,
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

pub struct Guard {
    cfg: Config,
    scanner: Scanner,
    agent_id: Option<String>,
    ca: Option<Ca>,
    tls_client: Arc<rustls::ClientConfig>,
    leaf_cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
    events: Mutex<Vec<Event>>,
}

impl Guard {
    /// `ca` is required for `tls_inspection: mitm`; without it CONNECT falls back to SNI mode.
    pub fn new(cfg: Config, scanner: Scanner, ca: Option<Ca>, agent_id: Option<String>) -> Arc<Guard> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(Guard {
            cfg,
            scanner,
            agent_id,
            ca,
            tls_client: Arc::new(tls),
            leaf_cache: Mutex::default(),
            events: Mutex::default(),
        })
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    /// Binds `addr` (use port 0 for an ephemeral port) and serves in the background.
    pub async fn listen(self: &Arc<Self>, addr: SocketAddr) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let guard = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let g = guard.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let g = g.clone();
                        async move { Ok::<_, Infallible>(g.handle(req).await) }
                    });
                    let conn = hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades();
                    if let Err(e) = conn.await {
                        tracing::debug!("proxy connection: {e}");
                    }
                });
            }
        });
        Ok(local)
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        if req.method() == Method::CONNECT {
            return self.connect(req);
        }
        let Some(host) = req.uri().host().map(|h| h.trim_matches(['[', ']']).to_string()) else {
            return text(StatusCode::BAD_REQUEST, "capyshield: proxy requests need an absolute URI\n");
        };
        let port = req.uri().port_u16().unwrap_or(80);
        self.forward(req, host, port, false).await
    }

    fn connect(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        let Some(auth) = req.uri().authority().cloned() else {
            return text(StatusCode::BAD_REQUEST, "capyshield: bad CONNECT target\n");
        };
        let host = auth.host().trim_matches(['[', ']']).to_string();
        let port = auth.port_u16().unwrap_or(443);
        let agent = self.agent(req.headers());
        let violation = self.host_violation(&host, agent.as_deref());
        if self.decide(&violation) == Action::Blocked {
            self.record(&host, port, "connect", 0, Action::Blocked, violation, agent);
            return text(StatusCode::FORBIDDEN, "capyshield: destination blocked by policy\n");
        }
        let mitm = self.cfg.egress.tls_inspection == TlsInspection::Mitm
            && self.ca.is_some()
            && !any_host_matches(&self.cfg.egress.tls_bypass_hosts, &host);
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(up) if mitm => self.mitm(TokioIo::new(up), host, port, agent).await,
                Ok(up) => self.tunnel(TokioIo::new(up), host, port, agent, violation).await,
                Err(e) => tracing::debug!("upgrade failed: {e}"),
            }
        });
        Response::new(empty())
    }

    /// SNI mode: peek at the ClientHello, re-check the SNI name, then splice bytes while counting them.
    async fn tunnel<S>(self: Arc<Self>, mut client: S, host: String, port: u16, agent: Option<String>, mut violation: Option<String>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut hello = Vec::with_capacity(4096);
        let parsed = tokio::time::timeout(CLIENT_HELLO_TIMEOUT, read_client_hello(&mut client, &mut hello)).await;
        let protocol = match parsed {
            Ok(Ok(sni::Hello::Sni(name))) => {
                if let Some(name) = name.filter(|n| !n.eq_ignore_ascii_case(&host)) {
                    violation = violation.or_else(|| self.host_violation(&name, agent.as_deref()));
                }
                "https-sni"
            }
            Ok(Err(_)) => return,
            // Not TLS (or server-speaks-first): the destination can't be confirmed via SNI.
            _ => {
                if self.cfg.fail_mode == FailMode::FailClosed && self.cfg.mode == Mode::Enforce {
                    violation = violation.or(Some("inspection_failed:not_tls".into()));
                }
                "tcp"
            }
        };
        if self.decide(&violation) == Action::Blocked {
            self.record(&host, port, protocol, hello.len() as u64, Action::Blocked, violation, agent);
            return;
        }
        let upstream = match TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("connect {host}:{port}: {e}");
                self.record(
                    &host,
                    port,
                    protocol,
                    0,
                    Action::Allowed,
                    Some("upstream_unreachable".into()),
                    agent,
                );
                return;
            }
        };
        let rules = self.agent_rules(agent.as_deref());
        let limit = if self.is_known(&host, rules) { None } else { self.limit(rules) };
        let enforce = self.cfg.mode == Mode::Enforce;
        // Recorded at open (keep-alive tunnels often outlive the wrapped command); bytes update live.
        let action = self.decide(&violation);
        let idx = self.record(&host, port, protocol, 0, action, violation.clone(), agent);
        let over = pump(client, upstream, &hello, limit, enforce, |sent| {
            self.update(idx, |e| e.bytes_sent = sent)
        })
        .await;
        if over && violation.is_none() {
            self.update(idx, |e| {
                e.action = self.decide(&Some(String::new()));
                e.rule_id = Some("payload_limit".into());
                announce(e);
            });
        }
    }

    /// MITM mode: terminate TLS with a local leaf cert and run every request through `forward`.
    async fn mitm<S>(self: Arc<Self>, client: S, host: String, port: u16, agent: Option<String>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let server_cfg = match self.leaf_config(&host) {
            Ok(c) => c,
            Err(e) if self.cfg.fail_mode == FailMode::FailOpen => {
                tracing::warn!("leaf cert for {host}: {e}; falling back to SNI tunnel");
                return self.tunnel(client, host, port, agent, None).await;
            }
            Err(e) => {
                tracing::warn!("leaf cert for {host}: {e}");
                self.record(
                    &host,
                    port,
                    "https-mitm",
                    0,
                    Action::Blocked,
                    Some("inspection_failed:cert".into()),
                    agent,
                );
                return;
            }
        };
        let tls = match TlsAcceptor::from(server_cfg).accept(client).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "capyshield: TLS handshake from client failed for {host} ({e}); add it to egress.tls_bypass_hosts if the client pins certificates"
                );
                return;
            }
        };
        let svc = service_fn(move |req| {
            let (g, host) = (self.clone(), host.clone());
            async move { Ok::<_, Infallible>(g.forward(req, host, port, true).await) }
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), svc)
            .await
        {
            tracing::debug!("mitm connection: {e}");
        }
    }

    /// Inspect a full HTTP request (plain or decrypted), then forward it upstream.
    async fn forward(self: Arc<Self>, req: Request<Incoming>, host: String, port: u16, tls: bool) -> Response<Body> {
        let protocol = if tls { "https-mitm" } else { "http" };
        let (mut parts, body) = req.into_parts();
        let agent = self.agent(&parts.headers);
        let mut violation = self.host_violation(&host, agent.as_deref());
        // Domain fronting: a Host header that differs from the connected host is checked too.
        let host_header = parts.headers.get(HOST).and_then(|v| v.to_str().ok()).map(strip_port);
        if let Some(h) = host_header.filter(|h| !h.eq_ignore_ascii_case(&host)) {
            violation = violation.or_else(|| self.host_violation(h, agent.as_deref()));
        }
        if self.decide(&violation) == Action::Blocked {
            self.record(&host, port, protocol, 0, Action::Blocked, violation, agent);
            return text(StatusCode::FORBIDDEN, "capyshield: destination blocked by policy\n");
        }
        // ponytail: bodies are buffered to scan them whole; stream with a rolling window if uploads get huge.
        let body = match body.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => return text(StatusCode::BAD_GATEWAY, format!("capyshield: reading request body: {e}\n")),
        };
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
        violation = violation.or_else(|| self.request_violation(&host, agent.as_deref(), &path, &parts.headers, &body));
        let action = self.decide(&violation);
        self.record(&host, port, protocol, body.len() as u64, action, violation, agent);
        if action == Action::Blocked {
            return text(StatusCode::FORBIDDEN, "capyshield: request blocked by policy\n");
        }

        parts.uri = path.parse().expect("path_and_query is a valid origin-form URI");
        for h in ["proxy-connection", "proxy-authorization", AGENT_HEADER] {
            parts.headers.remove(h);
        }
        if parts.headers.remove(TRANSFER_ENCODING).is_some() {
            parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
        if !parts.headers.contains_key(HOST) {
            let default_port = if tls { 443 } else { 80 };
            let value = if port == default_port {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            parts
                .headers
                .insert(HOST, HeaderValue::from_str(&value).unwrap_or(HeaderValue::from_static("localhost")));
        }
        match self.send(Request::from_parts(parts, Full::new(body)), &host, port, tls).await {
            Ok(resp) => resp.map(|b| b.boxed()),
            Err(e) => text(StatusCode::BAD_GATEWAY, format!("capyshield: upstream {host}:{port}: {e}\n")),
        }
    }

    async fn send(&self, req: Request<Full<Bytes>>, host: &str, port: u16, tls: bool) -> Result<Response<Incoming>, BoxError> {
        let tcp = TcpStream::connect((host, port)).await?;
        if !tls {
            return http1_send(tcp, req).await;
        }
        let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let stream = TlsConnector::from(self.tls_client.clone()).connect(name, tcp).await?;
        http1_send(stream, req).await
    }

    fn leaf_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, BoxError> {
        if let Some(c) = self.leaf_cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let ca = self.ca.as_ref().ok_or("no local CA")?;
        let (cert, key) = ca.leaf(host)?;
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert, ca.cert_der.clone()], key)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaf_cache.lock().unwrap().insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    // ---- policy ----

    fn agent(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(AGENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| self.agent_id.clone())
    }

    fn agent_rules(&self, agent: Option<&str>) -> Option<&AgentRules> {
        agent.and_then(|a| self.cfg.agents.get(a))
    }

    fn allow_list<'a>(&'a self, rules: Option<&'a AgentRules>) -> &'a [String] {
        rules.and_then(|r| r.allow_hosts.as_deref()).unwrap_or(&self.cfg.egress.allow_hosts)
    }

    /// Explicitly allow-listed (an empty allow list means "everything not denied", but nothing is *known*).
    fn is_known(&self, host: &str, rules: Option<&AgentRules>) -> bool {
        any_host_matches(self.allow_list(rules), host)
    }

    fn limit(&self, rules: Option<&AgentRules>) -> Option<u64> {
        rules.and_then(|r| r.max_outbound_bytes).or(self.cfg.egress.max_outbound_bytes)
    }

    fn host_violation(&self, host: &str, agent: Option<&str>) -> Option<String> {
        let rules = self.agent_rules(agent);
        let deny = self
            .cfg
            .egress
            .deny_hosts
            .iter()
            .chain(rules.into_iter().flat_map(|r| &r.deny_hosts));
        if let Some(p) = deny.into_iter().find(|p| capyshield_policy::host_matches(p, host)) {
            return Some(format!("disallowed_host:deny_hosts:{p}"));
        }
        let allow = self.allow_list(rules);
        if !allow.is_empty() && !any_host_matches(allow, host) {
            return Some("disallowed_host:not_in_allow_hosts".into());
        }
        // Secrets smuggled in the hostname itself (DNS-label exfiltration).
        self.secret_violation(host, &self.scanner.scan(host.as_bytes()))
    }

    fn request_violation(&self, host: &str, agent: Option<&str>, path: &str, headers: &HeaderMap, body: &[u8]) -> Option<String> {
        let rules = self.agent_rules(agent);
        let known = self.is_known(host, rules);
        let (mut payload, mut auth) = (path.as_bytes().to_vec(), vec![]);
        for (name, value) in headers {
            let buf = if AUTH_HEADERS.contains(&name.as_str()) {
                &mut auth
            } else {
                &mut payload
            };
            buf.extend_from_slice(value.as_bytes());
            buf.push(b'\n');
        }
        payload.extend_from_slice(body);
        if let Some(v) = self.secret_violation(host, &self.scanner.scan(&payload)) {
            return Some(v);
        }
        if known {
            return None;
        }
        if let Some(v) = self.secret_violation(host, &self.scanner.scan(&auth)) {
            return Some(v);
        }
        if let Some(max) = self.limit(rules).filter(|&max| body.len() as u64 > max) {
            return Some(format!("payload_limit:{}>{max}", body.len()));
        }
        let query = path.split_once('?').map_or("", |(_, q)| q);
        let values = query.split('&').filter_map(|kv| kv.split_once('=').map(|(_, v)| v));
        let header_values = headers
            .iter()
            .filter(|(n, _)| !BENIGN_HEADERS.contains(&n.as_str()))
            .filter_map(|(_, v)| v.to_str().ok());
        values
            .chain(header_values)
            .find_map(|v| self.scanner.scan_entropy(v))
            .map(|f| f.rule_id())
    }

    fn secret_violation(&self, host: &str, findings: &[Finding]) -> Option<String> {
        let allow = &self.cfg.egress.scan.secret_allow;
        findings
            .iter()
            .find(|f| {
                let bare = f.id.strip_prefix("env:").unwrap_or(&f.id);
                !allow
                    .get(bare)
                    .or_else(|| allow.get(&f.id))
                    .is_some_and(|hosts| any_host_matches(hosts, host))
            })
            .map(Finding::rule_id)
    }

    fn decide(&self, violation: &Option<String>) -> Action {
        match (violation, self.cfg.mode) {
            (None, _) => Action::Allowed,
            (Some(_), Mode::Enforce) => Action::Blocked,
            (Some(_), Mode::Audit) => Action::Audited,
        }
    }

    /// Appends an event and returns its index.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        host: &str,
        port: u16,
        protocol: &'static str,
        bytes_sent: u64,
        action: Action,
        rule_id: Option<String>,
        agent_id: Option<String>,
    ) -> usize {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let ev = Event {
            timestamp,
            destination_host: host.to_string(),
            port,
            protocol,
            bytes_sent,
            action,
            rule_id,
            agent_id,
        };
        announce(&ev);
        let mut events = self.events.lock().unwrap();
        events.push(ev);
        events.len() - 1
    }

    fn update(&self, idx: usize, f: impl FnOnce(&mut Event)) {
        f(&mut self.events.lock().unwrap()[idx]);
    }
}

fn announce(e: &Event) {
    if e.action != Action::Allowed {
        let verb = if e.action == Action::Blocked { "BLOCKED" } else { "AUDIT" };
        eprintln!(
            "capyshield: {verb} {}:{} ({})",
            e.destination_host,
            e.port,
            e.rule_id.as_deref().unwrap_or("-")
        );
    }
}

async fn read_client_hello<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> io::Result<sni::Hello> {
    let mut chunk = [0u8; 4096];
    loop {
        match sni::parse(buf) {
            sni::Hello::NeedMore if buf.len() <= 16 * 1024 + 5 => {}
            sni::Hello::NeedMore => return Ok(sni::Hello::Sni(None)),
            done => return Ok(done),
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Splice client <-> upstream, reporting bytes sent upstream. Returns whether `limit` was exceeded.
async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    client: S,
    upstream: TcpStream,
    first: &[u8],
    limit: Option<u64>,
    enforce: bool,
    mut progress: impl FnMut(u64),
) -> bool {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();
    let (mut sent, mut over) = (0u64, false);
    let up = async {
        let mut buf = first.to_vec();
        loop {
            sent += buf.len() as u64;
            progress(sent);
            if limit.is_some_and(|l| sent > l) {
                over = true;
                if enforce {
                    return Err(io::Error::other("payload_limit"));
                }
            }
            uw.write_all(&buf).await?;
            buf.resize(16 * 1024, 0);
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                uw.shutdown().await?;
                return Ok::<_, io::Error>(());
            }
            buf.truncate(n);
        }
    };
    let down = async {
        tokio::io::copy(&mut ur, &mut cw).await?;
        cw.shutdown().await
    };
    let _ = tokio::try_join!(up, down);
    over
}

async fn http1_send<S>(stream: S, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("upstream connection: {e}");
        }
    });
    Ok(sender.send_request(req).await?)
}

fn strip_port(h: &str) -> &str {
    match h.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !host.ends_with(':') => host.trim_matches(['[', ']']),
        _ => h.trim_matches(['[', ']']),
    }
}

fn empty() -> Body {
    Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
}

fn text(status: StatusCode, msg: impl Into<String>) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(msg.into())).map_err(|e| match e {}).boxed());
    *r.status_mut() = status;
    r
}
