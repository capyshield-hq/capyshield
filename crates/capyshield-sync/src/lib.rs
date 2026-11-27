//! Optional CapyShield Cloud client. Only used when the user passes `--sync` and a token is set;
//! nothing here runs otherwise. Payloads are metadata only (ids, purls, reachability facts,
//! blocked host/port/rule counts), never request bodies or ENV values.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::sync::Arc;
use tokio::net::TcpStream;

/// ENV names that hold the Cloud token; `guard`/`watch` strip them from the wrapped command.
pub const TOKEN_VARS: [&str; 2] = ["CAPYSHIELD_TOKEN", "CAPYSHIELD_API_KEY"];
pub const DEFAULT_API: &str = "https://api.capyshield.com";
pub const MAX_PAYLOAD_BYTES: usize = 500 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct Client {
    base: String,
    token: String,
}

impl Client {
    /// `CAPYSHIELD_TOKEN` (or `CAPYSHIELD_API_KEY`), endpoint override via `CAPYSHIELD_API_URL`.
    pub fn from_env() -> Option<Client> {
        let token = TOKEN_VARS.iter().find_map(|k| std::env::var(k).ok().filter(|t| !t.is_empty()))?;
        let base = std::env::var("CAPYSHIELD_API_URL").unwrap_or_else(|_| DEFAULT_API.into());
        Some(Client {
            base: base.trim_end_matches('/').to_string(),
            token,
        })
    }

    /// Team VEX rules for a project, as the same YAML/JSON shape as `.capyshield/vex-rules.yaml`.
    pub async fn pull_vex_rules(&self, project: &str) -> Result<String, BoxError> {
        let body = self.request(Method::GET, &format!("/v1/vex/rules?project={project}"), None).await?;
        Ok(String::from_utf8(body.to_vec())?)
    }

    /// Team egress policy for a project: `{allow_presets, allow_hosts, deny_hosts}`.
    pub async fn pull_egress_policy(&self, project: &str) -> Result<String, BoxError> {
        let body = self
            .request(Method::GET, &format!("/v1/egress/policy?project={project}"), None)
            .await?;
        Ok(String::from_utf8(body.to_vec())?)
    }

    pub async fn push_vex(&self, payload: &Value) -> Result<Value, BoxError> {
        self.post("/v1/vex/sync", payload).await
    }

    pub async fn push_egress_report(&self, payload: &Value) -> Result<Value, BoxError> {
        self.post("/v1/egress/report", payload).await
    }

    async fn post(&self, path: &str, payload: &Value) -> Result<Value, BoxError> {
        let body = check_size(payload)?;
        let resp = self.request(Method::POST, path, Some(body)).await?;
        Ok(serde_json::from_slice(&resp).unwrap_or(Value::Null))
    }

    async fn request(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<Bytes, BoxError> {
        let uri: Uri = format!("{}{path}", self.base).parse()?;
        let host = uri.host().ok_or("API URL has no host")?.to_string();
        let https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let req = Request::builder()
            .method(method)
            .uri(uri.path_and_query().map_or("/", |p| p.as_str()))
            .header("host", &host)
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .header("user-agent", concat!("capyshield/", env!("CARGO_PKG_VERSION")))
            .body(Full::new(Bytes::from(body.unwrap_or_default())))?;
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        let resp = if https {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.clone())?;
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?;
            send(tls, req).await?
        } else {
            send(tcp, req).await?
        };
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            return Err(format!("{status}: {}", String::from_utf8_lossy(&bytes)).into());
        }
        Ok(bytes)
    }
}

pub fn check_size(payload: &Value) -> Result<Vec<u8>, BoxError> {
    let body = serde_json::to_vec(payload)?;
    if body.len() > MAX_PAYLOAD_BYTES {
        return Err(format!("sync payload is {} bytes, limit is {MAX_PAYLOAD_BYTES}", body.len()).into());
    }
    Ok(body)
}

async fn send<S>(stream: S, req: Request<Full<Bytes>>) -> Result<hyper::Response<hyper::body::Incoming>, BoxError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    Ok(sender.send_request(req).await?)
}
