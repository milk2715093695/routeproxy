use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{CONNECTION, UPGRADE};
use http::{HeaderMap, HeaderName, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::engine::Engine;

pub mod connect;
pub mod proxy;

/// 活跃上游请求/隧道的并发上限；空闲 keep-alive 不占用请求许可。
pub(crate) const MAX_ACTIVE_CONNECTIONS: usize = 512;
/// 单进程连接槽上限；限制空闲 keep-alive 和慢客户端占用的 fd。
const MAX_CONNECTION_SLOTS: usize = 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

pub type BoxBody = UnsyncBoxBody<Bytes, Box<dyn Error + Send + Sync>>;

pub fn full_body(body: impl Into<Bytes>) -> BoxBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn error_response(status: StatusCode, message: impl AsRef<str>) -> Response<BoxBody> {
    let body = full_body(format!("{}\n", message.as_ref()));
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("静态错误响应")
}

pub(crate) async fn bind_listeners(
    config: &Config,
    label: &str,
) -> Result<Vec<(SocketAddr, TcpListener)>> {
    let mut listeners = Vec::with_capacity(config.listen_addresses().len());
    for &address in config.listen_addresses() {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("绑定 {label} 监听 {address} 失败"))?;
        listeners.push((address, listener));
    }
    Ok(listeners)
}

pub(crate) async fn wait_for_listeners(
    mut tasks: JoinSet<(SocketAddr, Result<()>)>,
    label: &str,
) -> Result<()> {
    match tasks.join_next().await {
        Some(Ok((address, Ok(())))) => bail!("{label} 监听 {address} 意外停止"),
        Some(Ok((address, Err(error)))) => bail!("{label} 监听 {address} 已停止: {error:#}"),
        Some(Err(error)) => bail!("{label} 监听任务失败: {error}"),
        None => bail!("{label} 监听器未运行"),
    }
}

pub async fn serve(config: Arc<Config>, engine: Arc<Engine>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let connection_slots = Arc::new(Semaphore::new(MAX_CONNECTION_SLOTS));
    let listeners = bind_listeners(&config, "proxy").await?;
    let mut tasks = JoinSet::new();

    for (address, listener) in listeners {
        let config = Arc::clone(&config);
        let engine = Arc::clone(&engine);
        let permits = Arc::clone(&permits);
        let connection_slots = Arc::clone(&connection_slots);
        tasks.spawn(async move {
            let result = accept_loop(listener, config, engine, permits, connection_slots).await;
            (address, result)
        });
    }

    wait_for_listeners(tasks, "proxy").await
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<Config>,
    engine: Arc<Engine>,
    permits: Arc<Semaphore>,
    connection_slots: Arc<Semaphore>,
) -> Result<()> {
    let mut failures = 0_u32;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(connection) => {
                failures = 0;
                connection
            }
            Err(error) => {
                failures += 1;
                tracing::warn!("accept 失败: {error}");
                if failures >= 5 {
                    return Err(error).context("accept 连续失败");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let slot = match Arc::clone(&connection_slots).try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                tracing::warn!("HTTP 连接数已达上限，丢弃 {peer}");
                drop(stream);
                continue;
            }
        };
        let config = Arc::clone(&config);
        let engine = Arc::clone(&engine);
        let permits = Arc::clone(&permits);
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(error) = serve_connection(stream, config, engine, permits).await {
                tracing::debug!("来自 {peer} 的连接已关闭: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    config: Arc<Config>,
    engine: Arc<Engine>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let service = service_fn(move |request: Request<Incoming>| {
        let config = Arc::clone(&config);
        let engine = Arc::clone(&engine);
        let permits = Arc::clone(&permits);
        async move {
            let permit = match permits.try_acquire_owned() {
                Ok(permit) => Arc::new(permit),
                Err(_) => {
                    return Ok::<_, Infallible>(error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "并发请求数已达上限",
                    ));
                }
            };
            let response = match request.method() {
                &http::Method::CONNECT => connect::handle(request, engine, config, permit).await,
                _ => proxy::handle(request, engine, config, permit).await,
            };
            Ok::<_, Infallible>(response)
        }
    });

    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("HTTP 连接失败")
}

pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let connection_tokens: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();

    for token in connection_tokens {
        if preserve_upgrade && token == "upgrade" {
            continue;
        }
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(name);
        }
    }

    for name in [
        "proxy-connection",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "proxy-authorization",
    ] {
        headers.remove(name);
    }

    if preserve_upgrade && headers.contains_key(UPGRADE) {
        headers.insert(CONNECTION, "upgrade".parse().expect("valid header value"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}

pub(crate) fn normalize_authority_host(host: &str, port: u16) -> (String, u16) {
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    (host.to_ascii_lowercase(), port)
}

pub(crate) fn host_header(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
