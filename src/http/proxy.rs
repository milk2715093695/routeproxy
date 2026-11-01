use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use http::header::{HOST, UPGRADE};
use http::{HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::time::timeout;

use crate::config::Config;
use crate::engine::{Decision, Engine, HostResolution};
use crate::net::canonicalize_addr;

use super::{
    error_response, full_body, host_header, normalize_authority_host, strip_hop_by_hop, BoxBody,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

macro_rules! request_event {
    ($level:expr, $($fields:tt)*) => {
        if $level == tracing::Level::DEBUG {
            tracing::debug!($($fields)*);
        } else {
            tracing::info!($($fields)*);
        }
    };
}

#[derive(Debug)]
enum TimedBodyError {
    Inner(Box<dyn Error + Send + Sync>),
    Timeout,
}

impl fmt::Display for TimedBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => error.fmt(formatter),
            Self::Timeout => formatter.write_str("body 空闲超时"),
        }
    }
}

impl Error for TimedBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inner(error) => Some(error.as_ref()),
            Self::Timeout => None,
        }
    }
}

/// 无 frame 进展超过 `idle` 时失败；每个成功 frame 重置计时。
struct TimedBody<B> {
    inner: B,
    idle: Duration,
    timer: Pin<Box<tokio::time::Sleep>>,
    progress: Option<Arc<Notify>>,
    finished: bool,
}

impl<B> TimedBody<B> {
    fn new(inner: B, idle: Duration, progress: Option<Arc<Notify>>) -> Self {
        Self {
            inner,
            idle,
            timer: Box::pin(tokio::time::sleep(idle)),
            progress,
            finished: false,
        }
    }
}

impl<B> Body for TimedBody<B>
where
    B: Body + Unpin,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = TimedBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.finished = true;
            return Poll::Ready(Some(Err(TimedBodyError::Timeout)));
        }

        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let next = tokio::time::Instant::now() + self.idle;
                self.timer.as_mut().reset(next);
                if let Some(progress) = &self.progress {
                    progress.notify_one();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(TimedBodyError::Inner(error.into()))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

pub async fn handle(
    req: Request<Incoming>,
    engine: Arc<Engine>,
    config: Arc<Config>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response<BoxBody> {
    let started = Instant::now();
    let flow_id = crate::logging::next_flow_id();
    let (host, port) = match request_target(&req) {
        Ok(target) => target,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "请求格式错误"),
    };
    let authority = host_header(&host, port);
    let resolution = engine.resolve_host(&host).await;
    let decision = resolution.decision;
    let level = request_log_level(&host);

    let result = forward(req, &host, port, &authority, &resolution, &config, permit).await;
    match result {
        Ok(response) => {
            request_event!(
                level,
                event = "http_request",
                flow_id,
                target = %authority,
                decision = %decision,
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_millis(),
                transport = "tcp",
                "HTTP 请求"
            );
            response
        }
        Err(error) => {
            request_event!(
                level,
                event = "http_request",
                flow_id,
                target = %authority,
                decision = %decision,
                status = 502,
                duration_ms = started.elapsed().as_millis(),
                transport = "tcp",
                error = %error,
                "HTTP 请求失败: {error:#}"
            );
            error_response(StatusCode::BAD_GATEWAY, "代理请求失败")
        }
    }
}

fn request_log_level(host: &str) -> tracing::Level {
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    }
}

fn request_target(req: &Request<Incoming>) -> Result<(String, u16)> {
    let uri = req.uri();
    if let Some(scheme) = uri.scheme() {
        if scheme != "http" {
            bail!("不支持的 URI scheme: {scheme}");
        }
    }

    if let Some(host) = uri.host() {
        return Ok(normalize_authority_host(host, uri.port_u16().unwrap_or(80)));
    }

    let host_header = req
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("缺少 Host 请求头"))?;
    let authority = host_header
        .parse::<http::uri::Authority>()
        .with_context(|| format!("Host 请求头无效: {host_header}"))?;
    Ok(normalize_authority_host(
        authority.host(),
        authority.port_u16().unwrap_or(80),
    ))
}

async fn forward(
    mut req: Request<Incoming>,
    host: &str,
    port: u16,
    authority: &str,
    resolution: &HostResolution,
    config: &Config,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Response<BoxBody>> {
    let decision = resolution.decision;
    let stream = match decision {
        Decision::Direct => {
            connect_direct(host, port, config, resolution.direct_ips.as_deref()).await?
        }
        Decision::Proxy => connect_upstream(config).await?,
    };

    let (mut sender, connection) = timeout(CONNECT_TIMEOUT, http1::handshake(TokioIo::new(stream)))
        .await
        .context("上游 HTTP 握手超时")?
        .context("初始化上游 HTTP 连接失败")?;
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::debug!("上游 HTTP 连接已关闭: {error}");
        }
    });

    let has_upgrade = req.headers().contains_key(UPGRADE);
    let client_upgrade = has_upgrade.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers, has_upgrade);

    // RFC 7230 §5.4：代理必须使用请求目标中的 authority，忽略客户端 Host。
    parts
        .headers
        .insert(HOST, HeaderValue::from_str(authority)?);

    rewrite_request_uri(&mut parts, decision, authority)?;

    let progress = Arc::new(Notify::new());
    let body = TimedBody::new(body, UPSTREAM_TIMEOUT, Some(Arc::clone(&progress)));
    let request = Request::from_parts(parts, body);
    let mut response = await_response(sender.send_request(request), progress).await?;

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "上游切换协议，但客户端未发起 Upgrade",
            ));
        };
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        spawn_upgrade_tunnel(client_upgrade, upstream_upgrade, permit);
        return Ok(response.map(|_| full_body("")));
    }

    // 响应头已返回；慢读只占连接槽，不占活跃请求许可。
    drop(permit);
    Ok(timed_response(response))
}

/// Direct 使用 origin-form；Proxy 使用 absolute-form。
fn rewrite_request_uri(
    parts: &mut http::request::Parts,
    decision: Decision,
    authority: &str,
) -> Result<()> {
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_owned();

    if decision == Decision::Direct {
        parts.uri = Uri::builder().path_and_query(path).build()?;
    } else if parts.uri.scheme().is_none() {
        parts.uri = Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query(path)
            .build()?;
    }
    Ok(())
}

fn spawn_upgrade_tunnel(
    client_upgrade: hyper::upgrade::OnUpgrade,
    upstream_upgrade: hyper::upgrade::OnUpgrade,
    permit: Arc<OwnedSemaphorePermit>,
) {
    tokio::spawn(async move {
        let _permit = permit;
        let client = match client_upgrade.await {
            Ok(upgrade) => upgrade,
            Err(error) => {
                tracing::debug!("客户端升级失败: {error}");
                return;
            }
        };
        let upstream = match upstream_upgrade.await {
            Ok(upgrade) => upgrade,
            Err(error) => {
                tracing::debug!("上游升级失败: {error}");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut upstream = TokioIo::new(upstream);
        if let Err(error) = copy_bidirectional(&mut client, &mut upstream).await {
            tracing::debug!("升级流关闭: {error}");
        }
    });
}

fn timed_response(mut response: Response<Incoming>) -> Response<BoxBody> {
    strip_hop_by_hop(response.headers_mut(), false);
    let (parts, body) = response.into_parts();
    let body = TimedBody::new(body, UPSTREAM_TIMEOUT, None)
        .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
        .boxed_unsync();
    Response::from_parts(parts, body)
}

async fn await_response<F>(future: F, progress: Arc<Notify>) -> Result<Response<Incoming>>
where
    F: Future<Output = std::result::Result<Response<Incoming>, hyper::Error>>,
{
    tokio::pin!(future);
    // 空闲 deadline：每个请求 body frame 重置；在 body 被 poll 前启动。
    let mut deadline = Box::pin(tokio::time::sleep(UPSTREAM_TIMEOUT));

    loop {
        tokio::select! {
            result = &mut future => return result.context("上游请求失败"),
            _ = progress.notified() => {
                deadline.as_mut().reset(tokio::time::Instant::now() + UPSTREAM_TIMEOUT);
            }
            _ = deadline.as_mut() => {
                bail!("上游请求或响应停滞超过 {} 秒", UPSTREAM_TIMEOUT.as_secs());
            }
        }
    }
}

pub(crate) async fn connect_direct(
    host: &str,
    port: u16,
    config: &Config,
    direct_ips: Option<&[IpAddr]>,
) -> Result<TcpStream> {
    let Some(direct_ips) = direct_ips else {
        return connect_target(host, port, config).await;
    };

    let addresses: Vec<SocketAddr> = direct_ips
        .iter()
        .map(|ip| SocketAddr::new(*ip, port))
        .collect();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    connect_addresses(&addresses, config, deadline).await
}

pub(crate) async fn connect_target(host: &str, port: u16, config: &Config) -> Result<TcpStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => timeout(
            deadline.saturating_duration_since(Instant::now()),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .context("DNS 查询超时")?
        .with_context(|| format!("解析 {host} 失败"))?
        .collect::<Vec<_>>(),
    };
    connect_addresses(&addresses, config, deadline).await
}

async fn connect_addresses(
    addresses: &[SocketAddr],
    config: &Config,
    deadline: Instant,
) -> Result<TcpStream> {
    if addresses.is_empty() {
        bail!("没有解析到可用地址");
    }

    let mut last_error = None;
    let total = addresses.len();
    for (index, address) in addresses.iter().enumerate() {
        let address = canonicalize_addr(*address);
        if config.is_forbidden_target(address) {
            last_error = Some(anyhow!("拒绝连接本代理监听地址 {address}"));
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_error = Some(anyhow!("连接已解析地址超时"));
            break;
        }

        // 把剩余预算分给尚未尝试的地址，避免首个黑洞 IPv6 吞掉全部 10s。
        let attempts_left = (total - index) as u32;
        let attempt_budget = (remaining / attempts_left).max(Duration::from_millis(200));

        match timeout(attempt_budget, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                last_error = Some(anyhow!("连接 {address} 失败: {error}"));
            }
            Err(_) => {
                last_error = Some(anyhow!("连接 {address} 超时"));
            }
        }
    }

    Err(last_error.expect("非空地址列表必然记录连接错误"))
}

async fn connect_upstream(config: &Config) -> Result<TcpStream> {
    let address = config.upstream_addr();
    timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .context("连接上游超时")?
        .with_context(|| format!("连接上游 {address} 失败"))
}
