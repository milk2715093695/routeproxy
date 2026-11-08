use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::config::Config;
use crate::engine::{Decision, Engine};
use crate::relay::copy_bidirectional_idle;

use super::proxy::connect_direct;
use super::{error_response, full_body, host_header, normalize_authority_host, BoxBody};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn handle(
    mut req: Request<Incoming>,
    engine: Arc<Engine>,
    config: Arc<Config>,
    permit: Arc<OwnedSemaphorePermit>,
) -> hyper::Response<BoxBody> {
    let started = Instant::now();
    let flow_id = crate::logging::next_flow_id();
    let Some(authority) = req.uri().authority().cloned() else {
        return error_response(hyper::StatusCode::BAD_REQUEST, "CONNECT 请求缺少 authority");
    };
    let (host, port) =
        normalize_authority_host(authority.host(), authority.port_u16().unwrap_or(443));
    let resolution = engine.resolve_host(&host).await;
    let decision = resolution.decision;
    let on_upgrade = hyper::upgrade::on(&mut req);

    let upstream = match decision {
        Decision::Direct => {
            connect_direct(&host, port, &config, resolution.direct_ips.as_deref()).await
        }
        Decision::Proxy => connect_via_proxy(&host, port, &config).await,
    };

    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(
                event = "connect",
                flow_id,
                target = %host,
                decision = %decision,
                status = 502,
                duration_ms = started.elapsed().as_millis(),
                transport = "tcp",
                error = %error,
                "CONNECT 失败: {error:#}"
            );
            return error_response(hyper::StatusCode::BAD_GATEWAY, "代理连接失败");
        }
    };

    tokio::spawn(async move {
        let _permit = permit;
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                tracing::debug!("客户端 CONNECT 升级失败: {error}");
                return;
            }
        };
        let mut client = TokioIo::new(upgraded);
        if let Err(error) =
            copy_bidirectional_idle(&mut client, &mut upstream, config.idle_timeout()).await
        {
            tracing::debug!("CONNECT 隧道关闭: {error}");
        }
    });

    tracing::debug!(
        event = "connect",
        flow_id,
        target = %host,
        decision = %decision,
        status = 200,
        duration_ms = started.elapsed().as_millis(),
        transport = "tcp",
        "CONNECT 已建立"
    );

    hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .body(full_body(""))
        .expect("静态 CONNECT 响应")
}

pub(crate) async fn connect_via_proxy(host: &str, port: u16, config: &Config) -> Result<TcpStream> {
    let upstream = config.upstream_addr();
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("连接上游超时")?
        .with_context(|| format!("连接上游 {upstream} 失败"))?;

    let authority = host_header(host, port);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    timeout(IO_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .context("发送上游 CONNECT 超时")?
        .context("发送上游 CONNECT 失败")?;

    let status = timeout(IO_TIMEOUT, read_status(&mut stream))
        .await
        .context("读取上游 CONNECT 响应超时")??;
    if !(200..300).contains(&status) {
        bail!("上游 CONNECT 返回 HTTP {status}");
    }
    Ok(stream)
}

async fn read_status(stream: &mut TcpStream) -> Result<u16> {
    let mut header = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        let read = stream
            .read(&mut byte)
            .await
            .context("读取上游 CONNECT 响应失败")?;
        if read == 0 {
            bail!("上游在 CONNECT 响应期间关闭连接");
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 16 * 1024 {
            bail!("上游 CONNECT 响应头过大");
        }
    }

    let header = std::str::from_utf8(&header).context("上游 CONNECT 响应不是 UTF-8")?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("上游 CONNECT 响应为空"))?;
    let mut fields = status_line.split_whitespace();
    let version = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("上游状态行无效"))?;
    if !version.starts_with("HTTP/") {
        bail!("上游状态行无效: {status_line}");
    }
    fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("上游缺少状态码"))?
        .parse::<u16>()
        .context("上游状态码无效")
}
