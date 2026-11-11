use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, timeout_at};

use crate::config::Config;
use crate::engine::{Decision, Engine};
use crate::http::bind_listeners;
use crate::http::connect::connect_via_proxy;
use crate::platform::original_dst;
use crate::relay::copy_bidirectional_idle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_SNIFF_BYTES: usize = 16 * 1024;

pub async fn serve(config: Arc<Config>, engine: Arc<Engine>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(config.max_connections()));
    let mut listeners = bind_listeners(&config, "transparent").await?;
    if listeners.len() != 1 {
        bail!("transparent 模式要求恰好一个监听器");
    }
    let (address, listener) = listeners
        .pop()
        .expect("transparent 配置已校验只有一个监听器");

    let tcp = accept_loop(listener, Arc::clone(&config), Arc::clone(&engine), permits);
    if config.udp_enabled() {
        // UDP 是附加数据面：UDP ingress 失败不能带走 TCP 监听。
        let udp_config = Arc::clone(&config);
        let udp_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            if let Err(error) = crate::udp::serve(udp_config, udp_engine).await {
                tracing::error!(
                    event = "udp_serve",
                    error = %format!("{error:#}"),
                    "UDP 服务已退出，TCP 继续运行"
                );
            }
        });
    }
    tcp.await
        .with_context(|| format!("transparent 监听 {address} 已停止"))
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<Config>,
    engine: Arc<Engine>,
    permits: Arc<Semaphore>,
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
                tracing::warn!("transparent accept 失败: {error}");
                if failures >= 5 {
                    return Err(error).context("transparent accept 连续失败");
                }
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("transparent 连接数已达上限，丢弃 {peer}");
                drop(stream);
                continue;
            }
        };
        let config = Arc::clone(&config);
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(stream, peer, engine, config).await;
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: std::net::SocketAddr,
    engine: Arc<Engine>,
    config: Arc<Config>,
) {
    let started = Instant::now();
    let flow_id = crate::logging::next_flow_id();
    let target = match original_dst(&client) {
        Ok(target) => target,
        Err(error) => {
            tracing::warn!("transparent 目标查找失败 {peer}: {error}");
            return;
        }
    };

    // 连到本监听器会再次进入透明代理，必须拒绝以免形成反馈环。
    if config.is_forbidden_target(target.into()) {
        tracing::debug!(
            event = "transparent_tcp",
            flow_id,
            target = %target,
            transport = "tcp",
            transparent = true,
            status = 400,
            error = "连接目标是 transparent 监听器自身",
            "拒绝连接到自身监听器"
        );
        return;
    }

    let ip_decision = engine.decide_ip(IpAddr::V4(*target.ip())).await;
    // 只有 80 端口能读明文 Host；非 80 端口不等待客户端数据，按 IP 决策。
    let mut sniff_failed = false;
    let http_host = if target.port() == 80 {
        match peek_http_host(&client).await {
            Ok(host) => host,
            Err(error) => {
                sniff_failed = true;
                tracing::debug!("transparent HTTP 嗅探失败 {peer}: {error}");
                None
            }
        }
    } else {
        None
    };
    let decision = if config.is_excluded_port(target.port()) {
        Decision::Direct
    } else {
        match http_host.as_deref() {
            Some(host) => combine_decisions(ip_decision, engine.decide_host(host).await),
            // 已确认是 HTTP 但 header 不完整时不能回退 Direct IP，否则可绕过域名规则。
            None if sniff_failed => Decision::Proxy,
            None => ip_decision,
        }
    };

    let mut upstream = match decision {
        Decision::Direct => match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                log_transparent_failure(
                    flow_id,
                    target,
                    decision,
                    502,
                    "transparent TCP 连接失败",
                    &error,
                );
                return;
            }
            Err(_) => {
                log_transparent_failure(
                    flow_id,
                    target,
                    decision,
                    504,
                    "transparent TCP 连接超时",
                    &"超过截止时间",
                );
                return;
            }
        },
        Decision::Proxy => {
            // 有嗅探 Host 时保留域名；否则回退目标 IP。
            let target_host = target.ip().to_string();
            let upstream_host = http_host.as_deref().unwrap_or(&target_host);
            match connect_via_proxy(upstream_host, target.port(), &config).await {
                Ok(stream) => stream,
                Err(error) => {
                    log_transparent_failure(
                        flow_id,
                        target,
                        decision,
                        502,
                        "transparent 上游 CONNECT 失败",
                        &format!("{error:#}"),
                    );
                    return;
                }
            }
        }
    };

    tracing::debug!(
        event = "transparent_tcp",
        flow_id,
        target = %target,
        decision = %decision,
        transport = "tcp",
        transparent = true,
        status = 200,
        duration_ms = started.elapsed().as_millis(),
        "transparent TCP 已建立"
    );

    if let Err(error) =
        copy_bidirectional_idle(&mut client, &mut upstream, config.idle_timeout()).await
    {
        tracing::debug!("transparent TCP 已关闭: {error}");
    }
}

fn log_transparent_failure(
    flow_id: u64,
    target: SocketAddrV4,
    decision: Decision,
    status: u16,
    message: &'static str,
    error: &dyn fmt::Display,
) {
    tracing::debug!(
        event = "transparent_tcp",
        flow_id,
        target = %target,
        decision = %decision,
        transport = "tcp",
        transparent = true,
        status,
        error = %error,
        "{message}: {error}"
    );
}

fn combine_decisions(ip: Decision, host: Decision) -> Decision {
    match (ip, host) {
        // 域名可把 Direct IP 升级为 Proxy，也可让 foreign IP 上的 Direct 域名直连。
        (Decision::Direct, Decision::Proxy) => Decision::Proxy,
        (Decision::Proxy, Decision::Direct) | (Decision::Direct, Decision::Direct) => {
            Decision::Direct
        }
        (Decision::Proxy, Decision::Proxy) => Decision::Proxy,
    }
}

async fn peek_http_host(stream: &TcpStream) -> io::Result<Option<String>> {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut buffer = [0_u8; MAX_SNIFF_BYTES];

    loop {
        // peek 每次从流起点返回可读字节，不能把偏移当累计长度。
        let read = match timeout_at(deadline, stream.peek(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP header 不完整",
                ));
            }
        };
        if read == 0 {
            return Ok(None);
        }

        let bytes = &buffer[..read];
        match classify_http_prefix(bytes) {
            HttpPrefix::NotHttp => return Ok(None),
            HttpPrefix::Incomplete => {}
            HttpPrefix::Method => {
                if let Some(end) = find_header_end(bytes) {
                    return Ok(parse_host(&bytes[..end]));
                }
            }
        }
        if read == buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header 超过嗅探缓冲区",
            ));
        }

        // peek 不消费字节，给客户端时间补齐跨 TCP 段的 header。
        sleep(Duration::from_millis(10)).await;
    }
}

fn parse_host(head: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(head);
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let authority = value.trim().parse::<http::uri::Authority>().ok()?;
            return Some(authority.host().to_string());
        }
    }
    None
}

enum HttpPrefix {
    NotHttp,
    Incomplete,
    Method,
}

fn classify_http_prefix(bytes: &[u8]) -> HttpPrefix {
    const METHODS: [&[u8]; 8] = [
        b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"CONNECT", b"OPTIONS", b"PATCH",
    ];
    match bytes.iter().position(|byte| *byte == b' ') {
        Some(space) => {
            let method = &bytes[..space];
            if METHODS.contains(&method) {
                HttpPrefix::Method
            } else {
                HttpPrefix::NotHttp
            }
        }
        None if METHODS.iter().any(|method| method.starts_with(bytes)) => HttpPrefix::Incomplete,
        None => HttpPrefix::NotHttp,
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_can_promote_foreign_ip_to_direct() {
        assert_eq!(
            combine_decisions(Decision::Proxy, Decision::Direct),
            Decision::Direct
        );
        assert_eq!(
            combine_decisions(Decision::Direct, Decision::Proxy),
            Decision::Proxy
        );
    }
}
