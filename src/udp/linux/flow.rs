use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, Instant};

use crate::config::{Config, UdpDefault};
use crate::engine::{Decision, Engine};
use crate::socks5::UdpAssociation;

use super::raw::SharedRawReply;
use super::{reply_for, FlowFailures, ReplyRegistry, BUFFER_SIZE};

const FLOW_IDLE: Duration = Duration::from_secs(30);

pub(super) type FlowKey = (SocketAddrV4, SocketAddrV4);
pub(super) type FlowRegistry = Arc<Mutex<HashMap<FlowKey, mpsc::Sender<QueuedDatagram>>>>;

pub(super) struct QueuedDatagram {
    pub(super) payload: Vec<u8>,
    // 队列字节计入全局预算，数据报消费/丢弃时自动归还。
    _permit: OwnedSemaphorePermit,
}
pub(super) struct FlowTask {
    pub(super) key: FlowKey,
    pub(super) config: Arc<Config>,
    pub(super) engine: Arc<Engine>,
    pub(super) receiver: mpsc::Receiver<QueuedDatagram>,
    pub(super) registry: FlowRegistry,
    pub(super) failures: FlowFailures,
    pub(super) replies: ReplyRegistry,
    pub(super) local: bool,
    pub(super) raw_reply: Option<SharedRawReply>,
    pub(super) sender: mpsc::Sender<QueuedDatagram>,
    pub(super) permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpDecision {
    Direct,
    Proxy,
    Reject,
}

impl fmt::Display for UdpDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
            Self::Reject => "reject",
        })
    }
}

pub(super) enum ReplySocket {
    Target(Arc<TokioUdpSocket>),
    Raw(SharedRawReply),
}

impl ReplySocket {
    async fn send_to(
        &self,
        buffer: &[u8],
        client: SocketAddrV4,
        target: SocketAddrV4,
    ) -> io::Result<usize> {
        match self {
            Self::Target(socket) => socket.send_to(buffer, client).await,
            Self::Raw(socket) => socket.send_to(buffer, target, client),
        }
    }
}
pub(super) fn queue_datagram(budget: &Arc<Semaphore>, payload: &[u8]) -> Option<QueuedDatagram> {
    let permit = Arc::clone(budget)
        .try_acquire_many_owned(payload.len() as u32)
        .ok()?;
    Some(QueuedDatagram {
        payload: payload.to_vec(),
        _permit: permit,
    })
}

pub(super) async fn run_flow(task: FlowTask) {
    let FlowTask {
        key,
        config,
        engine,
        mut receiver,
        registry,
        failures,
        replies,
        local,
        raw_reply,
        sender,
        permit: _flow_permit,
    } = task;
    let (client, target) = key;
    let flow_id = crate::logging::next_flow_id();
    let decision = decide(&config, &engine, target).await;
    if decision == UdpDecision::Reject {
        tracing::debug!(
            event = "udp_flow",
            flow_id,
            transport = "udp",
            client = %client,
            target = %target,
            decision = %decision,
            "UDP flow 被拒绝"
        );
        if finish_flow(&registry, key, &sender) {
            mark_flow_failure(&failures, key);
        }
        return;
    }

    let reply = if local {
        let Some(raw_reply) = raw_reply else {
            tracing::warn!(
                event = "udp_flow",
                flow_id,
                transport = "udp",
                client = %client,
                target = %target,
                "本机 UDP 缺少 raw 回包 socket，关闭 flow"
            );
            if finish_flow(&registry, key, &sender) {
                mark_flow_failure(&failures, key);
            }
            return;
        };
        ReplySocket::Raw(raw_reply)
    } else {
        match reply_for(&replies, target) {
            Ok(socket) => ReplySocket::Target(socket),
            Err(error) => {
                tracing::warn!(
                    event = "udp_flow",
                    flow_id,
                    transport = "udp",
                    client = %client,
                    target = %target,
                    decision = %decision,
                    error = %error,
                    "UDP 回包 socket 注册失败"
                );
                if finish_flow(&registry, key, &sender) {
                    mark_flow_failure(&failures, key);
                }
                return;
            }
        }
    };

    tracing::info!(
        event = "udp_flow",
        flow_id,
        transport = "udp",
        client = %client,
        target = %target,
        decision = %decision,
        "UDP flow 已建立"
    );

    let result = match decision {
        UdpDecision::Direct => run_direct(&mut receiver, target, client, reply).await,
        UdpDecision::Proxy => run_proxy(&mut receiver, &config, target, client, reply).await,
        UdpDecision::Reject => unreachable!("Reject 已在前面处理"),
    };
    let failed = result.is_err();
    if let Err(error) = result {
        tracing::warn!(
            event = "udp_flow",
            flow_id,
            transport = "udp",
            client = %client,
            target = %target,
            decision = %decision,
            error = %format!("{error:#}"),
            "UDP flow 已关闭"
        );
    } else {
        tracing::debug!(
            event = "udp_flow",
            flow_id,
            transport = "udp",
            client = %client,
            target = %target,
            decision = %decision,
            "UDP flow 空闲关闭"
        );
    }
    if finish_flow(&registry, key, &sender) && failed {
        mark_flow_failure(&failures, key);
    }
}

async fn run_direct(
    receiver: &mut mpsc::Receiver<QueuedDatagram>,
    target: SocketAddrV4,
    client: SocketAddrV4,
    reply: ReplySocket,
) -> Result<()> {
    let upstream = TokioUdpSocket::bind("0.0.0.0:0")
        .await
        .context("创建直连 UDP socket 失败")?;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut idle = Box::pin(sleep(FLOW_IDLE));

    loop {
        tokio::select! {
            datagram = receiver.recv() => {
                let Some(datagram) = datagram else { return Ok(()) };
                upstream.send_to(&datagram.payload, target).await.context("直连 UDP 发送失败")?;
                idle.as_mut().reset(Instant::now() + FLOW_IDLE);
            }
            result = upstream.recv_from(&mut buffer) => {
                let (length, source) = result.context("直连 UDP 接收失败")?;
                if source != SocketAddr::V4(target) {
                    tracing::warn!(
                        event = "udp_direct",
                        target = %target,
                        source = %source,
                        "丢弃非目标来源的直连 UDP 响应"
                    );
                    continue;
                }
                reply.send_to(&buffer[..length], client, target).await.context("UDP 回包发送失败")?;
                idle.as_mut().reset(Instant::now() + FLOW_IDLE);
            }
            _ = &mut idle => return Ok(()),
        }
    }
}

async fn run_proxy(
    receiver: &mut mpsc::Receiver<QueuedDatagram>,
    config: &Config,
    target: SocketAddrV4,
    client: SocketAddrV4,
    reply: ReplySocket,
) -> Result<()> {
    let proxy = config
        .udp_upstream_addr()
        .context("UDP proxy 缺少上游地址")?;
    let mut association = UdpAssociation::connect(proxy).await?;
    let closed = association.closed_notify();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut idle = Box::pin(sleep(FLOW_IDLE));

    loop {
        tokio::select! {
            datagram = receiver.recv() => {
                let Some(datagram) = datagram else { return Ok(()) };
                association.send_to(target, &datagram.payload).await?;
                idle.as_mut().reset(Instant::now() + FLOW_IDLE);
            }
            result = association.recv_from(&mut buffer) => {
                let Some((reply_target, length)) = result? else { continue; };
                if reply_target != target {
                    tracing::warn!(
                        event = "udp_proxy",
                        target = %target,
                        source = %reply_target,
                        "丢弃非目标来源的 SOCKS5 UDP 响应"
                    );
                    continue;
                }
                reply.send_to(&buffer[..length], client, target).await.context("UDP 回包发送失败")?;
                idle.as_mut().reset(Instant::now() + FLOW_IDLE);
            }
            _ = closed.notified() => {
                tracing::warn!(
                    event = "udp_proxy",
                    target = %target,
                    "SOCKS5 控制连接已关闭，回收 UDP flow"
                );
                return Ok(());
            }
            _ = &mut idle => return Ok(()),
        }
    }
}

async fn decide(config: &Config, engine: &Engine, target: SocketAddrV4) -> UdpDecision {
    if config.is_excluded_port(target.port()) {
        return UdpDecision::Direct;
    }
    if config.is_udp_rejected(target.port()) {
        return UdpDecision::Reject;
    }

    let base = engine.decide_ip(IpAddr::V4(*target.ip())).await;
    match (base, config.udp_default()) {
        (Decision::Direct, _) => UdpDecision::Direct,
        (Decision::Proxy, UdpDefault::Direct) => UdpDecision::Direct,
        (Decision::Proxy, UdpDefault::Reject) => UdpDecision::Reject,
        (Decision::Proxy, UdpDefault::Proxy) => UdpDecision::Proxy,
    }
}

fn mark_flow_failure(failures: &FlowFailures, key: FlowKey) {
    let now = StdInstant::now();
    let mut failures = failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    failures.retain(|_, until| *until > now);
    failures.insert(key, now + super::FLOW_FAILURE_COOLDOWN);
}

fn finish_flow(
    registry: &FlowRegistry,
    key: FlowKey,
    sender: &mpsc::Sender<QueuedDatagram>,
) -> bool {
    let mut flows = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if flows
        .get(&key)
        .is_some_and(|current| current.same_channel(sender))
    {
        flows.remove(&key);
        true
    } else {
        false
    }
}
