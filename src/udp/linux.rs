use std::collections::HashMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, Semaphore};

use crate::config::Config;
use crate::engine::Engine;

mod flow;
mod nfqueue;
mod raw;
use flow::{queue_datagram, run_flow, FlowKey, FlowRegistry, FlowTask};
use raw::{RawReply, SharedRawReply};

// 每 flow 最多缓冲 8 个数据报；满则丢当前数据报，不拆已有 flow。
const FLOW_QUEUE: usize = 8;
const FLOW_BUFFER_BUDGET: usize = 64 * 1024 * 1024;
// 每 flow 预留两块 64 KiB：接收缓冲和 SOCKS5 包缓冲；direct flow 只占一块。
const FLOW_MEMORY_PER_FLOW: usize = 2 * BUFFER_SIZE;
const FLOW_MEMORY_BUDGET: usize = 64 * 1024 * 1024;
const MAX_FLOWS: usize = FLOW_MEMORY_BUDGET / FLOW_MEMORY_PER_FLOW;
// 同一源 IP 最多 256 flow；本机所有 app 共享一个 IP，阈值不能按单 app 估。
const MAX_FLOWS_PER_CLIENT: usize = 256;
const MAX_FLOWS_PER_SOCKET: usize = 64;
// 上游失败后 5 秒内不再重建同一 flow。
const FLOW_FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
pub(super) const BUFFER_SIZE: usize = 65_535;
// 必须与 packaging/android/scripts/common.sh 的 UDP_NFQ_QUEUE 保持一致。
const NFQUEUE_NUM: u16 = 21072;
pub(super) type ReplyRegistry = Arc<Mutex<HashMap<SocketAddrV4, Weak<TokioUdpSocket>>>>;
pub(super) type FlowFailures = Arc<Mutex<HashMap<FlowKey, Instant>>>;

#[derive(Clone)]
struct UdpState {
    config: Arc<Config>,
    engine: Arc<Engine>,
    registry: FlowRegistry,
    failures: FlowFailures,
    replies: ReplyRegistry,
    budget: Arc<Semaphore>,
    flow_budget: Arc<Semaphore>,
    handle: tokio::runtime::Handle,
    listen_port: u16,
    raw_reply: Option<SharedRawReply>,
}

pub async fn serve(config: Arc<Config>, engine: Arc<Engine>) -> Result<()> {
    let port = config
        .listen_addresses()
        .first()
        .context("transparent 配置缺少监听地址")?
        .port();
    let socket = Arc::new(
        bind_ingress(port).with_context(|| format!("绑定 UDP TPROXY 入口 0.0.0.0:{port} 失败"))?,
    );
    let raw_reply = match RawReply::new() {
        Ok(raw) => Some(Arc::new(raw)),
        Err(error) => {
            tracing::warn!(
                event = "udp_nfqueue",
                error = %error,
                "创建 UDP 本机回包 raw socket 失败，本机 UDP 将降级"
            );
            None
        }
    };
    let state = UdpState {
        config,
        engine,
        registry: Arc::new(Mutex::new(HashMap::new())),
        failures: Arc::new(Mutex::new(HashMap::new())),
        replies: Arc::new(Mutex::new(HashMap::new())),
        budget: Arc::new(Semaphore::new(FLOW_BUFFER_BUDGET)),
        flow_budget: Arc::new(Semaphore::new(FLOW_MEMORY_BUDGET)),
        handle: tokio::runtime::Handle::current(),
        listen_port: port,
        raw_reply,
    };
    if state.raw_reply.is_some() {
        let nfqueue_state = state.clone();
        std::thread::Builder::new()
            .name("routeproxy-udp-nfqueue".to_owned())
            .spawn(move || nfqueue::run(NFQUEUE_NUM, nfqueue_state))
            .context("启动 UDP NFQUEUE 线程失败")?;
    } else {
        tracing::warn!(
            event = "udp_nfqueue",
            "raw socket 不可用，本机 UDP 不启用 NFQUEUE，转发继续"
        );
    }
    let thread = std::thread::Builder::new()
        .name("routeproxy-udp-ingress".to_owned())
        .spawn(move || ingress_loop(socket, state))
        .context("启动 UDP ingress 线程失败")?;

    tracing::info!(event = "udp_ingress", port, "透明 UDP ingress 已启动");
    let result = tokio::task::spawn_blocking(move || thread.join())
        .await
        .context("等待 UDP ingress 线程失败")?;
    match result {
        Ok(()) => unreachable!("UDP ingress 线程不会正常退出"),
        Err(payload) => bail!("UDP ingress 线程 panic: {payload:?}"),
    }
}

fn ingress_loop(socket: Arc<UdpSocket>, state: UdpState) {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let (client, target, length) = match recv_original(&socket, &mut buffer) {
            Ok(packet) => packet,
            Err(error) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    tracing::warn!(
                        event = "udp_ingress",
                        error = %error,
                        "读取 UDP TPROXY 数据失败"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
        };
        dispatch((client, target), false, &buffer[..length], &state);
    }
}

fn dispatch(key: FlowKey, local: bool, payload: &[u8], state: &UdpState) {
    let (client, target) = key;
    let config = &state.config;
    let engine = &state.engine;
    let registry = &state.registry;
    let failures = &state.failures;
    let replies = &state.replies;
    let budget = &state.budget;
    let flow_budget = &state.flow_budget;
    let handle = &state.handle;
    let listen_port = state.listen_port;
    if target.port() == 0 || target.port() == listen_port {
        tracing::debug!(
            event = "udp_reject",
            transport = "udp",
            client = %client,
            target = %target,
            reason = "目标是本代理监听端口或端口 0",
            "拒绝 UDP 目标"
        );
        return;
    }
    if config.is_forbidden_target(SocketAddr::V4(target)) {
        tracing::debug!(
            event = "udp_reject",
            transport = "udp",
            client = %client,
            target = %target,
            reason = "目标是本代理监听地址",
            "拒绝 UDP 目标"
        );
        return;
    }
    if config.is_udp_rejected(target.port()) {
        // reject_ports 在创建 flow 前直接丢弃，避免为注定拒绝的目标
        // 分配 flow、spawn 任务并打印 flow 级日志。
        tracing::debug!(
            event = "udp_reject",
            transport = "udp",
            client = %client,
            target = %target,
            reason = "目标端口在 udp.reject_ports 中",
            "拒绝 UDP 目标"
        );
        return;
    }

    if flow_in_cooldown(failures, key) {
        tracing::debug!(
            event = "udp_flow_backoff",
            transport = "udp",
            client = %client,
            target = %target,
            "UDP flow 刚失败，退避期内丢弃数据报"
        );
        return;
    }

    let mut flows = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(sender) = flows.get(&key) {
        if sender.capacity() == 0 {
            if sender.is_closed() {
                flows.remove(&key);
            } else {
                tracing::debug!(
                    event = "udp_flow_queue_full",
                    transport = "udp",
                    client = %client,
                    target = %target,
                    "UDP flow 队列已满，丢弃数据报"
                );
            }
            return;
        }
        let Some(queued) = queue_datagram(budget, payload) else {
            tracing::debug!(
                event = "udp_buffer_limit",
                transport = "udp",
                client = %client,
                target = %target,
                limit = FLOW_BUFFER_BUDGET,
                "UDP 队列字节预算已满，丢弃数据报"
            );
            return;
        };
        match sender.try_send(queued) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!(
                    event = "udp_flow_queue_full",
                    transport = "udp",
                    client = %client,
                    target = %target,
                    "UDP flow 队列已满，丢弃数据报"
                );
                return;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                flows.remove(&key);
            }
        }
    }
    if flows.len() >= MAX_FLOWS {
        tracing::debug!(
            event = "udp_flow_limit",
            transport = "udp",
            client = %client,
            target = %target,
            limit = MAX_FLOWS,
            "UDP flow 数量达到上限，丢弃数据报"
        );
        return;
    }
    let client_flows = flows
        .keys()
        .filter(|(existing_client, _)| existing_client.ip() == client.ip())
        .count();
    if client_flows >= MAX_FLOWS_PER_CLIENT {
        tracing::debug!(
            event = "udp_client_flow_limit",
            transport = "udp",
            client = %client,
            target = %target,
            limit = MAX_FLOWS_PER_CLIENT,
            "单个客户端 UDP flow 数量达到上限，丢弃数据报"
        );
        return;
    }
    let socket_flows = flows
        .keys()
        .filter(|(existing_client, _)| *existing_client == client)
        .count();
    if socket_flows >= MAX_FLOWS_PER_SOCKET {
        tracing::debug!(
            event = "udp_socket_flow_limit",
            transport = "udp",
            client = %client,
            target = %target,
            limit = MAX_FLOWS_PER_SOCKET,
            "单个源端口 UDP flow 数量达到上限，丢弃数据报"
        );
        return;
    }

    let Ok(flow_permit) =
        Arc::clone(flow_budget).try_acquire_many_owned(FLOW_MEMORY_PER_FLOW as u32)
    else {
        tracing::debug!(
            event = "udp_flow_memory_limit",
            transport = "udp",
            client = %client,
            target = %target,
            limit = FLOW_MEMORY_BUDGET,
            "UDP flow 缓冲预算已满，丢弃数据报"
        );
        return;
    };

    let Some(queued) = queue_datagram(budget, payload) else {
        tracing::debug!(
            event = "udp_buffer_limit",
            transport = "udp",
            client = %client,
            target = %target,
            limit = FLOW_BUFFER_BUDGET,
            "UDP 队列字节预算已满，丢弃数据报"
        );
        return;
    };
    let (sender, receiver) = mpsc::channel(FLOW_QUEUE);
    // 新 channel 容量非零，首包不可能失败。
    sender
        .try_send(queued)
        .expect("新建 UDP flow channel 必然可写");
    flows.insert(key, sender.clone());
    drop(flows);

    let config = Arc::clone(config);
    let engine = Arc::clone(engine);
    let registry = Arc::clone(registry);
    let failures = Arc::clone(failures);
    let replies = Arc::clone(replies);
    let raw_reply = state.raw_reply.clone();
    handle.spawn(async move {
        run_flow(FlowTask {
            key,
            config,
            engine,
            receiver,
            registry,
            failures,
            replies,
            local,
            raw_reply,
            sender,
            permit: flow_permit,
        })
        .await;
    });
}

fn flow_in_cooldown(failures: &FlowFailures, key: FlowKey) -> bool {
    let now = Instant::now();
    let mut failures = failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match failures.get(&key) {
        Some(until) if now < *until => true,
        Some(_) => {
            failures.remove(&key);
            false
        }
        None => false,
    }
}

fn bind_ingress(port: u16) -> io::Result<UdpSocket> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = configure_udp_socket(fd) {
        close_fd(fd);
        return Err(error);
    }
    let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    if let Err(error) = bind_raw(fd, address) {
        close_fd(fd);
        return Err(error);
    }
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

fn bind_reply(address: SocketAddrV4) -> io::Result<UdpSocket> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        set_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        set_int(fd, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
        bind_raw(fd, address)
    })();
    if let Err(error) = result {
        close_fd(fd);
        return Err(error);
    }
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    socket.set_nonblocking(true)?;
    Ok(socket)
}

// 同一目标可能同时有多个客户端 flow；回包 socket 必须按目标共享，
// 否则绑定相同 target:port 的第二个 socket 会抢包或 EADDRINUSE。
pub(super) fn reply_for(
    registry: &ReplyRegistry,
    target: SocketAddrV4,
) -> io::Result<Arc<TokioUdpSocket>> {
    let mut replies = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(socket) = replies.get(&target).and_then(Weak::upgrade) {
        return Ok(socket);
    }
    // 清掉已经随 flow 结束而释放的弱引用，避免历史目标无限堆积。
    replies.retain(|_, socket| socket.strong_count() > 0);
    let socket = TokioUdpSocket::from_std(bind_reply(target)?)?;
    let socket = Arc::new(socket);
    replies.insert(target, Arc::downgrade(&socket));
    Ok(socket)
}

fn configure_udp_socket(fd: RawFd) -> io::Result<()> {
    // ingress 必须是独占绑定：SO_REUSEADDR 会让第二个进程/旧实例同时
    // bind 0.0.0.0:PORT，流量被随机分走，表现为 UDP 黑洞。
    set_int(fd, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
    set_int(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)
}

fn set_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_raw(fd: RawFd, address: SocketAddrV4) -> io::Result<()> {
    let sockaddr = socket_addr(address);
    let result = unsafe {
        libc::bind(
            fd,
            &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn recv_original(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(SocketAddrV4, SocketAddrV4, usize)> {
    let mut address: libc::sockaddr_in = unsafe { zeroed() };
    let mut control = [0_u64; 16];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
    message.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[u64; 16]>();

    let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP 控制消息被截断",
        ));
    }
    if message.msg_namelen < size_of::<libc::sockaddr_in>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP 来源地址被截断",
        ));
    }
    let client = sockaddr_v4(&address)?;
    let target = original_dst(&message)?;
    Ok((client, target, length as usize))
}

fn original_dst(message: &libc::msghdr) -> io::Result<SocketAddrV4> {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        let minimum = size_of::<libc::cmsghdr>() + size_of::<libc::sockaddr_in>();
        if current.cmsg_len < minimum {
            header = unsafe { libc::CMSG_NXTHDR(message, header) };
            continue;
        }
        if current.cmsg_level == libc::SOL_IP && current.cmsg_type == libc::IP_ORIGDSTADDR {
            let data = unsafe { libc::CMSG_DATA(header) as *const libc::sockaddr_in };
            return sockaddr_v4(unsafe { &*data });
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "UDP 缺少 IP_ORIGDSTADDR 控制消息",
    ))
}

fn sockaddr_v4(address: &libc::sockaddr_in) -> io::Result<SocketAddrV4> {
    if address.sin_family as libc::c_int != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP 地址不是 IPv4",
        ));
    }
    let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
    Ok(SocketAddrV4::new(ip, u16::from_be(address.sin_port)))
}

fn socket_addr(address: SocketAddrV4) -> libc::sockaddr_in {
    let mut result: libc::sockaddr_in = unsafe { zeroed() };
    result.sin_family = libc::AF_INET as libc::sa_family_t;
    result.sin_port = address.port().to_be();
    result.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    result
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

use std::os::fd::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_failure_cooldown_blocks_until_expiry() {
        let failures: FlowFailures = Arc::new(Mutex::new(HashMap::new()));
        let key = (
            "192.0.2.1:1234".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        );
        failures
            .lock()
            .unwrap()
            .insert(key, Instant::now() + Duration::from_secs(1));
        assert!(flow_in_cooldown(&failures, key));

        failures
            .lock()
            .unwrap()
            .insert(key, Instant::now() - Duration::from_secs(1));
        assert!(!flow_in_cooldown(&failures, key));
    }

    #[test]
    fn queue_budget_is_released_when_datagram_drops() {
        let budget = Arc::new(Semaphore::new(4));
        let first = queue_datagram(&budget, b"1234").expect("预算足够");
        assert!(queue_datagram(&budget, b"x").is_none());
        drop(first);
        assert!(queue_datagram(&budget, b"x").is_some());
    }
}
