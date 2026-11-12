use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::UdpState;

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NLA_ALIGNTO: usize = 4;
const NLA_HDRLEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

#[repr(C)]
struct NlAttr {
    len: u16,
    kind: u16,
}

#[repr(C)]
struct NfGenMsg {
    family: u8,
    version: u8,
    res_id: u16,
}

#[repr(C, packed)]
struct PacketHeader {
    packet_id: u32,
    hw_protocol: u16,
    hook: u8,
}

#[repr(C, packed)]
struct VerdictHeader {
    verdict: u32,
    id: u32,
}

#[repr(C)]
struct ConfigCmd {
    command: u8,
    pad: u8,
    pf: u16,
}

#[repr(C, packed)]
struct ConfigParams {
    copy_range: u32,
    copy_mode: u8,
}

pub(super) fn run(queue: u16, state: UdpState) -> io::Result<()> {
    let ready = ready_path();
    let mut attempts = 0_u8;
    loop {
        match run_inner(queue, &state, ready.as_deref()) {
            Ok(()) => return Ok(()),
            Err(error) => {
                attempts = attempts.saturating_add(1);
                if attempts >= 10 {
                    tracing::error!(
                        event = "udp_nfqueue",
                        queue,
                        error = %error,
                        "NFQUEUE 连续重建失败，60 秒后继续重试"
                    );
                    attempts = 0;
                    std::thread::sleep(Duration::from_secs(60));
                } else {
                    tracing::error!(
                        event = "udp_nfqueue",
                        queue,
                        error = %error,
                        "NFQUEUE 线程异常退出，1 秒后重建"
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }
}

struct ReadyGuard(Option<PathBuf>);

impl Drop for ReadyGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn run_inner(queue: u16, state: &UdpState, ready: Option<&Path>) -> io::Result<()> {
    let socket = open_socket()?;
    bind_queue(&socket, queue)?;
    clear_timeout(&socket)?;
    let _guard = ReadyGuard(ready.map(Path::to_owned));
    if let Some(path) = ready {
        if let Err(error) = write_ready(path) {
            tracing::warn!(
                event = "udp_nfqueue",
                queue,
                path = %path.display(),
                error = %error,
                "NFQUEUE 就绪文件写入失败，继续运行"
            );
        }
    }
    tracing::info!(event = "udp_nfqueue", queue, "本机 UDP NFQUEUE 已绑定");
    let mut buffer = vec![0_u8; 65_535 + 512];
    let mut last_touch = Instant::now();
    loop {
        let length = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    touch_ready(ready);
                    last_touch = Instant::now();
                    continue;
                }
                _ if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    tracing::warn!(
                        event = "udp_nfqueue",
                        queue,
                        "NFQUEUE 接收缓冲溢出，丢弃当前批次"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                _ => return Err(error),
            }
        }
        let length = (length as usize).min(buffer.len());
        if (length as usize) == buffer.len() {
            tracing::warn!(
                event = "udp_nfqueue",
                queue,
                "NFQUEUE 消息被截断，仍尝试发送 verdict"
            );
        }
        handle_messages(&socket, queue, &buffer[..length], state)?;
        // 持续流量下 recv 不会超时；心跳不能只依赖 WouldBlock。
        if last_touch.elapsed() >= Duration::from_secs(5) {
            touch_ready(ready);
            last_touch = Instant::now();
        }
    }
}

fn write_ready(path: &Path) -> io::Result<()> {
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| "0".to_owned());
    fs::write(path, format!("{}\n{uptime}\n", std::process::id()))
}

fn touch_ready(ready: Option<&Path>) {
    if let Some(path) = ready {
        let _ = write_ready(path);
    }
}

fn ready_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ROUTEPROXY_NFQ_READY") {
        return Some(PathBuf::from(path));
    }
    let path = PathBuf::from("/data/adb/routeproxy/udp-nfq.ready");
    path.parent()
        .is_some_and(|parent| parent.is_dir())
        .then_some(path)
}

fn open_socket() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let receive_buffer: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &receive_buffer as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // 让内核分配 portid，避免同进程多队列时 EADDRINUSE。
    address.nl_pid = 0;
    address.nl_groups = 0;
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    Ok(socket)
}

fn clear_timeout(socket: &OwnedFd) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_queue(socket: &OwnedFd, queue: u16) -> io::Result<()> {
    bind_queue_inner(socket, queue)
}

fn bind_queue_inner(socket: &OwnedFd, queue: u16) -> io::Result<()> {
    let mut message = Vec::new();
    let header_len = size_of::<libc::nlmsghdr>() + size_of::<NfGenMsg>();
    message.resize(header_len, 0);
    let command = ConfigCmd {
        command: NFQNL_CFG_CMD_BIND,
        pad: 0,
        pf: 0,
    };
    put_attr(&mut message, NFQA_CFG_CMD, as_bytes(&command));
    let params = ConfigParams {
        copy_range: 0xFFFF_u32.to_be(),
        copy_mode: NFQNL_COPY_PACKET,
    };
    put_attr(&mut message, NFQA_CFG_PARAMS, as_bytes(&params));
    put_attr(&mut message, NFQA_CFG_QUEUE_MAXLEN, &256_u32.to_be_bytes());
    write_header(
        &mut message,
        (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
        libc::NLM_F_REQUEST | libc::NLM_F_ACK,
        queue,
        libc::AF_UNSPEC as u8,
    );
    send_message(socket, &message)?;

    let mut response = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let length = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                0,
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) && Instant::now() < deadline
            {
                continue;
            }
            return Err(error);
        }
        let mut offset = 0;
        while offset + size_of::<libc::nlmsghdr>() <= length as usize {
            let header = unsafe {
                std::ptr::read_unaligned(response[offset..].as_ptr().cast::<libc::nlmsghdr>())
            };
            let message_len = header.nlmsg_len as usize;
            if message_len < size_of::<libc::nlmsghdr>() || offset + message_len > length as usize {
                break;
            }
            if header.nlmsg_type == libc::NLMSG_ERROR as u16 {
                let error = unsafe {
                    std::ptr::read_unaligned(
                        response[offset + size_of::<libc::nlmsghdr>()..]
                            .as_ptr()
                            .cast::<libc::nlmsgerr>(),
                    )
                };
                if error.error != 0 {
                    return Err(io::Error::from_raw_os_error(-error.error));
                }
                return Ok(());
            }
            // 重绑时旧规则可能已把包投进队列；先丢弃，避免占住队列。
            if header.nlmsg_type & 0xff == NFQNL_MSG_PACKET {
                if let Some((id, _)) = packet_parts(&response[offset..offset + message_len]) {
                    let _ = verdict_drop(socket, queue, id);
                }
            }
            offset += align(message_len);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NFQUEUE 绑定未收到 ACK",
            ));
        }
    }
}

fn handle_messages(
    socket: &OwnedFd,
    queue: u16,
    buffer: &[u8],
    state: &UdpState,
) -> io::Result<()> {
    let mut offset = 0;
    let mut verdict_failures = 0_u32;
    while offset + size_of::<libc::nlmsghdr>() <= buffer.len() {
        let header =
            unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<libc::nlmsghdr>()) };
        let message_len = header.nlmsg_len as usize;
        if message_len < size_of::<libc::nlmsghdr>() || offset + message_len > buffer.len() {
            break;
        }
        let kind = header.nlmsg_type & 0xff;
        if kind == NFQNL_MSG_PACKET {
            if let Some((id, payload)) = packet_parts(&buffer[offset..offset + message_len]) {
                if let Some(payload) = payload {
                    if let Some((client, target, data)) = parse_ipv4_udp(payload) {
                        super::dispatch((client, target), true, data, state);
                    }
                }
                let result = verdict_drop(socket, queue, id);
                if let Err(error) = result {
                    // 单条 verdict 失败不能结束线程，否则剩余队列会永久占住。
                    verdict_failures = verdict_failures.saturating_add(1);
                    tracing::warn!(
                        event = "udp_nfqueue",
                        queue,
                        packet_id = id,
                        error = %error,
                        "发送 NFQUEUE verdict 失败"
                    );
                    if verdict_failures >= 16 {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "NFQUEUE verdict 连续失败",
                        ));
                    }
                } else {
                    verdict_failures = 0;
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NFQUEUE 消息缺少 packet id",
                ));
            }
        }
        offset += align(message_len);
    }
    Ok(())
}

fn packet_parts(message: &[u8]) -> Option<(u32, Option<&[u8]>)> {
    let header_len = size_of::<libc::nlmsghdr>() + align(size_of::<NfGenMsg>());
    if message.len() < header_len {
        return None;
    }
    let mut offset = header_len;
    let mut id = None;
    let mut payload = None;
    while offset + NLA_HDRLEN <= message.len() {
        let attr = unsafe { std::ptr::read_unaligned(message[offset..].as_ptr().cast::<NlAttr>()) };
        let length = attr.len as usize;
        if length < NLA_HDRLEN || offset + length > message.len() {
            break;
        }
        let data = &message[offset + NLA_HDRLEN..offset + length];
        match attr.kind & NLA_TYPE_MASK {
            NFQA_PACKET_HDR if data.len() >= size_of::<PacketHeader>() => {
                let header =
                    unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<PacketHeader>()) };
                id = Some(u32::from_be(header.packet_id));
            }
            NFQA_PAYLOAD => payload = Some(data),
            _ => {}
        }
        offset += align(length);
    }
    Some((id?, payload))
}

fn parse_ipv4_udp(payload: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4, &[u8])> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return None;
    }
    let ip_header = (payload[0] & 0x0f) as usize * 4;
    if ip_header < 20 || payload.len() < ip_header + 8 || payload[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    // 非首片或带 MF 的分片没有完整 UDP 头，不能按完整报文解析。
    let flags_frag = u16::from_be_bytes([payload[6], payload[7]]);
    if flags_frag & 0x3fff != 0 {
        return None;
    }
    let total_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if total_length < ip_header + 8 || total_length > payload.len() {
        return None;
    }
    let udp_length = u16::from_be_bytes([payload[ip_header + 4], payload[ip_header + 5]]) as usize;
    if udp_length < 8 || ip_header + udp_length > total_length {
        return None;
    }
    let source = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let destination = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    let source_port = u16::from_be_bytes([payload[ip_header], payload[ip_header + 1]]);
    let destination_port = u16::from_be_bytes([payload[ip_header + 2], payload[ip_header + 3]]);
    Some((
        SocketAddrV4::new(source, source_port),
        SocketAddrV4::new(destination, destination_port),
        &payload[ip_header + 8..ip_header + udp_length],
    ))
}

fn verdict_drop(socket: &OwnedFd, queue: u16, id: u32) -> io::Result<()> {
    verdict(socket, queue, id, libc::NF_DROP as u32)
}

fn verdict(socket: &OwnedFd, queue: u16, id: u32, action: u32) -> io::Result<()> {
    let mut message = vec![0_u8; size_of::<libc::nlmsghdr>() + size_of::<NfGenMsg>()];
    let verdict = VerdictHeader {
        verdict: action.to_be(),
        id: id.to_be(),
    };
    put_attr(&mut message, NFQA_VERDICT_HDR, as_bytes(&verdict));
    write_header(
        &mut message,
        (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
        libc::NLM_F_REQUEST,
        queue,
        libc::AF_UNSPEC as u8,
    );
    let mut last_error = None;
    for _ in 0..3 {
        match send_message(socket, &message) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "verdict 发送失败")))
}

fn write_header(message: &mut [u8], kind: u16, flags: libc::c_int, queue: u16, family: u8) {
    let header = libc::nlmsghdr {
        nlmsg_len: message.len() as u32,
        nlmsg_type: kind,
        nlmsg_flags: flags as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    unsafe { std::ptr::write_unaligned(message.as_mut_ptr().cast::<libc::nlmsghdr>(), header) };
    let gen = NfGenMsg {
        family,
        version: 0,
        res_id: queue.to_be(),
    };
    unsafe {
        std::ptr::write_unaligned(
            message
                .as_mut_ptr()
                .add(size_of::<libc::nlmsghdr>())
                .cast::<NfGenMsg>(),
            gen,
        )
    };
}

fn put_attr(message: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let start = message.len();
    message.extend_from_slice(&((NLA_HDRLEN + data.len()) as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(data);
    while message.len() % NLA_ALIGNTO != 0 {
        message.push(0);
    }
    debug_assert_eq!(message.len(), start + align(NLA_HDRLEN + data.len()));
}

fn send_message(socket: &OwnedFd, message: &[u8]) -> io::Result<()> {
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address.nl_pid = 0;
    address.nl_groups = 0;
    let result = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn align(length: usize) -> usize {
    (length + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp_payload() {
        let mut packet = vec![0_u8; 20 + 8 + 4];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(32_u16).to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..22].copy_from_slice(&1234_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&12_u16.to_be_bytes());
        packet[28..].copy_from_slice(b"test");
        let (client, target, data) = parse_ipv4_udp(&packet).unwrap();
        assert_eq!(client, "192.0.2.1:1234".parse().unwrap());
        assert_eq!(target, "198.51.100.7:53".parse().unwrap());
        assert_eq!(data, b"test");
    }
}
