use std::io;
use std::mem::{size_of, zeroed};
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

/// 用 raw IPv4 socket 伪造“原始目标 → 本机客户端”的 UDP 回包。
/// NFQUEUE 路径没有 conntrack NAT 可依赖，回包必须自己构造。
pub(super) struct RawReply {
    fd: OwnedFd,
}

impl RawReply {
    pub(super) fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // IPPROTO_RAW 已隐含 IP_HDRINCL，不再额外设置。
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    pub(super) fn send_to(
        &self,
        payload: &[u8],
        source: SocketAddrV4,
        destination: SocketAddrV4,
    ) -> io::Result<usize> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let packet = build_packet_with_id(payload, source, destination, id)?;
        let address = socket_addr(destination);
        let result = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                &address as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

#[cfg(test)]
pub(super) fn build_packet(
    payload: &[u8],
    source: SocketAddrV4,
    destination: SocketAddrV4,
) -> io::Result<Vec<u8>> {
    build_packet_with_id(payload, source, destination, 0)
}

fn build_packet_with_id(
    payload: &[u8],
    source: SocketAddrV4,
    destination: SocketAddrV4,
    id: u16,
) -> io::Result<Vec<u8>> {
    const IP_HEADER: usize = 20;
    const UDP_HEADER: usize = 8;
    let total = IP_HEADER + UDP_HEADER + payload.len();
    if total > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP 回包超过 IPv4 最大长度",
        ));
    }
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    // 回包目的地址是本机回环，MTU 足够；不依赖 IP 分片。
    packet[6..8].copy_from_slice(&0_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = libc::IPPROTO_UDP as u8;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    let ip_checksum = checksum(&packet[..IP_HEADER]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = IP_HEADER;
    packet[udp..udp + 2].copy_from_slice(&source.port().to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&destination.port().to_be_bytes());
    packet[udp + 4..udp + 6].copy_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
    packet[udp + 8..].copy_from_slice(payload);
    let udp_len = UDP_HEADER + payload.len();
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&source.ip().octets());
    pseudo.extend_from_slice(&destination.ip().octets());
    pseudo.extend_from_slice(&[0, libc::IPPROTO_UDP as u8]);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[udp..udp + udp_len]);
    let mut udp_checksum = checksum(&pseudo);
    if udp_checksum == 0 {
        udp_checksum = 0xffff;
    }
    packet[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn socket_addr(address: SocketAddrV4) -> libc::sockaddr_in {
    let mut result: libc::sockaddr_in = unsafe { zeroed() };
    result.sin_family = libc::AF_INET as libc::sa_family_t;
    result.sin_port = address.port().to_be();
    result.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    result
}

pub(super) type SharedRawReply = Arc<RawReply>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_has_original_source_and_client_destination() {
        let source: SocketAddrV4 = "1.2.3.4:19999".parse().unwrap();
        let destination: SocketAddrV4 = "192.0.2.10:5353".parse().unwrap();
        let packet = build_packet(b"hello", source, destination).unwrap();
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[9], 17);
        assert_eq!(&packet[12..16], &[1, 2, 3, 4]);
        assert_eq!(&packet[16..20], &[192, 0, 2, 10]);
        assert_eq!(&packet[20..22], &19999_u16.to_be_bytes());
        assert_eq!(&packet[22..24], &5353_u16.to_be_bytes());
        assert_eq!(&packet[28..], b"hello");
    }
}
