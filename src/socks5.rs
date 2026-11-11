use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect_tcp(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, connect_tcp_inner(proxy, host, port))
        .await
        .context("SOCKS5 握手超时")?
}

async fn connect_tcp_inner(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .with_context(|| format!("连接 SOCKS5 上游 {proxy} 失败"))?;
    handshake(&mut stream).await?;
    send_request(&mut stream, 0x01, host, port).await?;
    read_reply(&mut stream).await?;
    Ok(stream)
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub struct UdpAssociation {
    closed: Arc<Notify>,
    udp: UdpSocket,
    relay: SocketAddr,
    // 收包缓冲复用；发包仍按数据报分配。
    packet: Vec<u8>,
    control_task: JoinHandle<()>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.control_task.abort();
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
impl UdpAssociation {
    pub async fn connect(proxy: SocketAddr) -> Result<Self> {
        timeout(HANDSHAKE_TIMEOUT, Self::connect_inner(proxy))
            .await
            .context("SOCKS5 UDP 握手超时")?
    }

    async fn connect_inner(proxy: SocketAddr) -> Result<Self> {
        let mut control = TcpStream::connect(proxy)
            .await
            .with_context(|| format!("连接 SOCKS5 上游 {proxy} 失败"))?;
        handshake(&mut control).await?;
        // 绑定必须在发送 ASSOCIATE 之前；整个 association 复用这个源 socket。
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("创建 SOCKS5 UDP 客户端 socket 失败")?;
        send_request(&mut control, 0x03, "0.0.0.0", 0).await?;
        let relay = read_reply(&mut control).await?;
        let relay = if relay.ip().is_unspecified() {
            SocketAddr::new(proxy.ip(), relay.port())
        } else {
            relay
        };
        if relay.port() == 0 {
            bail!("SOCKS5 UDP relay 端口为 0");
        }
        if relay.is_ipv6() {
            bail!("SOCKS5 UDP relay 是 IPv6，0.2.0 不支持");
        }

        // 控制连接关闭即 association 失效，通知 flow 回收。
        let closed = Arc::new(Notify::new());
        let notify = Arc::clone(&closed);
        let control_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 1];
            loop {
                match control.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            notify.notify_one();
        });

        Ok(Self {
            closed,
            udp,
            relay,
            packet: vec![0_u8; 65_535],
            control_task,
        })
    }

    #[cfg(test)]
    pub async fn closed(&self) {
        self.closed.notified().await;
    }

    /// 在持有 `&mut self` 接收 UDP 时等待控制连接关闭。
    pub fn closed_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.closed)
    }

    pub async fn send_to(&self, target: SocketAddrV4, payload: &[u8]) -> Result<()> {
        let packet = encode_udp_packet(target, payload);
        self.udp
            .send_to(&packet, self.relay)
            .await
            .context("发送 SOCKS5 UDP 数据失败")?;
        Ok(())
    }

    pub async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<Option<(SocketAddrV4, usize)>> {
        let (length, source) = self
            .udp
            .recv_from(&mut self.packet)
            .await
            .context("接收 SOCKS5 UDP 数据失败")?;
        if source != self.relay {
            tracing::debug!(
                event = "socks5_udp",
                source = %source,
                relay = %self.relay,
                "丢弃非 relay 来源的 SOCKS5 UDP 数据"
            );
            return Ok(None);
        }
        let (target, payload_offset, payload_length) =
            match decode_udp_packet(&self.packet[..length]) {
                Ok(decoded) => decoded,
                Err(error) => {
                    tracing::debug!(
                        event = "socks5_udp",
                        source = %source,
                        error = %format!("{error:#}"),
                        "丢弃无法解析的 SOCKS5 UDP 响应"
                    );
                    return Ok(None);
                }
            };
        if payload_length > buffer.len() {
            tracing::debug!(
                event = "socks5_udp",
                source = %source,
                length = payload_length,
                buffer = buffer.len(),
                "丢弃超过接收缓冲区的 SOCKS5 UDP 响应"
            );
            return Ok(None);
        }
        buffer[..payload_length]
            .copy_from_slice(&self.packet[payload_offset..payload_offset + payload_length]);
        Ok(Some((target, payload_length)))
    }
}

async fn handshake(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .context("发送 SOCKS5 握手失败")?;
    let mut reply = [0_u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .context("读取 SOCKS5 握手响应失败")?;
    if reply != [0x05, 0x00] {
        bail!("SOCKS5 握手失败: {:02x?}", reply);
    }
    Ok(())
}

async fn send_request(stream: &mut TcpStream, command: u8, host: &str, port: u16) -> Result<()> {
    let mut request = Vec::with_capacity(32);
    request.extend_from_slice(&[0x05, command, 0x00]);
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if host.len() > u8::MAX as usize {
            bail!("SOCKS5 目标域名过长");
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .context("发送 SOCKS5 请求失败")
}

async fn read_reply(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0_u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("读取 SOCKS5 响应失败")?;
    if head[0] != 0x05 {
        bail!("SOCKS5 响应版本无效: {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 请求失败，REP={}", head[1]);
    }
    let (address, domain) = match head[3] {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            (Some(IpAddr::V4(Ipv4Addr::from(bytes))), None)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes).await?;
            (Some(IpAddr::V6(bytes.into())), None)
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut host = vec![0_u8; length[0] as usize];
            stream.read_exact(&mut host).await?;
            let host = String::from_utf8(host).context("SOCKS5 域名不是 UTF-8")?;
            (None, Some(host))
        }
        atyp => bail!("SOCKS5 响应地址类型无效: {atyp}"),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if let Some(domain) = domain {
        let mut addresses = tokio::net::lookup_host((domain.as_str(), port))
            .await
            .with_context(|| format!("SOCKS5 响应域名解析失败: {domain}"))?;
        return addresses
            .next()
            .with_context(|| format!("SOCKS5 响应域名无地址: {domain}"));
    }
    Ok(SocketAddr::new(address.expect("非域名地址必然存在"), port))
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn encode_udp_packet(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn decode_udp_packet(packet: &[u8]) -> Result<(SocketAddrV4, usize, usize)> {
    if packet.len() < 10 {
        bail!("SOCKS5 UDP 响应过短");
    }
    if packet[0..2] != [0x00, 0x00] {
        bail!("SOCKS5 UDP RSV 非零");
    }
    if packet[2] != 0x00 {
        bail!("SOCKS5 UDP 分片不受支持");
    }
    if packet[3] != 0x01 {
        bail!("SOCKS5 UDP 响应不是 IPv4");
    }
    let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    Ok((SocketAddrV4::new(ip, port), 10, packet.len() - 10))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn complete_udp_associate(control: &mut TcpStream, relay: SocketAddrV4) {
        let mut greeting = [0_u8; 3];
        control.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        control.write_all(&[0x05, 0x00]).await.unwrap();

        let mut request = [0_u8; 4];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[0x05, 0x03, 0x00]);
        assert_eq!(request[3], 0x01);
        let mut address = [0_u8; 4];
        control.read_exact(&mut address).await.unwrap();
        let mut port = [0_u8; 2];
        control.read_exact(&mut port).await.unwrap();

        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        reply.extend_from_slice(&relay.ip().octets());
        reply.extend_from_slice(&relay.port().to_be_bytes());
        control.write_all(&reply).await.unwrap();
    }

    #[test]
    fn udp_packet_roundtrip() {
        let target: SocketAddrV4 = "1.1.1.1:53".parse().unwrap();
        let packet = encode_udp_packet(target, b"dns");
        let (decoded, offset, length) = decode_udp_packet(&packet).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(&packet[offset..offset + length], b"dns");
    }

    #[test]
    fn udp_packet_rejects_fragment() {
        let target: SocketAddrV4 = "1.1.1.1:53".parse().unwrap();
        let mut packet = encode_udp_packet(target, b"dns");
        packet[2] = 1;
        assert!(decode_udp_packet(&packet).is_err());
    }

    #[test]
    fn udp_packet_rejects_ipv6() {
        let mut packet = vec![0x00, 0x00, 0x00, 0x04];
        packet.extend_from_slice(&[0_u8; 16]);
        packet.extend_from_slice(&[0_u8; 2]);
        assert!(decode_udp_packet(&packet).is_err());
    }

    #[tokio::test]
    async fn udp_association_observes_control_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            complete_udp_associate(&mut control, "127.0.0.1:9".parse().unwrap()).await;
            // 关闭控制 TCP；UDP association 必须能观察到。
        });

        let association = UdpAssociation::connect(proxy).await.unwrap();
        timeout(Duration::from_secs(1), association.closed())
            .await
            .expect("控制连接关闭未通知");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_association_drop_aborts_control_task() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            complete_udp_associate(&mut control, "127.0.0.1:9".parse().unwrap()).await;
            let mut byte = [0_u8; 1];
            assert_eq!(
                control.read(&mut byte).await.unwrap(),
                0,
                "控制连接未在 Drop 后关闭"
            );
        });

        let association = UdpAssociation::connect(proxy).await.unwrap();
        drop(association);
        timeout(Duration::from_secs(1), server)
            .await
            .expect("Drop 后控制任务未退出")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_associate_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();

            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_port = relay.local_addr().unwrap().port();
            complete_udp_associate(
                &mut control,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, relay_port),
            )
            .await;

            let mut packet = [0_u8; 1024];
            let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
            // 先回一个畸形包，确认 recv_from 跳过它而不是终止整个 flow。
            relay
                .send_to(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1], peer)
                .await
                .unwrap();
            relay.send_to(&packet[..length], peer).await.unwrap();
        });

        let mut association = UdpAssociation::connect(proxy).await.unwrap();
        let target: SocketAddrV4 = "1.1.1.1:53".parse().unwrap();
        association.send_to(target, b"ping").await.unwrap();
        let mut buffer = [0_u8; 64];
        assert!(association.recv_from(&mut buffer).await.unwrap().is_none());
        let (reply_target, length) = association.recv_from(&mut buffer).await.unwrap().unwrap();
        assert_eq!(reply_target, target);
        assert_eq!(&buffer[..length], b"ping");
        server.abort();
    }
}
