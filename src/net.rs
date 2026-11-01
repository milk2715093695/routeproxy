use std::net::{IpAddr, SocketAddr};

/// 在做地址身份判断前，把 IPv4-mapped IPv6 归一成 IPv4。
///
/// macOS 允许用 `::ffff:127.0.0.1` 访问绑定在 `127.0.0.1` 的监听端口；
/// 只比较原始 `SocketAddr` 会被映射地址绕过。
pub fn canonicalize_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), address.port()),
            None => SocketAddr::V6(address),
        },
        address => address,
    }
}

pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

/// 拒绝无法唯一定位远端主机的地址。
pub fn is_invalid_target(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}
