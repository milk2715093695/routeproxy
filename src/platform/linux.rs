use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;

use tokio::net::TcpStream;

const SO_ORIGINAL_DST: libc::c_int = 80;

pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddrV4> {
    let mut address: libc::sockaddr_in = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // SAFETY: 调用期间 `stream.as_raw_fd()` 是有效的 TCP socket；`address`
    // 指向已清零的 `sockaddr_in`，`length` 初始化为其大小；内核最多写入
    // 这么多字节，返回后先校验长度再读字段。
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length < size_of::<libc::sockaddr_in>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "原始目标地址被截断",
        ));
    }
    if address.sin_family as libc::c_int != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "原始目标不是 IPv4",
        ));
    }

    let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
    let port = u16::from_be(address.sin_port);
    Ok(SocketAddrV4::new(ip, port))
}
