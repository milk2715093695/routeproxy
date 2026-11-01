#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::io;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::net::SocketAddrV4;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use tokio::net::TcpStream;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::original_dst;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn original_dst(_stream: &TcpStream) -> io::Result<SocketAddrV4> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "透明模式仅支持 Linux/Android",
    ))
}
