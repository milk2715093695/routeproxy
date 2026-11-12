use std::net::SocketAddr;

use anyhow::{bail, Context, Result};

use crate::net::{canonicalize_addr, is_invalid_target};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpUpstream {
    Http(SocketAddr),
    Socks5(SocketAddr),
}

impl TcpUpstream {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (kind, address) = match value.split_once("://") {
            Some(("http", address)) => ("http", address),
            Some(("socks5", address)) => ("socks5", address),
            Some((scheme, _)) => {
                bail!("不支持的 TCP 上游协议: {scheme}，只允许 http:// 或 socks5://")
            }
            None => bail!("TCP 上游必须带 http:// 或 socks5://: {value}"),
        };
        let address = canonicalize_addr(
            address
                .parse::<SocketAddr>()
                .with_context(|| format!("TCP 上游地址无效: {value}"))?,
        );
        validate_address(address)?;
        Ok(match kind {
            "socks5" => Self::Socks5(address),
            _ => Self::Http(address),
        })
    }

    pub fn addr(self) -> SocketAddr {
        match self {
            Self::Http(address) | Self::Socks5(address) => address,
        }
    }

    pub fn scheme(self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Socks5(_) => "socks5",
        }
    }
}

fn validate_address(address: SocketAddr) -> Result<()> {
    if address.port() == 0 {
        bail!("上游不能使用端口 0: {address}");
    }
    if is_invalid_target(address.ip()) {
        bail!("上游不能是未指定、组播或广播地址: {address}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_http_and_socks5_schemes() {
        assert!(matches!(
            TcpUpstream::parse("http://127.0.0.1:8080").unwrap(),
            TcpUpstream::Http(_)
        ));
        assert!(matches!(
            TcpUpstream::parse("socks5://127.0.0.1:1080").unwrap(),
            TcpUpstream::Socks5(_)
        ));
    }

    #[test]
    fn rejects_unknown_scheme_and_bad_port() {
        assert!(TcpUpstream::parse("https://127.0.0.1:443").is_err());
        assert!(TcpUpstream::parse("127.0.0.1:8080").is_err());
        assert!(TcpUpstream::parse("127.0.0.1:0").is_err());
        assert!(TcpUpstream::parse("127.0.0.1:8080/path").is_err());
    }
}
