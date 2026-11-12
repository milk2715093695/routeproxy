use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::net::{canonicalize_addr, is_invalid_target};
use crate::upstream::TcpUpstream;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub udp: UdpConfig,
    pub rules: RulesConfig,
    pub logging: LoggingConfig,
    // 以下缓存字段由 validate 填充，serde 不读取。
    #[serde(skip)]
    listens: Vec<SocketAddr>,
    #[serde(skip)]
    tcp_upstream: Option<TcpUpstream>,
    #[serde(skip)]
    udp_upstream: Option<SocketAddr>,
    #[serde(skip)]
    exclude_ports: HashSet<u16>,
    #[serde(skip)]
    udp_reject_ports: HashSet<u16>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Http,
    Transparent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub mode: Mode,
    pub listen: Vec<String>,
    /// TCP 上游；必须带 http:// 或 socks5://。
    pub upstream: String,
    /// UDP 上游；只接受 socks5://。
    #[serde(default)]
    pub udp_upstream: Option<String>,
    /// 同时活跃的 TCP 连接/请求上限。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// 双向连接无数据多久后回收；避免半关闭连接长期占用槽位。
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// 目标端口排除；TCP/UDP 都生效。
    pub exclude_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    pub enabled: bool,
    pub default: UdpDefault,
    /// UDP 专用拒绝端口；与 exclude_ports 不得重叠。
    pub reject_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum UdpDefault {
    #[default]
    Proxy,
    Direct,
    Reject,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    pub file: PathBuf,
    #[serde(default = "default_true")]
    pub reload: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub file: PathBuf,
    pub level: String,
    #[serde(default = "default_max_size")]
    pub max_size_mb: u64,
    #[serde(default = "default_keep")]
    pub keep: usize,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        let mut config: Self = toml::from_str(&contents)
            .with_context(|| format!("解析配置失败: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> Result<()> {
        if self.rules.file.as_os_str().is_empty() {
            bail!("rules.file 不能为空");
        }
        if self.logging.file.as_os_str().is_empty() {
            bail!("logging.file 不能为空");
        }
        if self.proxy.listen.is_empty() {
            bail!("proxy.listen 至少需要一个地址");
        }
        if self.proxy.max_connections == 0 {
            bail!("proxy.max_connections 必须大于 0");
        }
        if self.proxy.idle_timeout_secs == 0 {
            bail!("proxy.idle_timeout_secs 必须大于 0");
        }

        let mut listens = Vec::with_capacity(self.proxy.listen.len());
        for listen in &self.proxy.listen {
            let address = canonicalize_addr(
                listen
                    .parse::<SocketAddr>()
                    .with_context(|| format!("proxy.listen 地址无效: {listen}"))?,
            );
            if address.port() == 0 {
                bail!("proxy.listen 不能使用端口 0: {address}");
            }
            if !address.ip().is_loopback() {
                bail!("proxy.listen 必须是回环地址: {address}");
            }
            if listens.contains(&address) {
                bail!("proxy.listen 包含重复地址: {address}");
            }
            listens.push(address);
        }

        if self.proxy.mode == Mode::Transparent
            && (listens.len() != 1 || listens[0].ip() != IpAddr::V4(Ipv4Addr::LOCALHOST))
        {
            bail!("transparent 模式要求恰好一个 127.0.0.1 监听地址");
        }

        let tcp_upstream = TcpUpstream::parse(&self.proxy.upstream)?;
        let tcp_address = tcp_upstream.addr();
        if listens.contains(&tcp_address) {
            bail!("proxy.upstream 不能指向 proxy.listen 地址: {tcp_address}");
        }
        if self.proxy.mode == Mode::Http && matches!(tcp_upstream, TcpUpstream::Socks5(_)) {
            bail!("HTTP 模式需要 HTTP TCP 上游，socks5:// 仅用于 transparent 模式");
        }

        let mut exclude_ports = HashSet::with_capacity(self.routing.exclude_ports.len());
        for port in &self.routing.exclude_ports {
            if *port == 0 {
                bail!("routing.exclude_ports 不能包含端口 0");
            }
            exclude_ports.insert(*port);
        }

        let mut udp_reject_ports = HashSet::with_capacity(self.udp.reject_ports.len());
        for port in &self.udp.reject_ports {
            if *port == 0 {
                bail!("udp.reject_ports 不能包含端口 0");
            }
            udp_reject_ports.insert(*port);
        }
        if !exclude_ports.is_disjoint(&udp_reject_ports) {
            let overlap: Vec<u16> = exclude_ports
                .intersection(&udp_reject_ports)
                .copied()
                .collect();
            bail!(
                "routing.exclude_ports 与 udp.reject_ports 不能重叠: {:?}",
                overlap
            );
        }

        let udp_upstream = match self.proxy.udp_upstream.as_deref() {
            Some(value) => {
                let parsed = TcpUpstream::parse(value)
                    .with_context(|| format!("proxy.udp_upstream 无效: {value}"))?;
                if !matches!(parsed, TcpUpstream::Socks5(_)) {
                    bail!("proxy.udp_upstream 只支持 socks5://: {value}");
                }
                let address = parsed.addr();
                if address.is_ipv6() {
                    bail!("proxy.udp_upstream 只支持 IPv4 上游: {address}");
                }
                if listens.contains(&address) {
                    bail!("proxy.udp_upstream 不能指向 proxy.listen 地址: {address}");
                }
                Some(address)
            }
            None => None,
        };

        if self.udp.enabled {
            if self.proxy.mode != Mode::Transparent {
                bail!("udp.enabled 需要 proxy.mode = \"transparent\"");
            }
            if udp_upstream.is_none() {
                bail!("udp.enabled 需要配置 proxy.udp_upstream = \"socks5://...\"");
            }
        } else if self.proxy.udp_upstream.is_some() {
            // 配了 UDP 上游却关闭 UDP，Android 脚本不会装规则，UDP 会全部直连。
            bail!("proxy.udp_upstream 已配置但 udp.enabled = false；请启用 UDP 或删除该配置");
        }

        self.listens = listens;
        self.tcp_upstream = Some(tcp_upstream);
        self.udp_upstream = udp_upstream;
        self.exclude_ports = exclude_ports;
        self.udp_reject_ports = udp_reject_ports;

        if self.logging.max_size_mb == 0 {
            bail!("logging.max_size_mb 必须大于 0");
        }
        if self.logging.keep == 0 {
            bail!("logging.keep 必须大于 0");
        }
        crate::logging::parse_level(&self.logging.level)?;
        if self.proxy.mode == Mode::Transparent
            && !cfg!(any(target_os = "linux", target_os = "android"))
        {
            bail!("proxy.mode = \"transparent\" 仅支持 Linux/Android");
        }

        Ok(())
    }

    /// 本代理监听地址或不可用目标。
    pub fn is_forbidden_target(&self, target: SocketAddr) -> bool {
        let target = canonicalize_addr(target);
        if is_invalid_target(target.ip()) {
            return true;
        }
        self.listens.iter().any(|listen| *listen == target)
    }

    pub fn listen_addresses(&self) -> &[SocketAddr] {
        &self.listens
    }

    pub fn tcp_upstream(&self) -> TcpUpstream {
        self.tcp_upstream
            .expect("Config::validate 必须填充 TCP 上游地址")
    }

    pub fn tcp_upstream_addr(&self) -> SocketAddr {
        self.tcp_upstream().addr()
    }

    pub fn udp_upstream_addr(&self) -> Option<SocketAddr> {
        self.udp_upstream
    }

    pub fn udp_enabled(&self) -> bool {
        self.udp.enabled
    }

    pub fn max_connections(&self) -> usize {
        self.proxy.max_connections
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.proxy.idle_timeout_secs)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    pub fn udp_default(&self) -> UdpDefault {
        self.udp.default
    }

    pub fn is_excluded_port(&self, port: u16) -> bool {
        self.exclude_ports.contains(&port)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    pub fn is_udp_rejected(&self, port: u16) -> bool {
        self.udp_reject_ports.contains(&port)
    }
}

fn default_true() -> bool {
    true
}

fn default_max_size() -> u64 {
    5
}

fn default_keep() -> usize {
    3
}

fn default_max_connections() -> usize {
    4096
}

fn default_idle_timeout_secs() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn load(text: &str) -> Result<Config> {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        Config::load(file.path())
    }

    fn base(proxy: &str) -> String {
        format!(
            "{proxy}\n[rules]\nfile = \"/tmp/rules.toml\"\n[logging]\nfile = \"/tmp/routeproxy.log\"\nlevel = \"info\"\n"
        )
    }

    #[test]
    fn upstream_requires_scheme() {
        let result = load(&base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"127.0.0.1:9910\"",
        ));
        assert!(result.is_err());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn udp_requires_transparent_socks5_upstream() {
        let text = base(
            "[proxy]\nmode = \"transparent\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nudp_upstream = \"http://127.0.0.1:9909\"\n[udp]\nenabled = true",
        );
        assert!(load(&text).is_err());

        let text = base(
            "[proxy]\nmode = \"transparent\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\n[udp]\nenabled = true",
        );
        assert!(load(&text).is_err());

        let text = base(
            "[proxy]\nmode = \"transparent\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nudp_upstream = \"socks5://127.0.0.1:9909\"\n[udp]\nenabled = true",
        );
        assert!(load(&text).is_ok());
    }

    #[test]
    fn udp_upstream_requires_udp_enabled() {
        let text = base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nudp_upstream = \"socks5://127.0.0.1:9909\"",
        );
        assert!(load(&text).is_err());
    }

    #[test]
    fn udp_reject_overlap_with_exclude_ports_fails() {
        let text = base(
            "[proxy]\nmode = \"transparent\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nudp_upstream = \"socks5://127.0.0.1:9909\"\n[routing]\nexclude_ports = [53, 443]\n[udp]\nenabled = true\nreject_ports = [443]",
        );
        assert!(load(&text).is_err());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn udp_ports_are_deduplicated() {
        let text = base(
            "[proxy]\nmode = \"transparent\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nudp_upstream = \"socks5://127.0.0.1:9909\"\n[routing]\nexclude_ports = [53, 53]\n[udp]\nenabled = true\nreject_ports = [443, 443]",
        );
        let config = load(&text).unwrap();
        assert!(config.is_excluded_port(53));
        assert!(config.is_udp_rejected(443));
    }

    #[test]
    fn connection_limits_have_safe_defaults() {
        let config = load(&base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"",
        ))
        .unwrap();
        assert_eq!(config.max_connections(), 4096);
        assert_eq!(config.idle_timeout(), Duration::from_secs(300));

        let text = base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nmax_connections = 0",
        );
        assert!(load(&text).is_err());

        let text = base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"http://127.0.0.1:9910\"\nidle_timeout_secs = 0",
        );
        assert!(load(&text).is_err());
    }

    #[test]
    fn http_mode_rejects_socks5_tcp_upstream() {
        let text = base(
            "[proxy]\nmode = \"http\"\nlisten = [\"127.0.0.1:6045\"]\nupstream = \"socks5://127.0.0.1:9910\"",
        );
        assert!(load(&text).is_err());
    }
}
