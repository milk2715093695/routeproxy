use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::net::{canonicalize_addr, is_invalid_target};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub rules: RulesConfig,
    pub logging: LoggingConfig,
    /// 由 `validate` 填充。
    #[serde(skip)]
    listens: Vec<SocketAddr>,
    /// 由 `validate` 填充。
    #[serde(skip)]
    upstream: Option<SocketAddr>,
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
    pub upstream: String,
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

        let upstream = canonicalize_addr(
            self.proxy
                .upstream
                .parse::<SocketAddr>()
                .with_context(|| format!("proxy.upstream 地址无效: {}", self.proxy.upstream))?,
        );
        if upstream.port() == 0 {
            bail!("proxy.upstream 不能使用端口 0: {upstream}");
        }
        if is_invalid_target(upstream.ip()) {
            bail!("proxy.upstream 不能是未指定、组播或广播地址: {upstream}");
        }
        if listens.contains(&upstream) {
            bail!("proxy.upstream 不能指向 proxy.listen 地址: {upstream}");
        }
        self.listens = listens;
        self.upstream = Some(upstream);

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

    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream
            .expect("Config::validate 必须填充 upstream 地址")
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
