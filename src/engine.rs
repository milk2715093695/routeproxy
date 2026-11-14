use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration as TokioDuration};

use crate::net::canonicalize_ip;
use crate::rules::model::Rules;

const DNS_TIMEOUT: TokioDuration = TokioDuration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Direct,
    Proxy,
}

impl fmt::Display for Decision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
        })
    }
}

#[derive(Debug, Clone)]
pub struct HostResolution {
    pub decision: Decision,
    /// Direct 命中的地址；`None` 表示交给连接层解析。
    pub direct_ips: Option<Vec<IpAddr>>,
}

pub struct Engine {
    rules: RwLock<Arc<Rules>>,
    rules_file: PathBuf,
}

impl Engine {
    pub fn new(rules_file: &Path) -> Result<Self> {
        let rules = Rules::load(rules_file)?;
        Ok(Self {
            rules: RwLock::new(Arc::new(rules)),
            rules_file: rules_file.to_path_buf(),
        })
    }

    pub async fn counts(&self) -> crate::rules::model::Counts {
        self.rules.read().await.counts()
    }

    pub async fn metadata(&self) -> (String, String) {
        let rules = self.rules.read().await;
        (
            rules.snapshot.upstream_sha.clone(),
            rules.snapshot.updated_at.clone(),
        )
    }

    pub async fn resolve_host(&self, host: &str) -> HostResolution {
        let host = normalize_host(host);
        if host.is_empty() {
            return resolution(Decision::Proxy);
        }

        let rules = self.rules.read().await.clone();

        if matches_suffix(&host, &rules.direct) {
            return resolution(Decision::Direct);
        }
        if matches_suffix(&host, &rules.proxy) {
            return resolution(Decision::Proxy);
        }
        if is_plain_hostname(&host) {
            return resolution(Decision::Direct);
        }
        if matches_local_tld(&host, &rules.local_tlds) {
            return resolution(Decision::Direct);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            let ip = canonicalize_ip(ip);
            return match decide_ip_with(&rules, ip) {
                Decision::Direct => HostResolution {
                    decision: Decision::Direct,
                    direct_ips: Some(vec![ip]),
                },
                decision => resolution(decision),
            };
        }

        let started = Instant::now();
        let lookup = timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_str(), 0))).await;
        let addresses = match lookup {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                tracing::warn!(
                    event = "dns_resolve_failed",
                    domain = %host,
                    latency_ms = started.elapsed().as_millis() as u64,
                    error = %error,
                    "DNS 解析失败，改用代理"
                );
                return resolution(Decision::Proxy);
            }
            Err(_) => {
                tracing::warn!(
                    event = "dns_resolve_timeout",
                    domain = %host,
                    latency_ms = started.elapsed().as_millis() as u64,
                    timeout_ms = DNS_TIMEOUT.as_millis() as u64,
                    "DNS 解析超时，改用代理"
                );
                return resolution(Decision::Proxy);
            }
        };

        let mut direct_ips = Vec::new();
        for address in addresses {
            let ip = canonicalize_ip(address.ip());
            if (is_private_ip(ip) || is_cn_ip(&rules, ip)) && !direct_ips.contains(&ip) {
                direct_ips.push(ip);
            }
        }

        if direct_ips.is_empty() {
            resolution(Decision::Proxy)
        } else {
            HostResolution {
                decision: Decision::Direct,
                direct_ips: Some(direct_ips),
            }
        }
    }

    pub async fn decide_host(&self, host: &str) -> Decision {
        self.resolve_host(host).await.decision
    }

    pub async fn decide_ip(&self, ip: IpAddr) -> Decision {
        let rules = self.rules.read().await.clone();
        decide_ip_with(&rules, ip)
    }

    pub fn spawn_reload(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            // 强制先检查一次，覆盖 Engine::new 读取后、watcher 记录 mtime 前的窗口。
            let mut signature = None;
            let mut backoff = Duration::from_secs(1);
            let mut failing = false;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let next = engine.signature();
                if next == signature {
                    continue;
                }

                // 规则解析是同步操作，放到阻塞线程池，避免卡住代理运行时。
                let rules_file = engine.rules_file.clone();
                let loaded = tokio::task::spawn_blocking(move || Rules::load(&rules_file))
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|result| result);

                match loaded {
                    Ok(rules) => {
                        signature = next;
                        *engine.rules.write().await = Arc::new(rules);
                        failing = false;
                        backoff = Duration::from_secs(1);
                        tracing::info!("规则已重新加载");
                    }
                    Err(error) => {
                        // 保留旧签名，失败后继续重试；用退避代替每秒重新解析。
                        if !failing {
                            tracing::warn!("规则加载失败，继续使用旧快照: {error:#}");
                            failing = true;
                        } else {
                            tracing::debug!("规则仍加载失败: {error:#}");
                        }
                        tokio::time::sleep(backoff).await;
                        backoff =
                            std::cmp::min(backoff.saturating_mul(5), Duration::from_secs(300));
                    }
                }
            }
        });
    }

    fn signature(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.rules_file)
            .and_then(|metadata| metadata.modified())
            .ok()
    }
}

fn resolution(decision: Decision) -> HostResolution {
    HostResolution {
        decision,
        direct_ips: None,
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

fn is_plain_hostname(host: &str) -> bool {
    !host.contains('.') && !host.contains(':')
}

fn matches_suffix(host: &str, suffixes: &HashSet<String>) -> bool {
    suffixes.iter().any(|suffix| {
        host == suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn matches_local_tld(host: &str, tlds: &HashSet<String>) -> bool {
    tlds.iter().any(|tld| {
        let bare = tld.strip_prefix('.').unwrap_or(tld);
        host == bare || host.ends_with(tld)
    })
}

fn decide_ip_with(rules: &Rules, ip: IpAddr) -> Decision {
    let ip = canonicalize_ip(ip);
    if is_private_ip(ip) || is_cn_ip(rules, ip) {
        Decision::Direct
    } else {
        Decision::Proxy
    }
}

pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let carrier_grade_nat = octets[0] == 100 && (64..=127).contains(&octets[1]);
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || carrier_grade_nat
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
    }
}

fn is_cn_ip(rules: &Rules, ip: IpAddr) -> bool {
    let ip = canonicalize_ip(ip);
    rules.cidrs.iter().any(|network| network.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_tld_matches_apex_and_suffix_only() {
        let tlds = HashSet::from([".test".to_string()]);
        assert!(matches_local_tld("test", &tlds));
        assert!(matches_local_tld("foo.test", &tlds));
        assert!(!matches_local_tld("contest", &tlds));
    }

    #[test]
    fn cgnat_is_private() {
        assert!(is_private_ip("100.64.0.1".parse().expect("IPv4")));
        assert!(is_private_ip("100.127.255.254".parse().expect("IPv4")));
        assert!(!is_private_ip("100.63.255.255".parse().expect("IPv4")));
        assert!(!is_private_ip("100.128.0.1".parse().expect("IPv4")));
    }
}
