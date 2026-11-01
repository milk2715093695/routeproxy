use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use ipnet::IpNet;
use serde::Deserialize;

pub const SCHEMA: u32 = 1;
pub const MAX_RULES_BYTES: usize = 4 * 1024 * 1024;

const DIRECT_FLOOR: usize = 100;
const PROXY_FLOOR: usize = 20;
const CIDR_FLOOR: usize = 5_000;
const LOCAL_TLD_FLOOR: usize = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesFile {
    pub schema: u32,
    #[serde(default)]
    pub upstream_sha: String,
    pub updated_at: String,
    pub direct: Vec<String>,
    pub proxy: Vec<String>,
    pub local_tlds: Vec<String>,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub direct: usize,
    pub proxy: usize,
    pub local_tlds: usize,
    pub cidrs: usize,
}

pub struct Rules {
    pub snapshot: RulesFile,
    pub direct: HashSet<String>,
    pub proxy: HashSet<String>,
    pub local_tlds: HashSet<String>,
    pub cidrs: Vec<IpNet>,
}

struct NormalizedRules {
    direct: Vec<String>,
    proxy: Vec<String>,
    local_tlds: Vec<String>,
    cidrs: Vec<IpNet>,
}

impl Rules {
    pub fn load(file_path: &Path) -> Result<Self> {
        let text = read_text_limited(file_path, "规则文件")?;
        let file: RulesFile = toml::from_str(&text)
            .with_context(|| format!("解析规则文件失败: {}", file_path.display()))?;
        let normalized = validate_file(&file)?;

        let direct = normalized.direct.into_iter().collect::<HashSet<_>>();
        let mut proxy = normalized.proxy.into_iter().collect::<HashSet<_>>();
        let local_tlds = normalized.local_tlds.into_iter().collect::<HashSet<_>>();
        let mut cidrs = normalized.cidrs;

        proxy.retain(|domain| !is_shadowed_by_direct(domain, &direct));
        if proxy.len() < PROXY_FLOOR {
            bail!(
                "移除与 direct 重叠的条目后，rules.proxy 只剩 {} 条（最少 {PROXY_FLOOR} 条）",
                proxy.len()
            );
        }
        let mut seen = HashSet::new();
        cidrs.retain(|cidr| seen.insert(*cidr));

        Ok(Self {
            snapshot: file,
            direct,
            proxy,
            local_tlds,
            cidrs,
        })
    }

    pub fn counts(&self) -> Counts {
        Counts {
            direct: self.direct.len(),
            proxy: self.proxy.len(),
            local_tlds: self.local_tlds.len(),
            cidrs: self.cidrs.len(),
        }
    }
}

pub(crate) fn read_text_limited(path: &Path, label: &str) -> Result<String> {
    let metadata =
        fs::metadata(path).with_context(|| format!("读取 {label} 状态失败: {}", path.display()))?;
    if metadata.len() > MAX_RULES_BYTES as u64 {
        bail!("{label} {} 超过 {MAX_RULES_BYTES} 字节限制", path.display());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 {label} 失败: {}", path.display()))?;
    if text.len() > MAX_RULES_BYTES {
        bail!("{label} {} 超过 {MAX_RULES_BYTES} 字节限制", path.display());
    }
    Ok(text)
}

fn validate_file(file: &RulesFile) -> Result<NormalizedRules> {
    if file.schema != SCHEMA {
        bail!("不支持的 rules.schema: {}（期望 {SCHEMA}）", file.schema);
    }
    DateTime::parse_from_rfc3339(&file.updated_at)
        .with_context(|| format!("rules.updated_at 无效: {}", file.updated_at))?;

    let direct = unique(file.direct.clone());
    let proxy = unique(file.proxy.clone());
    let local_tlds = unique(file.local_tlds.clone());
    let cidrs = unique(file.cidrs.clone());

    validate_domains("direct", &direct)?;
    validate_domains("proxy", &proxy)?;
    validate_local_tlds(&local_tlds)?;
    let cidrs = parse_cidrs(&cidrs)?;

    if direct.len() < DIRECT_FLOOR {
        bail!(
            "rules.direct 只有 {} 条（最少 {DIRECT_FLOOR} 条）",
            direct.len()
        );
    }
    if proxy.len() < PROXY_FLOOR {
        bail!(
            "rules.proxy 只有 {} 条（最少 {PROXY_FLOOR} 条）",
            proxy.len()
        );
    }
    if local_tlds.len() < LOCAL_TLD_FLOOR {
        bail!(
            "rules.local_tlds 只有 {} 条（最少 {LOCAL_TLD_FLOOR} 条）",
            local_tlds.len()
        );
    }
    if cidrs.len() < CIDR_FLOOR {
        bail!(
            "rules.cidrs 只有 {} 条（最少 {CIDR_FLOOR} 条）",
            cidrs.len()
        );
    }

    Ok(NormalizedRules {
        direct,
        proxy,
        local_tlds,
        cidrs,
    })
}

fn validate_domains(label: &str, entries: &[String]) -> Result<()> {
    for entry in entries {
        if !is_valid_domain(entry) {
            bail!("{label} 域名无效: {entry}");
        }
    }
    Ok(())
}

fn validate_local_tlds(entries: &[String]) -> Result<()> {
    for entry in entries {
        let Some(tld) = entry.strip_prefix('.') else {
            bail!("local_tlds 条目缺少前导点: {entry}");
        };
        if tld.contains('.') || !is_valid_domain(tld) {
            bail!("local_tlds 条目无效: {entry}");
        }
    }
    Ok(())
}

fn parse_cidrs(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .with_context(|| format!("CIDR 无效: {entry}"))
        })
        .collect()
}

fn is_valid_domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

fn is_shadowed_by_direct(domain: &str, direct: &HashSet<String>) -> bool {
    direct.iter().any(|suffix| {
        domain == suffix
            || domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn unique(entries: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    entries
        .into_iter()
        .map(|entry| entry.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|entry| !entry.is_empty())
        .filter(|entry| seen.insert(entry.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_direct_suffix_shadows_proxy_entry() {
        let direct = HashSet::from(["com".to_string()]);
        assert!(is_shadowed_by_direct("a.com", &direct));
        assert!(!is_shadowed_by_direct("example.org", &direct));
    }
}
