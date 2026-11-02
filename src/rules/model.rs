use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
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

pub(crate) struct NormalizedRules {
    pub direct: Vec<String>,
    pub proxy: Vec<String>,
    pub local_tlds: Vec<String>,
    pub cidrs: Vec<IpNet>,
}

impl Rules {
    /// 只做结构与语法校验，不执行数量下限、哨兵或后缀遮蔽策略。
    ///
    /// 这些策略属于 dotfiles；`rules check` 也复用这里。
    pub fn load(file_path: &Path) -> Result<Self> {
        let text = read_text(file_path, "规则文件")?;
        let file: RulesFile = toml::from_str(&text)
            .with_context(|| format!("解析规则文件失败: {}", file_path.display()))?;
        let normalized = normalize_file(&file)?;

        let direct = normalized.direct.into_iter().collect::<HashSet<_>>();
        let proxy = normalized.proxy.into_iter().collect::<HashSet<_>>();
        let local_tlds = normalized.local_tlds.into_iter().collect::<HashSet<_>>();
        let mut cidrs = normalized.cidrs;
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

pub(crate) fn read_text(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("读取 {label} 失败: {}", path.display()))
}

pub(crate) fn normalize_file(file: &RulesFile) -> Result<NormalizedRules> {
    if file.schema != SCHEMA {
        bail!("不支持的 rules.schema: {}（期望 {SCHEMA}）", file.schema);
    }
    if !is_sha(&file.upstream_sha) {
        bail!("rules.upstream_sha 必须是空值或 40 位十六进制");
    }
    DateTime::parse_from_rfc3339(&file.updated_at)
        .with_context(|| format!("rules.updated_at 无效: {}", file.updated_at))?;

    let direct = normalize_domains("direct", &file.direct)?;
    let proxy = normalize_domains("proxy", &file.proxy)?;
    let local_tlds = normalize_local_tlds(&file.local_tlds)?;
    let cidrs = normalize_cidrs(&file.cidrs)?;

    Ok(NormalizedRules {
        direct,
        proxy,
        local_tlds,
        cidrs,
    })
}

fn normalize_domains(label: &str, entries: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = trimmed
            .strip_suffix('.')
            .unwrap_or(trimmed)
            .to_ascii_lowercase();
        if !is_valid_domain(&value) {
            bail!("{label} 域名无效: {entry}");
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    Ok(out)
}

fn normalize_local_tlds(entries: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = trimmed
            .strip_suffix('.')
            .unwrap_or(trimmed)
            .to_ascii_lowercase();
        let Some(tld) = value.strip_prefix('.') else {
            bail!("local_tlds 条目缺少前导点: {entry}");
        };
        if tld.is_empty() || tld.contains('.') || !is_valid_domain(tld) {
            bail!("local_tlds 条目无效: {entry}");
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    Ok(out)
}

fn normalize_cidrs(entries: &[String]) -> Result<Vec<IpNet>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        let value = entry.trim();
        if value.is_empty() {
            continue;
        }
        let network = value
            .parse::<IpNet>()
            .map(|network| network.trunc())
            .with_context(|| format!("CIDR 无效: {entry}"))?;
        if seen.insert(network) {
            out.push(network);
        }
    }
    Ok(out)
}

fn is_sha(value: &str) -> bool {
    value.is_empty() || (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_valid_domain(value: &str) -> bool {
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
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(direct: Vec<&str>, proxy: Vec<&str>, cidrs: Vec<&str>) -> RulesFile {
        RulesFile {
            schema: SCHEMA,
            upstream_sha: "a".repeat(40),
            updated_at: "2026-11-02T00:00:00Z".to_string(),
            direct: direct.into_iter().map(str::to_string).collect(),
            proxy: proxy.into_iter().map(str::to_string).collect(),
            local_tlds: vec![".test".to_string()],
            cidrs: cidrs.into_iter().map(str::to_string).collect(),
        }
    }

    #[test]
    fn accepts_empty_arrays_and_duplicates() {
        let file = rules(vec!["", "Example.COM", "example.com."], vec![], vec![]);
        let normalized = normalize_file(&file).unwrap();
        assert_eq!(normalized.direct, vec!["example.com"]);
        assert!(normalized.proxy.is_empty());
        assert!(normalized.cidrs.is_empty());
    }

    #[test]
    fn exact_direct_proxy_overlap_is_allowed() {
        let file = rules(vec!["a.com"], vec!["a.com", "b.com"], vec![]);
        let normalized = normalize_file(&file).unwrap();
        assert_eq!(normalized.direct, vec!["a.com"]);
        assert_eq!(normalized.proxy, vec!["a.com", "b.com"]);
    }

    #[test]
    fn rejects_bad_domains_and_cidrs() {
        let bad_domain = rules(vec!["foo_bar.com"], vec![], vec![]);
        assert!(normalize_file(&bad_domain).is_err());

        let bad_cidr = rules(vec![], vec![], vec!["10.0.0.0/33"]);
        assert!(normalize_file(&bad_cidr).is_err());
    }

    #[test]
    fn rejects_trailing_dot_on_cidr_and_empty_domain() {
        let bad_cidr = rules(vec![], vec![], vec!["10.0.0.0/8."]);
        assert!(normalize_file(&bad_cidr).is_err());

        let bad_domain = rules(vec!["."], vec![], vec![]);
        assert!(normalize_file(&bad_domain).is_err());
    }

    #[test]
    fn canonicalizes_cidr_host_bits() {
        let file = rules(vec![], vec![], vec!["10.0.0.1/8"]);
        let normalized = normalize_file(&file).unwrap();
        assert_eq!(
            normalized.cidrs,
            vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]
        );
    }
}
