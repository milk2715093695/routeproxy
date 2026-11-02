//! 通用规则构建器：只处理显式输入，不读取配置、环境变量或网络。
//! direct/proxy 精确同名时 direct 优先，不执行 GFW 策略。

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, SecondsFormat, SubsecRound, Utc};

use super::model::{normalize_file, read_text, Counts, RulesFile, SCHEMA};

pub struct BuildInput {
    pub direct: Vec<PathBuf>,
    pub proxy: Vec<PathBuf>,
    pub local_tlds: Vec<PathBuf>,
    pub cidrs: Vec<PathBuf>,
    pub upstream_sha: String,
    pub updated_at: String,
    pub output: PathBuf,
}

pub fn build(input: BuildInput) -> Result<Counts> {
    let raw = RulesFile {
        schema: SCHEMA,
        upstream_sha: normalize_sha(&input.upstream_sha)?,
        updated_at: normalize_updated_at(&input.updated_at)?,
        direct: read_category(&input.direct)?,
        proxy: read_category(&input.proxy)?,
        local_tlds: read_category(&input.local_tlds)?,
        cidrs: read_category(&input.cidrs)?,
    };
    let normalized = normalize_file(&raw)?;

    let direct = normalized.direct.into_iter().collect::<BTreeSet<_>>();
    let proxy = normalized
        .proxy
        .into_iter()
        .filter(|entry| !direct.contains(entry))
        .collect::<BTreeSet<_>>();
    let local_tlds = normalized.local_tlds.into_iter().collect::<BTreeSet<_>>();
    let mut cidrs = normalized.cidrs;
    // IPv4 在前，再按网络地址和前缀；输出顺序是快照契约的一部分。
    cidrs.sort_by_key(|network| {
        (
            if network.addr().is_ipv4() { 0u8 } else { 1u8 },
            network.addr(),
            network.prefix_len(),
        )
    });

    let file = RulesFile {
        schema: SCHEMA,
        upstream_sha: raw.upstream_sha,
        updated_at: raw.updated_at,
        direct: direct.iter().cloned().collect(),
        proxy: proxy.iter().cloned().collect(),
        local_tlds: local_tlds.iter().cloned().collect(),
        cidrs: cidrs.iter().map(ToString::to_string).collect(),
    };

    let text = toml::to_string_pretty(&file).context("序列化规则失败")?;
    write_atomic(&input.output, text.as_bytes())?;

    Ok(Counts {
        direct: direct.len(),
        proxy: proxy.len(),
        local_tlds: local_tlds.len(),
        cidrs: cidrs.len(),
    })
}

fn read_category(files: &[PathBuf]) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    for path in files {
        let text = read_source(path)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            entries.push(line.to_string());
        }
    }
    Ok(entries)
}

fn read_source(path: &Path) -> Result<String> {
    // 只接受显式普通文件；符号链接可能把构建输入指向意外位置。
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("读取输入文件状态失败: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("输入路径不是普通文件: {}", path.display());
    }

    read_text(path, "输入文件")
}

fn normalize_sha(value: &str) -> Result<String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("--upstream-sha 必须是 40 位十六进制");
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_updated_at(value: &str) -> Result<String> {
    // 统一到 UTC 秒，保证同一输入生成字节一致的快照。
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("--updated-at 不是有效 RFC3339: {value}"))?;
    Ok(parsed
        .with_timezone(&Utc)
        .trunc_subsecs(0)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("输出父目录不存在: {}", parent.display());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("输出路径不能是符号链接: {}", path.display());
        }
    }

    // 临时文件必须与目标同目录，避免跨文件系统 rename。
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("创建临时文件失败: {}", parent.display()))?;
    temp.write_all(contents)
        .with_context(|| format!("写入临时文件失败: {}", path.display()))?;
    temp.as_file_mut().flush().context("刷新临时文件失败")?;
    temp.as_file().sync_all().context("同步临时文件失败")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // NamedTempFile 默认 0600；替换已有文件时保留其权限，避免服务进程失去读权限。
        let mode = fs::symlink_metadata(path)
            .ok()
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.permissions().mode())
            .unwrap_or(0o644);
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("设置输出文件权限失败: {}", path.display()))?;

        // rename 后同步父目录，确保目录项在崩溃后仍可见。
        temp.persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("替换输出文件失败: {}", path.display()))?;
        fs::File::open(parent)
            .with_context(|| format!("打开输出目录失败: {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("同步输出目录失败: {}", parent.display()))?;
    }

    #[cfg(windows)]
    {
        // 使用 ReplaceFileW/MOVEFILE_WRITE_THROUGH，不降级为 remove+rename。
        let temp_path = temp
            .into_temp_path()
            .keep()
            .map_err(|error| error.error)
            .context("保留临时文件失败")?;
        if let Err(error) = replace_windows(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    }

    Ok(())
}

#[cfg(windows)]
fn replace_windows(temp: &Path, output: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let output_exists = fs::symlink_metadata(output).is_ok();
    let temp = wide(temp);
    let output = wide(output);
    let ok = if output_exists {
        unsafe {
            ReplaceFileW(
                output.as_ptr(),
                temp.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe {
            MoveFileExW(
                temp.as_ptr(),
                output.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if ok == 0 {
        bail!("Windows 原子替换失败");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn input(dir: &Path, direct: &str, proxy: &str, cidrs: &str) -> BuildInput {
        let direct_path = dir.join("direct.txt");
        let proxy_path = dir.join("proxy.txt");
        let cidrs_path = dir.join("cidrs.txt");
        fs::write(&direct_path, direct).unwrap();
        fs::write(&proxy_path, proxy).unwrap();
        fs::write(&cidrs_path, cidrs).unwrap();
        BuildInput {
            direct: vec![direct_path],
            proxy: vec![proxy_path],
            local_tlds: vec![],
            cidrs: vec![cidrs_path],
            upstream_sha: "A".repeat(40),
            updated_at: "2026-11-02T12:34:56+08:00".to_string(),
            output: dir.join("rules.toml"),
        }
    }

    #[test]
    fn build_merges_exact_conflict_and_keeps_suffix() {
        let dir = tempdir();
        let input = input(
            dir.path(),
            "# direct\nExample.COM.\n",
            "example.com\nsub.example.com\n// proxy\n",
            "10.0.0.1/8\n",
        );
        let counts = build(input).unwrap();
        assert_eq!(counts.direct, 1);
        assert_eq!(counts.proxy, 1);
        let text = fs::read_to_string(dir.path().join("rules.toml")).unwrap();
        let parsed: RulesFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.upstream_sha, "a".repeat(40));
        assert_eq!(parsed.updated_at, "2026-11-02T04:34:56Z");
        assert_eq!(parsed.direct, vec!["example.com"]);
        assert_eq!(parsed.proxy, vec!["sub.example.com"]);
        assert_eq!(parsed.cidrs, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn build_sorts_categories() {
        let dir = tempdir();
        let input = input(
            dir.path(),
            "b.com\na.com\nb.com\n",
            "z.com\ny.com\n",
            "2001:db8::/32\n192.168.0.0/16\n10.0.0.0/8\n",
        );
        build(input).unwrap();
        let text = fs::read_to_string(dir.path().join("rules.toml")).unwrap();
        let parsed: RulesFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.direct, vec!["a.com", "b.com"]);
        assert_eq!(parsed.proxy, vec!["y.com", "z.com"]);
        assert_eq!(
            parsed.cidrs,
            vec!["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]
        );
    }

    #[test]
    fn empty_categories_are_valid() {
        let dir = tempdir();
        let input = input(dir.path(), "", "# only comment\n", "");
        let counts = build(input).unwrap();
        assert_eq!(counts.direct, 0);
        assert_eq!(counts.proxy, 0);
        assert_eq!(counts.cidrs, 0);
    }

    #[test]
    fn inline_comment_is_error() {
        let dir = tempdir();
        let input = input(dir.path(), "example.com # nope\n", "", "");
        assert!(build(input).is_err());
    }

    #[test]
    fn missing_parent_fails() {
        let dir = tempdir();
        let mut input = input(dir.path(), "a.com\n", "", "");
        input.output = dir.path().join("missing").join("rules.toml");
        assert!(build(input).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_keeps_existing_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let output = dir.path().join("rules.toml");
        fs::write(&output, "old").unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o640)).unwrap();
        let mut input = input(dir.path(), "a.com\n", "", "");
        input.output = output.clone();
        build(input).unwrap();

        let mode = fs::metadata(output).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_output_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir();
        let target = dir.path().join("target.toml");
        let output = dir.path().join("rules.toml");
        fs::write(&target, "old").unwrap();
        symlink(&target, &output).unwrap();
        let mut input = input(dir.path(), "a.com\n", "", "");
        input.output = output;
        assert!(build(input).is_err());
    }
}
