use std::fs::{self, OpenOptions};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};

use crate::config::{Config, Mode};
use crate::engine::{Decision, Engine};

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Http => "http",
        Mode::Transparent => "transparent",
    }
}

fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Direct => "直连",
        Decision::Proxy => "代理",
    }
}

fn check_log(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("创建日志目录失败: {}", parent.display()))?;

    if path.exists() {
        OpenOptions::new()
            .append(true)
            .open(path)
            .with_context(|| format!("打开日志文件失败: {}", path.display()))?;
    } else {
        // 只探测目录可写，不留下空日志文件。
        tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("在 {} 创建探测文件失败", parent.display()))?;
    }
    Ok(())
}

pub fn run(config_path: &Path, probe: Option<&str>) -> Result<()> {
    let config = Config::load(config_path)?;
    println!("配置: {}", config_path.display());
    println!("模式: {}", mode_name(config.proxy.mode));
    println!("上游: {}", config.proxy.upstream);
    println!("规则: {}", config.rules.file.display());
    println!("热加载: {}", config.rules.reload);
    println!(
        "日志: {} ({})",
        config.logging.file.display(),
        config.logging.level
    );

    let mut errors = 0_u32;
    let mut warnings = 0_u32;

    // 同时持有全部监听器。逐个绑定会把重复地址误判为可用，而 `run` 实际无法绑定。
    let mut listeners = Vec::new();
    for &address in config.listen_addresses() {
        match TcpListener::bind(address) {
            Ok(listener) => {
                listeners.push(listener);
                println!("监听 {address}: 正常");
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                println!("监听 {address}: 已被占用（服务可能已在运行）");
            }
            Err(error) => {
                errors += 1;
                println!("监听 {address}: 失败（服务无法启动: {error}）");
            }
        }
    }
    drop(listeners);

    let upstream = config.upstream_addr();
    match TcpStream::connect_timeout(&upstream, Duration::from_secs(3)) {
        Ok(stream) => {
            drop(stream);
            println!("上游 {upstream}: 可达");
        }
        Err(error) => {
            warnings += 1;
            println!("上游 {upstream}: 不可达 ({error})");
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut engine = None;
    if !config.rules.file.is_file() {
        errors += 1;
        println!("规则: 未找到 ({})", config.rules.file.display());
    } else {
        match Engine::new(&config.rules.file) {
            Ok(created) => {
                let counts = runtime.block_on(created.counts());
                let (sha, updated) = runtime.block_on(created.metadata());
                println!("规则 sha: {sha}");
                println!("规则更新时间: {updated}");
                println!(
                    "规则数量: direct={} proxy={} local_tlds={} cidrs={}",
                    counts.direct, counts.proxy, counts.local_tlds, counts.cidrs
                );
                if let Ok(timestamp) = DateTime::parse_from_rfc3339(&updated) {
                    let age = Utc::now().signed_duration_since(timestamp.with_timezone(&Utc));
                    if age.num_days() > 14 {
                        warnings += 1;
                        println!("规则年龄: {} 天（已过期）", age.num_days());
                    }
                }
                engine = Some(created);
            }
            Err(error) => {
                errors += 1;
                println!("规则: 失败 ({error:#})");
            }
        }
    }

    match check_log(&config.logging.file) {
        Ok(()) => println!("日志: {} (可写)", config.logging.file.display()),
        Err(error) => {
            errors += 1;
            println!("日志: 失败 ({}: {error:#})", config.logging.file.display());
        }
    }

    if let (Some(probe), Some(engine)) = (probe, engine.as_ref()) {
        let decision = match probe.parse::<std::net::IpAddr>() {
            Ok(ip) => runtime.block_on(engine.decide_ip(ip)),
            Err(_) => runtime.block_on(engine.decide_host(probe)),
        };
        println!("{probe} -> {}", decision_name(decision));
    }

    if errors > 0 {
        bail!("doctor 发现 {errors} 个错误、{warnings} 个警告");
    }
    if warnings > 0 {
        println!("doctor: 正常（{warnings} 个警告）");
    } else {
        println!("doctor: 正常");
    }
    Ok(())
}
