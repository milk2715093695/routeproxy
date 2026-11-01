mod cli;
mod config;
mod doctor;
mod engine;
mod http;
mod logging;
mod net;
mod platform;
mod rules;
mod transparent;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clap::error::ErrorKind;
use clap::Parser;
use cli::{Cli, Command, RulesCommand};
use config::Config;
use engine::Engine;

fn main() {
    if let Err(error) = execute() {
        eprintln!("错误: {error:#}");
        std::process::exit(1);
    }
}

fn parse_cli() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                std::process::exit(0);
            }
            let text = error
                .to_string()
                .replace("error: ", "错误: ")
                .replace("Usage: ", "用法: ")
                .replace("unrecognized subcommand", "未知命令")
                .replace("unexpected argument", "未知参数")
                .replace(" found", "")
                .replace(
                    "the following required arguments were not provided:",
                    "缺少必需参数:",
                )
                .replace("a value is required for", "缺少参数值:")
                .replace(" but none was supplied", "")
                .replace(
                    "For more information, try '--help'.",
                    "运行 'routeproxy --help' 查看帮助。",
                );
            eprintln!("{text}");
            std::process::exit(2);
        }
    }
}

fn execute() -> Result<()> {
    let cli = parse_cli();
    match cli.command {
        Command::Version => {
            const BUILD_ID: &str =
                concat!("routeproxy-build-id:", env!("ROUTEPROXY_BUILD_ID"), "|");
            println!("routeproxy {} ({BUILD_ID})", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Doctor { config, probe } => doctor::run(&config, probe.as_deref()),
        Command::Rules { cmd } => handle_rules(cmd),
        Command::Run { config, log_level } => run_proxy(&config, log_level.as_deref()),
    }
}

fn handle_rules(cmd: RulesCommand) -> Result<()> {
    match cmd {
        RulesCommand::Check { file } => {
            let rules = rules::model::Rules::load(&file)?;
            let counts = rules.counts();
            println!(
                "规则校验通过: {} (schema={}, sha={}, direct={}, proxy={}, local_tlds={}, cidrs={})",
                file.display(),
                rules.snapshot.schema,
                rules.snapshot.upstream_sha,
                counts.direct,
                counts.proxy,
                counts.local_tlds,
                counts.cidrs
            );
            Ok(())
        }
    }
}

fn run_proxy(config_path: &Path, log_level: Option<&str>) -> Result<()> {
    let config = Config::load(config_path)?;
    let level = logging::parse_level(log_level.unwrap_or(&config.logging.level))?;
    // 先加载规则再创建日志：坏快照不会留下日志文件。
    let engine = Engine::new(&config.rules.file)?;
    let engine = Arc::new(engine);
    logging::init(
        level,
        &config.logging.file,
        config.logging.max_size_mb,
        config.logging.keep,
    )?;
    let reload = config.rules.reload;
    let mode = config.proxy.mode;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        if reload {
            engine.spawn_reload();
        }
        let config = Arc::new(config);
        match mode {
            config::Mode::Http => http::serve(config, engine).await,
            config::Mode::Transparent => transparent::serve(config, engine).await,
        }
    })
}
