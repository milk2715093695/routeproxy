use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

const HELP_TEMPLATE: &str = "{about-with-newline}\n用法: {usage}\n\n{all-args}{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "routeproxy",
    version,
    about = "TCP 转发代理",
    long_about = "routeproxy 是一个只处理 TCP 的转发代理：按规则选择直连或上游代理，支持 HTTP 代理与 Android 透明代理。",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    propagate_version = true,
    subcommand_help_heading = "命令",
    next_help_heading = "选项",
    help_template = HELP_TEMPLATE
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(
        short = 'h',
        long = "help",
        action = ArgAction::Help,
        global = true,
        help = "显示帮助"
    )]
    pub help: Option<bool>,
    #[arg(
        short = 'V',
        long = "version",
        action = ArgAction::Version,
        global = true,
        help = "显示版本"
    )]
    pub version: Option<bool>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(
        about = "启动代理服务",
        help_template = HELP_TEMPLATE,
        next_help_heading = "选项"
    )]
    Run {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        #[arg(long, value_name = "LEVEL", help = "覆盖 logging.level")]
        log_level: Option<String>,
    },
    #[command(
        about = "规则文件操作",
        help_template = HELP_TEMPLATE,
        subcommand_help_heading = "命令",
        next_help_heading = "选项"
    )]
    Rules {
        #[command(subcommand)]
        cmd: RulesCommand,
    },
    #[command(
        about = "检查配置、监听、上游、规则和日志",
        help_template = HELP_TEMPLATE,
        next_help_heading = "选项"
    )]
    Doctor {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        #[arg(long, value_name = "HOST", help = "额外探测一个域名或 IP")]
        probe: Option<String>,
    },
    #[command(about = "输出版本和构建号", help_template = HELP_TEMPLATE)]
    Version,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    #[command(
        about = "校验规则文件",
        help_template = HELP_TEMPLATE,
        next_help_heading = "选项"
    )]
    Check {
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
}
