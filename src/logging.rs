use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use chrono::{Local, SecondsFormat};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::FormatTime;

static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_flow_id() -> u64 {
    NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed)
}

struct State {
    file: File,
    size: u64,
}

#[derive(Clone)]
pub struct RotatingWriter {
    state: Arc<Mutex<State>>,
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
}

impl RotatingWriter {
    pub fn new(path: &Path, max_size_mb: u64, keep: usize) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("创建日志目录失败: {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("打开日志文件失败: {}", path.display()))?;
        let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        Ok(Self {
            state: Arc::new(Mutex::new(State { file, size })),
            path: path.to_path_buf(),
            max_bytes: max_size_mb.saturating_mul(1024 * 1024),
            keep,
        })
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    fn rotate(&self, state: &mut State) -> io::Result<()> {
        state.file.flush()?;

        match fs::remove_file(self.rotated_path(self.keep)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        for index in (1..self.keep).rev() {
            let from = self.rotated_path(index);
            let to = self.rotated_path(index + 1);
            match fs::rename(&from, &to) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        match fs::rename(&self.path, self.rotated_path(1)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        // 替换文件打开失败时保留旧句柄。旧文件可能已被重命名，但至少还能写，
        // 不会在下次重启前静默停掉日志。
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        state.file = file;
        state.size = 0;
        Ok(())
    }
}

impl Write for RotatingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let incoming = buffer.len() as u64;
        if state.size > 0 && state.size.saturating_add(incoming) > self.max_bytes {
            if let Err(error) = self.rotate(&mut state) {
                // 继续写旧句柄。每次写入都重试轮转会持续失败。
                eprintln!("routeproxy: 日志轮转失败: {error}");
                state.size = 0;
            }
        }
        state.file.write_all(buffer)?;
        state.size = state.size.saturating_add(incoming);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.file.flush()?;
        Ok(())
    }
}

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, writer: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        write!(
            writer,
            "{}",
            Local::now().to_rfc3339_opts(SecondsFormat::Secs, false)
        )
    }
}

pub fn parse_level(level: &str) -> Result<LevelFilter> {
    match level.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(LevelFilter::TRACE),
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        "warn" => Ok(LevelFilter::WARN),
        "error" => Ok(LevelFilter::ERROR),
        "off" => Ok(LevelFilter::OFF),
        _ => bail!("日志级别无效: {level:?}；可选值 trace、debug、info、warn、error、off"),
    }
}

pub fn init(level: LevelFilter, path: &Path, max_size_mb: u64, keep: usize) -> Result<()> {
    let writer = RotatingWriter::new(path, max_size_mb, keep)?;
    let filter = level;
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_ansi(false)
        .with_timer(LocalTimer)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).context("安装 tracing subscriber 失败")?;
    Ok(())
}
