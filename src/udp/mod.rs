use std::sync::Arc;

use anyhow::Result;

use crate::config::Config;
use crate::engine::Engine;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn serve(config: Arc<Config>, engine: Arc<Engine>) -> Result<()> {
    linux::serve(config, engine).await
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub async fn serve(_config: Arc<Config>, _engine: Arc<Engine>) -> Result<()> {
    anyhow::bail!("透明 UDP 仅支持 Linux/Android");
}
