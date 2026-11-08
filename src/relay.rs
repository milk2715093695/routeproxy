use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};

const COPY_BUFFER_SIZE: usize = 16 * 1024;

/// 双向转发；单向半关闭不结束隧道，两个方向都超过 `idle` 才关闭。
pub async fn copy_bidirectional_idle<A, B>(
    client: &mut A,
    upstream: &mut B,
    idle: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (progress_tx, mut progress_rx) = mpsc::channel(8);

    let mut client_to_upstream = Box::pin(copy_direction(
        client_read,
        upstream_write,
        progress_tx.clone(),
    ));
    let mut upstream_to_client = Box::pin(copy_direction(upstream_read, client_write, progress_tx));

    let mut idle_timer = Box::pin(sleep(idle));
    let mut client_done = false;
    let mut upstream_done = false;

    while !client_done || !upstream_done {
        tokio::select! {
            _ = idle_timer.as_mut() => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("双向连接空闲超过 {} 秒", idle.as_secs()),
                ));
            }
            Some(()) = progress_rx.recv() => {
                idle_timer.as_mut().reset(Instant::now() + idle);
            }
            result = &mut client_to_upstream, if !client_done => {
                client_done = true;
                result?;
            }
            result = &mut upstream_to_client, if !upstream_done => {
                upstream_done = true;
                result?;
            }
        }
    }

    Ok(())
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    progress: mpsc::Sender<()>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        // 背压等待，避免高吞吐时丢通知导致活跃连接被误判为空闲。
        let _ = progress.send(()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_connection_times_out() {
        let (mut client, _client_peer) = duplex(64);
        let (mut upstream, _upstream_peer) = duplex(64);
        let error = copy_bidirectional_idle(&mut client, &mut upstream, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn half_closed_connection_still_relays_other_direction() {
        let (mut client, mut client_peer) = duplex(64);
        let (mut upstream, mut upstream_peer) = duplex(64);
        let task = tokio::spawn(async move {
            copy_bidirectional_idle(&mut client, &mut upstream, Duration::from_secs(1)).await
        });

        client_peer.write_all(b"request").await.unwrap();
        client_peer.shutdown().await.unwrap();
        let mut request = [0_u8; 7];
        upstream_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        upstream_peer.write_all(b"response").await.unwrap();
        upstream_peer.shutdown().await.unwrap();
        let mut response = [0_u8; 8];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        task.await.unwrap().unwrap();
    }
}
