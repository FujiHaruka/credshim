use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) async fn relay<A, B>(a: A, b: B, after_half_close: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite,
    B: AsyncRead + AsyncWrite,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let a_to_b = forward(&mut a_read, &mut b_write);
    let b_to_a = forward(&mut b_read, &mut a_write);
    tokio::pin!(a_to_b, b_to_a);
    tokio::select! {
        done = &mut a_to_b => {
            done?;
            drain(b_to_a, after_half_close).await
        }
        done = &mut b_to_a => {
            done?;
            drain(a_to_b, after_half_close).await
        }
    }
}

async fn forward<R, W>(from: &mut R, to: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(from, to).await?;
    to.shutdown().await
}

async fn drain<F>(rest: Pin<&mut F>, limit: Duration) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    tokio::time::timeout(limit, rest).await.unwrap_or(Ok(()))
}
