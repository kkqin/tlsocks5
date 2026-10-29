use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{copy, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tokio_io_timeout::TimeoutStream;

use crate::buffer_pool::POOL;

pub async fn read_buf_timeout<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut BytesMut,
    timeout_duration: Duration,
) -> Result<usize, std::io::Error> {
    match timeout(timeout_duration, stream.read_buf(buf)).await {
        Ok(result) => {
            let bytes_read = result?;
            if bytes_read == 0 {
                // 如果没有读取到字节，返回自定义错误
                return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "读取到0字节"));
            }
            Ok(bytes_read)
        } // 直接回傳內部 Result<usize>
        Err(_) => Err(std::io::Error::new(ErrorKind::TimedOut, "讀取超時")),
    }
}

pub async fn read_exact_timeout<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
    timeout_duration: Duration,
) -> Result<(), std::io::Error> {
    match timeout(timeout_duration, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(ErrorKind::TimedOut, "讀取超時")),
    }
}

pub async fn write_all_timeout<W: AsyncWrite + Unpin>(
    stream: &mut W,
    buf: &[u8],
    timeout_duration: Duration,
) -> Result<(), std::io::Error> {
    match timeout(timeout_duration, stream.write_all(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(ErrorKind::TimedOut, "寫入超時")),
    }
}

pub async fn handle_copy<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    _direction: &str,
    timeout_duration: Duration,
) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut writer_guard = writer.lock().await;

    match timeout(timeout_duration, copy(&mut reader, &mut *writer_guard)).await {
        Ok(Ok(_bytes)) => Ok(()),
        Ok(Err(e)) => {
            let _ = writer_guard.shutdown().await; //使用guard调用shutdown
            Err(e)
        }
        Err(_) => {
            let _ = writer_guard.shutdown().await; // 超时也需要shutdown
            Err(std::io::Error::new(ErrorKind::TimedOut, "复制超时"))
        }
    }
}

pub async fn handle_copy2<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    direction: &str,
    timeout_duration: Duration,
) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut writer_guard = writer.lock().await;
    let mut buffer = vec![0; 8 * 1024]; // 8KB 緩衝區
    loop {
        let read_future = reader.read(&mut buffer);
        let read_result = timeout(timeout_duration, read_future).await;
        let n = match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("{direction}：讀取錯誤：{e}");
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                eprintln!("{direction}：讀取超時");
                let _ = writer_guard.shutdown().await;
                return Err(std::io::Error::new(ErrorKind::TimedOut, "讀取超時"));
            }
        };

        let write_future = writer_guard.write_all(&buffer[..n]);
        let write_result = timeout(timeout_duration, write_future).await;
        match write_result {
            Ok(Ok(_)) => (), // 寫入成功，繼續
            Ok(Err(e)) => {
                eprintln!("{direction}：寫入錯誤：{e}");
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                eprintln!("{direction}：寫入超時");
                let _ = writer_guard.shutdown().await;
                return Err(std::io::Error::new(ErrorKind::TimedOut, "寫入超時"));
            }
        }
    }
    Ok(())
}

pub async fn handle_copy3<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    direction: &str,
    timeout_duration: Duration,
) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut writer_guard = writer.lock().await;
    let mut buffer = POOL.get_buffer().await; // pool 中拿到的 BytesMut

    loop {
        // append 模式读取
        let n = match timeout(timeout_duration, reader.read_buf(&mut buffer)).await {
            Ok(Ok(0)) => {
                let _ = writer_guard.shutdown().await;
                break;
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("{direction}：读取错误：{e}");
                let _ = writer_guard.shutdown().await;
                POOL.return_buffer(buffer).await;
                return Err(e);
            }
            Err(_) => {
                eprintln!("{direction}：读取超时");
                let _ = writer_guard.shutdown().await;
                POOL.return_buffer(buffer).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "读取超时",
                ));
            }
        };

        // 写出刚 append 的那 n 字节
        if let Err(e) = writer_guard.write_all(&buffer[..n]).await {
            eprintln!("{direction}：写入错误：{e}");
            let _ = writer_guard.shutdown().await;
            POOL.return_buffer(buffer).await;
            return Err(e);
        }

        buffer.clear();
    }

    // 用完还池子
    POOL.return_buffer(buffer).await;
    Ok(())
}

/// 从 reader 读数据，经 writer 写出：
/// 如果超过 `idle` 没读到任何字节，就返回 Err(io::ErrorKind::TimedOut)
pub async fn pump_with_idle_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 8 * 1024];
    loop {
        // 等待读操作，但最多等 idle 时长
        let n = match timeout(idle, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),  // 对端 EOF，正常结束
            Ok(Ok(n)) => n,              // 读到 n 字节，继续
            Ok(Err(e)) => return Err(e), // IO 错误
            Err(_) => {
                // 超过 idle 时间都没读到数据
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout"));
            }
        };
        // 把读到的数据写给对端
        writer.write_all(&buf[..n]).await?;
    }
}

/// 双向转发。
///
/// 空闲计时看的是整条隧道：任意一边读到或写出数据就重新计时。
/// 只有两个方向都安静了 `idle` 这么久才断开，单向下载或上传不会被掐断。
/// `idle` 为 0 时不因空闲断开。写操作卡住超过 `write_timeout` 仍会断开。
pub async fn copy_bidirectional_idle<A, B>(
    a: A,
    b: B,
    idle: Duration,
    write_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last = Arc::new(AtomicU64::new(mono_ms()));
    let write_timeout = if write_timeout.is_zero() {
        None
    } else {
        Some(write_timeout)
    };

    let mut a = TimeoutStream::new(Touch::new(a, Arc::clone(&last)));
    let mut b = TimeoutStream::new(Touch::new(b, Arc::clone(&last)));
    a.set_write_timeout(write_timeout);
    b.set_write_timeout(write_timeout);
    let mut a = Box::pin(a);
    let mut b = Box::pin(b);

    if idle.is_zero() {
        return tokio::io::copy_bidirectional(&mut a, &mut b).await;
    }

    tokio::select! {
        biased;
        result = tokio::io::copy_bidirectional(&mut a, &mut b) => result,
        err = wait_idle(&last, idle) => Err(err),
    }
}

fn mono_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn wait_idle(last: &AtomicU64, idle: Duration) -> io::Error {
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX).max(1);
    loop {
        let elapsed = mono_ms().saturating_sub(last.load(Ordering::Relaxed));
        if elapsed >= idle_ms {
            return io::Error::new(ErrorKind::TimedOut, "空闲超时");
        }
        tokio::time::sleep(Duration::from_millis(idle_ms - elapsed)).await;
    }
}

struct Touch<S> {
    inner: S,
    last: Arc<AtomicU64>,
}

impl<S> Touch<S> {
    fn new(inner: S, last: Arc<AtomicU64>) -> Self {
        Self { inner, last }
    }

    fn mark(&self) {
        self.last.store(mono_ms(), Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Touch<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.mark();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Touch<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                self.mark();
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn silence_hits_idle_timeout() {
        let (a, a_peer) = duplex(64);
        let (b, b_peer) = duplex(64);
        let started = Instant::now();
        let err = copy_bidirectional_idle(
            a_peer,
            b_peer,
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await
        .expect_err("silent tunnel should idle out");
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(err.to_string().contains("空闲"));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop((a, b));
    }

    #[tokio::test]
    async fn one_way_traffic_keeps_the_tunnel() {
        let (mut src, src_peer) = duplex(1024);
        let (mut dst, dst_peer) = duplex(1024);
        let copy = tokio::spawn(async move {
            copy_bidirectional_idle(
                src_peer,
                dst_peer,
                Duration::from_millis(800),
                Duration::from_secs(5),
            )
            .await
        });

        for i in 0..5u8 {
            src.write_all(&[i]).await.unwrap();
            let mut buf = [0u8; 1];
            tokio::time::timeout(Duration::from_secs(1), dst.read_exact(&mut buf))
                .await
                .expect("read")
                .unwrap();
            assert_eq!(buf[0], i);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!copy.is_finished(), "one-way transfer must not hit idle");

        let joined = tokio::time::timeout(Duration::from_secs(3), copy)
            .await
            .expect("idle should fire after traffic stops");
        let err = joined.unwrap().expect_err("idle");
        assert!(err.to_string().contains("空闲"));
        drop((src, dst));
    }

    #[tokio::test]
    async fn stalled_write_times_out_while_buffer_is_full() {
        let (mut src, src_peer) = duplex(64);
        let (_dst, dst_peer) = duplex(1);
        let copy = tokio::spawn(async move {
            copy_bidirectional_idle(
                src_peer,
                dst_peer,
                Duration::from_secs(30),
                Duration::from_millis(300),
            )
            .await
        });
        src.write_all(&[1u8; 64]).await.unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(2), copy)
            .await
            .expect("write stall should not wait for the idle timeout");
        let err = joined.unwrap().expect_err("write timeout");
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(!err.to_string().contains("空闲"));
    }
}
