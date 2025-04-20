use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy};
use tokio::time::{timeout, Duration};
use bytes::BytesMut;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::sync::Mutex;

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
        }, // 直接回傳內部 Result<usize>
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
        Ok(Err(e)) => {
            eprintln!("讀取錯誤：{}", e);
            Err(e)
        }
        Err(_) => {
            eprintln!("讀取超時");
            Err(std::io::Error::new(ErrorKind::TimedOut, "讀取超時"))
        }
    }
}

pub async fn write_all_timeout<W: AsyncWrite + Unpin>(
    stream: &mut W,
    buf: &[u8],
    timeout_duration: Duration,
) -> Result<(), std::io::Error> {
     match timeout(timeout_duration, stream.write_all(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            eprintln!("寫入錯誤：{}", e);
            Err(e)
        }
        Err(_) => {
            eprintln!("寫入超時");
            Err(std::io::Error::new(ErrorKind::TimedOut, "寫入超時"))
        }
    }
}

pub async fn handle_copy<R, W>(mut reader: R, writer: Arc<Mutex<W>>, direction: &str, timeout_duration: Duration) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut writer_guard = writer.lock().await;

    match timeout(timeout_duration, copy(&mut reader, &mut *writer_guard)).await {
        Ok(Ok(bytes)) => {
            println!("{}：复制了 {} 字节", direction, bytes);
            Ok(())
        }
        Ok(Err(e)) => {
            eprintln!("{}：复制出错：{}", direction, e);
            let _ = writer_guard.shutdown().await;//使用guard调用shutdown
            Err(e)
        }
        Err(_) => {
            eprintln!("{}：复制超时", direction);
            let _ = writer_guard.shutdown().await; // 超时也需要shutdown
            Err(std::io::Error::new(ErrorKind::TimedOut, "复制超时"))
        }
    }
}

pub async fn handle_copy2<R, W>(mut reader: R, writer: Arc<Mutex<W>>, direction: &str, timeout_duration: Duration) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut writer_guard = writer.lock().await;
    let mut buffer = vec![0; 8 * 1024]; // 8KB 緩衝區
    loop {
        let read_future = reader.read(&mut buffer);
        let read_result = timeout(timeout_duration, read_future).await;
        let n = match read_result{
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n))=> n,
            Ok(Err(e)) => {
                eprintln!("{}：讀取錯誤：{}", direction, e);
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                eprintln!("{}：讀取超時", direction);
                let _ = writer_guard.shutdown().await;
                return Err(std::io::Error::new(ErrorKind::TimedOut, "讀取超時"));
            }
        };

        let write_future = writer_guard.write_all(&buffer[..n]);
        let write_result = timeout(timeout_duration, write_future).await;
        match write_result {
            Ok(Ok(_)) => (), // 寫入成功，繼續
            Ok(Err(e)) => {
                eprintln!("{}：寫入錯誤：{}", direction, e);
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                eprintln!("{}：寫入超時", direction);
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
    timeout_duration: Duration
) -> Result<(), tokio::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // 在整个函数里持有 writer_guard，这样 shutdown() 调用时不会被其他任务抢走
    let mut writer_guard = writer.lock().await;
    let mut buffer = vec![0; 8 * 1024]; // 8KB 缓冲区

    loop {
        // 带超时的读取
        let read_future = reader.read(&mut buffer);
        let read_result = timeout(timeout_duration, read_future).await;

        let n = match read_result {
            Ok(Ok(0)) => {
                // EOF：对写端半关闭，让对端马上收到 FIN
                let _ = writer_guard.shutdown().await;
                break;
            }
            Ok(Ok(n)) => n,

            Ok(Err(e)) => {
                eprintln!("{}：读取错误：{}", direction, e);
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }

            Err(_) => {
                eprintln!("{}：读取超时", direction);
                let _ = writer_guard.shutdown().await;
                return Err(std::io::Error::new(ErrorKind::TimedOut, "读取超时"));
            }
        };

        // 带超时的写入
        let write_future = writer_guard.write_all(&buffer[..n]);
        let write_result = timeout(timeout_duration, write_future).await;
        match write_result {
            Ok(Ok(_)) => {
                // 写入成功，继续循环
            }

            Ok(Err(e)) => {
                eprintln!("{}：写入错误：{}", direction, e);
                let _ = writer_guard.shutdown().await;
                return Err(e);
            }

            Err(_) => {
                eprintln!("{}：写入超时", direction);
                let _ = writer_guard.shutdown().await;
                return Err(std::io::Error::new(ErrorKind::TimedOut, "写入超时"));
            }
        }
    }

    // 循环因 EOF 跳出，返回 Ok
    Ok(())
}