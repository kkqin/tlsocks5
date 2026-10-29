use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
//use anyhow::{Error, Result};
use crate::io_utils;
use bytes::{BufMut, BytesMut};
use socket2::{SockRef, TcpKeepalive};
use std::net::Ipv6Addr;
use tokio::io::AsyncWriteExt; // Import the trait for shutdown

fn build_socks_request(target_address: &str) -> Option<BytesMut> {
    use std::net::ToSocketAddrs;

    let mut buffer = BytesMut::with_capacity(22); // Use BytesMut for buffer management

    buffer.put_u8(0x05); // SOCKS5
    buffer.put_u8(0x01); // CONNECT 请求
    buffer.put_u8(0x00); // 保留字段

    if let Ok(mut addrs) = target_address.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            match addr {
                SocketAddr::V4(v4) => {
                    buffer.put_u8(0x01); // IPv4 地址类型
                    buffer.put_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buffer.put_u8(0x04); // IPv6 地址类型
                    buffer.put_slice(&v6.ip().octets());
                }
            }
            buffer.put_u16(addr.port());
            return Some(buffer);
        }
    }

    None
}

fn enable_keepalive(stream: &TcpStream) {
    // 60 秒没数据开始探测，每 15 秒一次，5 次无响应就由内核拆掉。大约 2 分钟能清掉死连接。
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15))
        .with_retries(5);
    let sock = SockRef::from(stream);
    if let Err(e) = sock.set_keepalive(true) {
        eprintln!("开启 TCP keepalive 失败: {e}");
        return;
    }
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        eprintln!("设置 TCP keepalive 失败: {e}");
    }
}

pub async fn handle_conn(
    peer_addr: SocketAddr,
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    timeout: Duration,
    idle: Duration,
    auth_passwords: &[String],
    ip_list: &[String],
) -> anyhow::Result<()> {
    enable_keepalive(&stream);
    // ✅ TLS 握手设置超时
    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
        Ok(Err(e)) => {
            eprintln!("TLS 握手錯誤: {e:?}");
            return Err(e.into());
        }
        Ok(Ok(mut stream)) => {
            //println!("接受到新的 TLS 連線");
            let mut buf = [0; 2];
            if let Err(e) = io_utils::read_exact_timeout(&mut stream, &mut buf, timeout).await {
                stream.shutdown().await.ok();
                return Err(anyhow::Error::new(e));
            }
            //Socks5 v5
            let v = match buf.first() {
                Some(v) => *v,
                None => {
                    stream.shutdown().await.unwrap_or_default();
                    let e = std::io::Error::other("讀取版本失敗");
                    return Err(anyhow::Error::new(e));
                }
            };
            if v != 0x05 {
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("is not socks5: {}, now shutdwon", buf[0]);
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            }

            // len
            let l = buf[1];
            if l as usize > 255 {
                stream.shutdown().await.unwrap_or_default();
                return Err(anyhow::anyhow!("Invalid method buffer length"));
            }
            let mut methodbuf = vec![0u8; l as usize];
            if (io_utils::read_exact_timeout(&mut stream, &mut methodbuf, timeout).await).is_err() {
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("is not socks5: {}, now shutdwon", buf[0]);
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            }

            // 如果支持使用者名稱/密碼認證，回覆認證方式 0x02
            let reply = if methodbuf.contains(&0x02) {
                [0x05, 0x02] // 0x02: 使用者名稱/密碼認證
            } else {
                [0x05, 0x00] // 0x00: 無需認證
            };

            if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                eprintln!();
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("write reply error: {e}");
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            }

            // 如果需要使用者名稱/密碼認證
            let p: String = if reply[1] == 0x02 {
                let mut buffer = BytesMut::with_capacity(1024);
                if let Err(e) = io_utils::read_buf_timeout(&mut stream, &mut buffer, timeout).await
                {
                    stream.shutdown().await.ok();
                    return Err(anyhow::Error::new(e));
                }

                // 检查是否超限
                if buffer.len() > 1024 {
                    stream.shutdown().await.ok();
                    return Err(anyhow::anyhow!("Authentication packet too large"));
                }

                let len = match buffer.get(1) {
                    Some(len) => *len,
                    None => {
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = "讀取長度失敗".to_string();
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }
                };
                let username = &buffer[2usize..2 + len as usize].to_vec();
                let username = String::from_utf8(username.to_vec())
                    .unwrap_or_else(|_| String::from("unknown"));
                let len2 = buffer[(1 + 1 + len) as usize];
                let password =
                    &buffer[(2 + len + 1) as usize..(2 + len + 1 + len2) as usize].to_vec();
                let password = String::from_utf8(password.to_vec())
                    .unwrap_or_else(|_| String::from("badpassword"));
                //print!("{username}, {password}\n");

                let mut reply = [0x01, 0x00];
                let mut success = true;

                // 检查密码
                if !auth_passwords.contains(&password) {
                    reply = [0x01, 0x01];
                    success = false;
                }
                if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                    stream.shutdown().await.unwrap_or_default();
                    let e_str = format!("write reply error: {e}");
                    let e = std::io::Error::other(e_str);
                    return Err(anyhow::Error::new(e));
                }
                if !success {
                    stream.shutdown().await.unwrap_or_default();
                    let e_str = format!("認證失敗: {username}, {password}, r:{peer_addr}");
                    let e = std::io::Error::other(e_str);
                    return Err(anyhow::Error::new(e));
                }
                password.clone()
            } else {
                let reply = [0x00, 0x00];
                if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                    stream.shutdown().await.unwrap_or_default();
                    let e_str = format!("write reply error: {e}");
                    let e = std::io::Error::other(e_str);
                    return Err(anyhow::Error::new(e));
                }
                stream.shutdown().await.unwrap_or_default();
                let e_str = "非socks認證".to_string();
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            };

            let mut reqbuf = [0; 4];
            if let Err(e) = io_utils::read_exact_timeout(&mut stream, &mut reqbuf, timeout).await {
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("error read {e}");
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            }

            if reqbuf[0] != 0x05 {
                stream.shutdown().await.unwrap_or_default();
                let e_str = "not socks5 protocol!".to_string();
                let e = std::io::Error::other(e_str);
                return Err(anyhow::Error::new(e));
            }
            let _cmd = reqbuf[1];
            let atyp = reqbuf[3];

            let target_address = match atyp {
                0x01 => {
                    //IPV4
                    let mut addr = [0; 4];
                    io_utils::read_exact_timeout(&mut stream, &mut addr, timeout)
                        .await
                        .unwrap();
                    let mut portbuf = [0; 2];
                    io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout)
                        .await
                        .unwrap();
                    let port = u16::from_be_bytes(portbuf);
                    format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
                }
                0x03 => {
                    //Domain name
                    let mut lenbuf = [0; 1];
                    io_utils::read_exact_timeout(&mut stream, &mut lenbuf, timeout)
                        .await
                        .unwrap();
                    let len = lenbuf[0];
                    let mut domainbuf = vec![0; len as usize];
                    io_utils::read_exact_timeout(&mut stream, &mut domainbuf, timeout)
                        .await
                        .unwrap();
                    let mut portbuf = [0u8; 2];
                    io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout)
                        .await
                        .unwrap();
                    let port = u16::from_be_bytes(portbuf);
                    format!("{}:{}", String::from_utf8_lossy(&domainbuf), port)
                }
                0x04 => {
                    //IPV6
                    let mut addr = [0u8; 16];
                    io_utils::read_exact_timeout(&mut stream, &mut addr, timeout)
                        .await
                        .unwrap();
                    let mut portbuf = [0u8; 2];
                    io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout)
                        .await
                        .unwrap();
                    let port = u16::from_be_bytes(portbuf);
                    // Convert the addr array to an Ipv6Addr
                    let ip_address = Ipv6Addr::from(addr);
                    format!("[{ip_address}]:{port}")
                }
                _ => {
                    if let Err(e) = stream.shutdown().await {
                        eprintln!("shutdown error: {e}"); // 处理 shutdown 错误
                    }
                    let e_str = "atyp error!".to_string();
                    let e = std::io::Error::other(e_str);
                    return Err(anyhow::Error::new(e));
                }
            };

            let target_host = &ip_list[0];

            match tokio::time::timeout(timeout, TcpStream::connect(target_host)).await {
                Ok(Ok(mut proxy_stream)) => {
                    enable_keepalive(&proxy_stream);
                    //println!("連接到目標代理 SOCKS 服務成功");

                    // 1. 发送 SOCKS 握手
                    let handshake = [0x05, 0x01, 0x00]; // SOCKS5 + 支持的认证方法 (无认证)
                    if let Err(e) =
                        io_utils::write_all_timeout(&mut proxy_stream, &handshake, timeout).await
                    {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("發送代理握手失敗: {e}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 2. 接收代理响应的握手数据
                    let mut response = [0u8; 2];
                    if let Err(e) =
                        io_utils::read_exact_timeout(&mut proxy_stream, &mut response, timeout)
                            .await
                    {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("讀取代理握手回應失敗: {e}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }
                    if response[0] != 0x05 || response[1] != 0x00 {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("代理握手失敗: {response:?}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    //println!("代理握手成功");

                    // 3. 构建 SOCKS 请求，发送目标地址到代理
                    let target_request = match build_socks_request(&target_address) {
                        None => {
                            stream.shutdown().await?;
                            proxy_stream.shutdown().await?;
                            let e_str = "構建 SOCKS 請求失敗".to_string();
                            let e = std::io::Error::other(e_str);
                            return Err(anyhow::Error::new(e));
                        }
                        Some(request) => request,
                    };

                    if let Err(e) = io_utils::write_all_timeout(
                        &mut proxy_stream,
                        &target_request,
                        Duration::from_secs(20),
                    )
                    .await
                    {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("發送目標位址請求失敗: {e}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 4. 接收代理响应的目标连接状态
                    let mut request_response = [0u8; 10];
                    if let Err(e) = io_utils::read_exact_timeout(
                        &mut proxy_stream,
                        &mut request_response,
                        Duration::from_secs(20),
                    )
                    .await
                    {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("讀取代理回應失敗: {e}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }
                    if request_response[1] != 0x00 {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("代理連線目標失敗，錯誤代碼: {}", request_response[1]);
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    println!("->: {target_address} u:{p} r:{peer_addr}");

                    // 5. 回复 SOCKS 请求，表示客户端连接成功
                    let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    if let Err(e) =
                        io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5))
                            .await
                    {
                        stream.shutdown().await.unwrap_or_default();
                        proxy_stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("回覆用戶端 SOCKS 請求失敗: {e}");
                        let e = std::io::Error::other(e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 名额由调用方持有到这个 await 结束，所以这里不能再套一层 spawn。
                    match io_utils::copy_bidirectional_idle(
                        stream,
                        proxy_stream,
                        idle,
                        Duration::from_secs(120),
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            eprintln!("连接结束 {peer_addr}: {e}");
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::NotConnected
                            ) => {}
                        Err(e) => eprintln!("转发失败 {peer_addr}: {e}"),
                    }
                }
                Ok(Err(e)) => {
                    //eprintln!("連接目標 SOCKS 服務失敗: {e}");

                    // 连接失败时返回错误
                    let reply = [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    if let Err(_e) =
                        io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5))
                            .await
                    {
                        //eprintln!("回覆用戶端錯誤失敗: {e}");
                    }
                    return Err(anyhow::Error::new(e)); // 👈 或 spawn 的任务就此退出！
                }
                Err(_) => {
                    let reply = [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    let _ =
                        io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5))
                            .await;
                    return Err(anyhow::anyhow!("连接上游超时: {target_host}"));
                }
            }
        }
        Err(e) => {
            eprintln!("TLS 握手超時: {e}");
            return Err(anyhow::anyhow!("TLS 握手超時"));
        }
    };
    Ok(())
}
