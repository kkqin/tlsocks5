use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
//use anyhow::{Error, Result};
use tokio::io::AsyncWriteExt; // Import the trait for shutdown
use crate::io_utils;
use bytes::{BufMut, BytesMut};
use std::net::Ipv6Addr;

fn build_socks_request(target_address: &str) -> Option<BytesMut> {
    use std::net::ToSocketAddrs;

    let mut buffer = BytesMut::with_capacity(22); // Use BytesMut for buffer management

    buffer.put_u8(0x05); // SOCKS5
    buffer.put_u8(0x01); // CONNECT 请求
    buffer.put_u8(0x00); // 保留字段

    if let Ok(mut addrs) = target_address.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    buffer.put_u8(0x01); // IPv4 地址类型
                    buffer.put_slice(&v4.ip().octets());
                }
                std::net::SocketAddr::V6(v6) => {
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


pub async fn handle_conn(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    timeout: Duration,
    auth_passwords :&Vec<String>,
    ip_list: &Vec<String>
) -> anyhow::Result<()> {

    match acceptor.accept(stream).await {
        Ok(mut stream) => {
            println!("接受到新的 TLS 連線");

            let mut buf = [0; 2];
            if let Err(_) = io_utils::read_exact_timeout(&mut stream, &mut buf, timeout).await {
                stream.shutdown().await.ok();
                let e = std::io::Error::new(std::io::ErrorKind::Other, "Timeout not specified");
                return Err(anyhow::Error::new(e));
            }

            //Socks5 v5
            let v = match buf.get(0) {
                Some(v) => *v,
                None => {
                    stream.shutdown().await.unwrap_or_default();
                    let e = std::io::Error::new(std::io::ErrorKind::Other, "讀取版本失敗");
                    return Err(anyhow::Error::new(e));
                }
            };
            if v != 0x05 {
              stream.shutdown().await.unwrap_or_default();
              let e_str = format!("is not socks5: {}, now shutdwon", buf[0]);
              let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
              return Err(anyhow::Error::new(e));
            }

            // len
            let l =  buf[1];
            if l as usize > 255 {
                stream.shutdown().await.unwrap_or_default();
                return Err(anyhow::anyhow!("Invalid method buffer length"));
            }
            let mut methodbuf = vec![0u8;l as usize];
            if let Err(_) = io_utils::read_exact_timeout(&mut stream, &mut methodbuf, timeout).await {
              stream.shutdown().await.unwrap_or_default();
              let e_str = format!("is not socks5: {}, now shutdwon", buf[0]);
              let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
              return Err(anyhow::Error::new(e));
            }

            // 如果支持使用者名稱/密碼認證，回覆認證方式 0x02
            let reply = if methodbuf.contains(&0x02) {
                [0x05, 0x02]  // 0x02: 使用者名稱/密碼認證
            } else {
                [0x05, 0x00]  // 0x00: 無需認證
            };

            if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                eprintln!();
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("write reply error: {}", e);
                let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                return Err(anyhow::Error::new(e));
            }

            // 如果需要使用者名稱/密碼認證
            if reply[1] == 0x02 {
                let mut buffer = BytesMut::with_capacity(1024);
                if let Err(e) = io_utils::read_buf_timeout(&mut stream, &mut buffer, timeout).await {
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
                        let e_str = format!("讀取長度失敗");
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }
                };
                let username = &buffer[2usize..2+len as usize].to_vec();
                let username = match String::from_utf8(username.to_vec()) {
                    Ok(username) => username,
                    Err(_) => String::from("使用 unwrap_or_else 的預設字串"),
                };
                let len2 =  buffer[(1+1+len) as usize];
                let password = &buffer[(2+len+1) as usize ..(2+len+1+len2) as usize].to_vec();
                let password = match String::from_utf8(password.to_vec()) {
                    Ok(password) => password,
                    Err(_) => String::from("badpassword"),
                };
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
                    let e_str = format!("write reply error: {}",e);
                    let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                    return Err(anyhow::Error::new(e));
                }
                if !success {
                    stream.shutdown().await.unwrap_or_default();
                    let e_str = format!("認證失敗: {username}, {password}");
                    let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                    return Err(anyhow::Error::new(e));
                }
            } else {
                let reply = [0x00, 0x00];
                if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                    stream.shutdown().await.unwrap_or_default();
                    let e_str = format!("write reply error: {}",e);
                    let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                    return Err(anyhow::Error::new(e));
                }
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("非socks認證");
                let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                return Err(anyhow::Error::new(e));
            }

            let mut reqbuf = [0; 4];
            if let Err(e) = io_utils::read_exact_timeout(&mut stream, &mut reqbuf, timeout).await {
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("error read {}", e);
                let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                return Err(anyhow::Error::new(e));
            }

            if reqbuf[0] != 0x05 {
                stream.shutdown().await.unwrap_or_default();
                let e_str = format!("not socks5 protocol!");
                let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                return Err(anyhow::Error::new(e));
            }
            let _cmd = reqbuf[1];
            let atyp = reqbuf[3];

            let target_address = match atyp {
              0x01 => { //IPV4
                let mut addr = [0;4];
                io_utils::read_exact_timeout(&mut stream, &mut addr, timeout).await.unwrap();
                let mut portbuf = [0;2];
                io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout).await.unwrap();
                let port = u16::from_be_bytes(portbuf);
                format!("{}.{}.{}.{}:{}", addr[0],addr[1],addr[2],addr[3], port)
              },
              0x03 => { //Domain name
                let mut lenbuf = [0;1];
                io_utils::read_exact_timeout(&mut stream, &mut lenbuf, timeout).await.unwrap();
                let len = lenbuf[0];
                let mut domainbuf = vec![0; len as usize];
                io_utils::read_exact_timeout(&mut stream, &mut domainbuf, timeout).await.unwrap();
                let mut portbuf = [0u8;2];
                io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout).await.unwrap();
                let port = u16::from_be_bytes(portbuf);
                format!("{}:{}",String::from_utf8_lossy(&domainbuf), port)
              },
              0x04 => { //IPV6
                let mut addr = [0u8;16];
                io_utils::read_exact_timeout(&mut stream, &mut addr, timeout).await.unwrap();
                let mut portbuf = [0u8;2];
                io_utils::read_exact_timeout(&mut stream, &mut portbuf, timeout).await.unwrap();
                let port = u16::from_be_bytes(portbuf);
                // Convert the addr array to an Ipv6Addr
                let ip_address = Ipv6Addr::from(addr);
                format!("[{}]:{}", ip_address,port)
              },
              _ => {
                if let Err(e) = stream.shutdown().await {
                    eprintln!("shutdown error: {}", e); // 处理 shutdown 错误
                }
                let e_str = format!("atyp error!");
                let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                return Err(anyhow::Error::new(e));
              }
            };

            let target_host = &ip_list[0];

            match TcpStream::connect(target_host).await {
                Ok(mut proxy_stream) => {
                    println!("連接到目標代理 SOCKS 服務成功");

                    // 1. 发送 SOCKS 握手
                    let handshake = [0x05, 0x01, 0x00]; // SOCKS5 + 支持的认证方法 (无认证)
                    if let Err(e) = io_utils::write_all_timeout(&mut proxy_stream, &handshake, timeout).await {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("發送代理握手失敗: {}", e);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 2. 接收代理响应的握手数据
                    let mut response = [0u8; 2];
                    if let Err(e) = io_utils::read_exact_timeout(&mut proxy_stream, &mut response, timeout).await {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("讀取代理握手回應失敗: {}", e);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }
                    if response[0] != 0x05 || response[1] != 0x00 {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("代理握手失敗: {:?}", response);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    println!("代理握手成功");

                    // 3. 构建 SOCKS 请求，发送目标地址到代理
                    let target_request = match build_socks_request(&target_address){
                        None => {
                            let _ = stream.shutdown();
                            let _ = proxy_stream.shutdown();
                            let e_str = format!("構建 SOCKS 請求失敗");
                            let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                            return Err(anyhow::Error::new(e));
                        },
                        Some(request) => request
                    };

                    if let Err(e) = io_utils::write_all_timeout(&mut proxy_stream, &target_request, Duration::from_secs(20)).await {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("發送目標位址請求失敗: {}", e);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 4. 接收代理响应的目标连接状态
                    let mut request_response = [0u8; 10];
                    if let Err(e) = io_utils::read_exact_timeout(&mut proxy_stream, &mut request_response, Duration::from_secs(20)).await {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("讀取代理回應失敗: {}", e);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }
                    if request_response[1] != 0x00 {
                        proxy_stream.shutdown().await.unwrap_or_default();
                        stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("代理連線目標失敗，錯誤代碼: {}", request_response[1]);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    println!("代理成功連線目標: {}", target_address);

                    // 5. 回复 SOCKS 请求，表示客户端连接成功
                    let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5)).await {
                        stream.shutdown().await.unwrap_or_default();
                        proxy_stream.shutdown().await.unwrap_or_default();
                        let e_str = format!("回覆用戶端 SOCKS 請求失敗: {}", e);
                        let e = std::io::Error::new(std::io::ErrorKind::Other, e_str);
                        return Err(anyhow::Error::new(e));
                    }

                    // 6. 建立双向数据转发
                    tokio::spawn(async move {
                        if let Err(e) = tokio::time::timeout(timeout, tokio::io::copy_bidirectional(&mut stream, &mut proxy_stream)).await {
                            eprintln!("數據轉發超時或失敗: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("連接目標 SOCKS 服務失敗: {}", e);

                    // 连接失败时返回错误
                    let reply = [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5)).await {
                        eprintln!("回覆用戶端錯誤失敗: {}", e);
                    }
                    return Err(anyhow::Error::new(e)); // 👈 或 spawn 的任务就此退出！
                }
            }
        },
        Err(e) => {
            eprintln!("TLS 握手超時: {}", e);
            return Err(anyhow::anyhow!("TLS 握手超時"));
        }
    };
    Ok(())
}