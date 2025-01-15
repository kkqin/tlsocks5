use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{ServerConfig,Certificate, PrivateKey};
use std::error::Error;
use std::sync::Arc;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;
use bytes::BytesMut;
use std::net::Ipv6Addr;
use rand::seq::SliceRandom;
use tokio::time::sleep;
mod io_utils;
mod config;

async fn check_connection(address: &str) -> bool {
    match TcpStream::connect(address).await {
        Ok(_) => true,  // 连接成功
        Err(_) => false, // 连接失败
    }
}

async fn update_ip_list(ip_port_list: Arc<Mutex<Vec<String>>>, all_ip_ports: Vec<String>) {
    loop {
        let mut updated_ips = vec![];

        for ip in &all_ip_ports {
            if check_connection(ip).await {
                updated_ips.push(ip.clone());
            }
        }

        {
            // 更新共享的 IP 列表
            let mut ip_list_lock = ip_port_list.lock().await;
            *ip_list_lock = updated_ips;
        }

        // 等待 15 分钟
        sleep(Duration::from_secs(15 * 60)).await;
    }
}

fn build_socks_request(target_address: &str) -> Option<Vec<u8>> {
    use std::net::ToSocketAddrs;

    let mut buffer = Vec::new();

    buffer.push(0x05); // SOCKS5
    buffer.push(0x01); // CONNECT 请求
    buffer.push(0x00); // 保留字段

    if let Ok(mut addrs) = target_address.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    buffer.push(0x01); // IPv4 地址类型
                    buffer.extend_from_slice(&v4.ip().octets());
                }
                std::net::SocketAddr::V6(v6) => {
                    buffer.push(0x04); // IPv6 地址类型
                    buffer.extend_from_slice(&v6.ip().octets());
                }
            }
            buffer.extend_from_slice(&addr.port().to_be_bytes());
            return Some(buffer);
        }
    }

    None
}

/// 加载证书和私钥
async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, io::Error> {
    // 读取 cert.pem 文件
    // 异步读取 cert.pem 文件内容到 Vec<u8>
    let cert_file = tokio::fs::File::open(cert_path).await?;
    let mut cert_reader =  BufReader::new(cert_file);
    let mut buf : Vec<u8> = Vec::new();
    cert_reader.read_to_end(&mut buf).await?;
    let mut buf = buf.as_slice();

    // 使用 BufReader 解析 PEM 数据
    let certs = rustls_pemfile::certs(&mut buf)
        .into_iter()
        .map(|item|{
            item.map(|i| Certificate(i.to_vec()))
        })
        .collect::<Result<Vec<Certificate>, _ >>()?;

    // 读取 key.pem 文件
    let key_file = tokio::fs::File::open(key_path).await?;
    let mut key_reader = BufReader::new(key_file);
    let mut buf : Vec<u8> = Vec::new();
    key_reader.read_to_end(&mut buf).await?;
    let mut buf = buf.as_slice();
    let keys = rustls_pemfile::private_key(&mut buf)?;

    if keys.is_none() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "未找到有效私钥"));
    }

    // 配置 TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth() // 不要求客户端证书
        .with_single_cert(certs, PrivateKey(keys.unwrap().secret_der().to_vec()))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 建立 TLS 設定
    let tls_config = load_tls_config("cert.pem", "key.pem").await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let config = config::parse_file("config.ini")?;

    let port = config.get_str("base", "listen_port").unwrap_or("1080".to_string());
    let timeout = match config.get_int("base", "time_out") {
        Some(t) => t,
        None => {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("timeout error"))) as Box<dyn Error>);
        }
    };
    let timeout = Duration::from_secs(timeout as u64);
    let host = "0.0.0.0".to_string() + &":".to_string() + &port;
    let connect_ips: Vec<String> = config
        .get_str_list("trans", "connect_ips") // 从配置文件中读取多个IP
        .unwrap_or_default();
    let connect_ports = config.get_str_list("trans", "connect_ports").unwrap_or_default();
    let target_hosts: Vec<String> = connect_ips
        .iter()
        .zip(connect_ports.iter())
        .map(|(ip, port)| format!("{}:{}", ip, port))
        .collect();

    let ip_list = Arc::new(Mutex::new(target_hosts.clone()));
    let ip_list_clone = ip_list.clone();
    tokio::spawn(async move {
        update_ip_list(ip_list_clone, target_hosts).await;
    });

    let auth_passwords = config.get_str_list("auth", "auth_passwords").unwrap_or_default();

    let listener = TcpListener::bind(&host).await?;

    println!("SOCKS5 伺服器已啟動，監聽 {host} (TLS)");
    println!("SOCKS5 伺服器已啟動，目標 {:?}", ip_list);
    println!("SOCKS5 伺服器已啟動，認證密碼 {:?}", auth_passwords);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let auth_passwords = auth_passwords.clone();
        let ip_list = ip_list.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut stream) => {
                    println!("接受到新的 TLS 連線");

                    let mut buf = [0; 2];
                    if let Err(_) = io_utils::read_exact_timeout(&mut stream, &mut buf, timeout).await {
                      stream.shutdown().await.unwrap_or_default();
                      return;
                    }

                    //Socks5 v5
                    let v = match buf.get(0) {
                        Some(v) => *v,
                        None => {
                            eprintln!("讀取版本失敗");
                            stream.shutdown().await.unwrap_or_default();
                            return;
                        }
                    };
                    if v != 0x05 {
                      eprintln!("is not socks5: {}, now shutdwon", buf[0]);
                      stream.shutdown().await.unwrap_or_default();
                      return;
                    }

                    // len
                    let l =  buf[1];
                    let mut methodbuf = vec![0u8;l as usize];
                    if let Err(_) = io_utils::read_exact_timeout(&mut stream, &mut methodbuf, timeout).await {
                      stream.shutdown().await.unwrap_or_default();
                      return;
                    }

                    // 如果支持使用者名稱/密碼認證，回覆認證方式 0x02
                    let reply = if methodbuf.contains(&0x02) {
                        [0x05, 0x02]  // 0x02: 使用者名稱/密碼認證
                    } else {
                        [0x05, 0x00]  // 0x00: 無需認證
                    };

                    if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                        eprintln!("write reply error: {}", e);
                        stream.shutdown().await.unwrap_or_default();
                        return;
                    }

                    // 如果需要使用者名稱/密碼認證
                    if reply[1] == 0x02 {
                        let mut buffer = BytesMut::with_capacity(1024);
                        if let Err(_) = io_utils::read_buf_timeout(&mut stream, &mut buffer, timeout).await {
                            stream.shutdown().await.unwrap_or_default();
                            return;
                        }
                        let len = match buffer.get(1) {
                            Some(len) => *len,
                            None => {
                                eprintln!("讀取長度失敗");
                                stream.shutdown().await.unwrap_or_default();
                                return;
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
                            eprintln!("write reply error: {}",e);
                            stream.shutdown().await.unwrap_or_default();
                            return;
                        }
                        if !success {
                            eprintln!("認證失敗: {username}, {password}");
                            stream.shutdown().await.unwrap_or_default();
                            return;
                        }
                    } else {
                        let reply = [0x00, 0x00];
                        if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, timeout).await {
                            eprintln!("write reply error: {}",e);
                            stream.shutdown().await.unwrap_or_default();
                            return;
                        }
                        eprintln!("非socks認證");
                        stream.shutdown().await.unwrap_or_default();
                        return;
                    }

                    let mut reqbuf = [0; 4];
                    if let Err(_) = io_utils::read_exact_timeout(&mut stream, &mut reqbuf, timeout).await {
                      eprintln!("error read");
                      stream.shutdown().await.unwrap_or_default();
                      return;
                    }

                    if reqbuf[0] != 0x05 {
                      eprintln!("not socks5 protocol!");
                      stream.shutdown().await.unwrap_or_default();
                      return;
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
                        eprintln!("atyp error!");
                        if let Err(e) = stream.shutdown().await {
                            eprintln!("shutdown error: {}", e); // 处理 shutdown 错误
                        }
                        return;
                      }
                    };

                    let ip_list_lock = ip_list.lock().await;
                    let target_host = match ip_list_lock.choose(&mut rand::thread_rng()) {
                        Some(host) => host,
                        None => {
                            eprintln!("未找到目標主機");
                            let _ = stream.shutdown();
                            return;
                        }
                    };

                    match TcpStream::connect(target_host).await {
                        Ok(mut proxy_stream) => {
                            println!("連接到目標代理 SOCKS 服務成功");

                            // 1. 发送 SOCKS 握手
                            let handshake = [0x05, 0x01, 0x00]; // SOCKS5 + 支持的认证方法 (无认证)
                            if let Err(e) = io_utils::write_all_timeout(&mut proxy_stream, &handshake, timeout).await {
                                eprintln!("發送代理握手失敗: {}", e);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }

                            // 2. 接收代理响应的握手数据
                            let mut response = [0u8; 2];
                            if let Err(e) = io_utils::read_exact_timeout(&mut proxy_stream, &mut response, timeout).await {
                                eprintln!("讀取代理握手回應失敗: {}", e);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }
                            if response[0] != 0x05 || response[1] != 0x00 {
                                eprintln!("代理握手失敗: {:?}", response);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }

                            println!("代理握手成功");

                            // 3. 构建 SOCKS 请求，发送目标地址到代理
                            let target_request = build_socks_request(&target_address).unwrap_or_else(|| {
                               eprintln!("構建 SOCKS 請求失敗");
                               let _ = stream.shutdown();
                               let _ = proxy_stream.shutdown();
                               Vec::new()
                            });

                            if let Err(e) = io_utils::write_all_timeout(&mut proxy_stream, &target_request, Duration::from_secs(20)).await {
                                eprintln!("發送目標位址請求失敗: {}", e);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }

                            // 4. 接收代理响应的目标连接状态
                            let mut request_response = [0u8; 10];
                            if let Err(e) = io_utils::read_exact_timeout(&mut proxy_stream, &mut request_response, Duration::from_secs(20)).await {
                                eprintln!("讀取代理回應失敗: {}", e);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }
                            if request_response[1] != 0x00 {
                                eprintln!("代理連線目標失敗，錯誤代碼: {}", request_response[1]);
                                proxy_stream.shutdown().await.unwrap_or_default();
                                stream.shutdown().await.unwrap_or_default();
                                return;
                            }

                            println!("代理成功連線目標: {}", target_address);

                            // 5. 回复 SOCKS 请求，表示客户端连接成功
                            let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                            if let Err(e) = io_utils::write_all_timeout(&mut stream, &reply, Duration::from_secs(5)).await {
                                eprintln!("回覆用戶端 SOCKS 請求失敗: {}", e);
                                stream.shutdown().await.unwrap_or_default();
                                proxy_stream.shutdown().await.unwrap_or_default();
                                return;
                            }

                            // 6. 建立双向数据转发
                            let (client_reader, client_writer) = tokio::io::split(stream);
                            let (proxy_reader, proxy_writer) = tokio::io::split(proxy_stream);

                            let proxy_writer = Arc::new(Mutex::new(proxy_writer));
                            tokio::spawn({
                                let proxy_writer = Arc::clone(&proxy_writer);
                                async move {
                                    let _ = io_utils::handle_copy2(client_reader, proxy_writer, "客户端 -> 代理", Duration::from_secs(10)).await;
                                }
                            });

                            let client_writer = Arc::new(Mutex::new(client_writer));
                            tokio::spawn({
                                let client_writer = Arc::clone(&client_writer);
                                async move {
                                    let _ = io_utils::handle_copy2(proxy_reader, client_writer, "代理 -> 客户端", Duration::from_secs(10)).await;
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
                        }
                    }
                },
                Err(e) => {
                    eprintln!("TLS 握手失敗: {}", e);
                }
            };
        });
    }
}