use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_rustls::rustls::{ServerConfig,Certificate, PrivateKey};
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, BufReader};
use std::collections::HashMap;

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

async fn handle_username_password_auth(ste : &mut TlsStream<TcpStream>, map : &HashMap<String, String>) -> Result<(), Box<dyn Error>> {
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData,"failed")))
}

/// 加载证书和私钥
async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, Box<dyn Error>> {
    // 读取 cert.pem 文件
    // 异步读取 cert.pem 文件内容到 Vec<u8>
    let cert_file = tokio::fs::File::open(cert_path).await?;
    let mut cert_reader =  BufReader::new(cert_file);
    let mut buf : Vec<u8> = Vec::new();
    cert_reader.read_to_end(&mut buf).await?;

    // 使用 BufReader 解析 PEM 数据
    let certs = rustls_pemfile::certs(&mut buf.as_slice())
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
    let keys = rustls_pemfile::private_key(&mut buf.as_slice())?;

    if keys.is_none() {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "未找到有效私钥")));
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

    let listener = TcpListener::bind("127.0.0.1:1080").await?;

    println!("SOCKS5 伺服器已啟動，監聽 127.0.0.1:1080 (TLS)");

    // 假设这里是用户认证信息（实际应用中可以从数据库或配置文件中读取）
    let users = Arc::new(HashMap::from([
        ("user1".to_string(), "password1".to_string()),
        ("user2".to_string(), "password2".to_string()),
    ]));

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let users = users.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut stream) => {
                    println!("接受到新的 TLS 連線");

                    let mut buf = [0; 4];
                    if let Err(e) = stream.read_exact(&mut buf).await{
                      eprintln!("read greeting error : {}", e);
                      return;
                    }

                    //Socks5 v5
                    if buf[0] != 0x05 {
                        eprintln!("not socks5 protocol!");
                        return;
                    }
                    let nmethods = buf[1];
                    let methodbuf = vec![0u8;nmethods as usize];

                    // 如果支持使用者名稱/密碼認證，回覆認證方式 0x02
                    let reply = if methodbuf.contains(&0x02) {
                        [0x05, 0x02]  // 0x02: 使用者名稱/密碼認證
                    } else {
                        [0x05, 0x00]  // 0x00: 無需認證
                    };

                    if let Err(e) = stream.write_all(&reply).await {
                        eprintln!("write reply error: {}", e);
                        return;
                    }

                    // 如果需要使用者名稱/密碼認證
                    if reply[1] == 0x02 {
                        if let Err(e) = handle_username_password_auth(&mut stream, &users).await {
                            eprintln!("authentication failed: {}", e);
                            return;
                        }
                    }

                    let reply = [0x05, 0x00];
                    if let Err(e) = stream.write_all(&reply).await{
                      eprintln!("write reply error: {}",e);
                      return;
                    }

                    let mut reqbuf = [0; 4];
                    if let Err(e) = stream.read_exact(&mut reqbuf).await{
                      eprintln!("read request error: {}",e);
                      return;
                    }

                    if reqbuf[0] != 0x05 {
                        eprintln!("not socks5 protocol!");
                        return;
                    }
                    let _cmd = reqbuf[1];
                    let atyp = reqbuf[3];

                    let target_address = match atyp {
                      0x01 => { //IPV4
                        let mut addr = [0;4];
                        stream.read_exact(&mut addr).await.unwrap();
                        let mut portbuf = [0;2];
                        stream.read_exact(&mut portbuf).await.unwrap();
                        let port = u16::from_be_bytes(portbuf);
                        format!("{}.{}.{}.{}:{}", addr[0],addr[1],addr[2],addr[3], port)
                      },
                      0x03 => { //Domain name
                        let mut lenbuf = [0;1];
                        stream.read_exact(&mut lenbuf).await.unwrap();
                        let len = lenbuf[0];
                        let mut domainbuf = vec![0; len as usize];
                        stream.read_exact(&mut domainbuf).await.unwrap();
                        let mut portbuf = [0u8;2];
                        stream.read_exact(&mut portbuf).await.unwrap();
                        let port = u16::from_be_bytes(portbuf);
                        format!("{}:{}",String::from_utf8_lossy(&domainbuf), port)
                      },
                      0x04 => { //IPV6
                        let mut addr = [0u8;16];
                        stream.read_exact(&mut addr).await.unwrap();
                        let mut portbuf = [0u8;2];
                        stream.read_exact(&mut portbuf).await.unwrap();
                        let port = u16::from_be_bytes(portbuf);
                        format!("[{}]:{}", std::str::from_utf8(&addr).unwrap(),port)
                      },
                      _ => {
                        eprintln!("atyp error!");
                        return;
                      }
                    };
                    match TcpStream::connect("127.0.0.1:1081").await {
                        Ok(mut proxy_stream) => {
                            println!("連接到目標代理 SOCKS 服務成功");

                            // 1. 发送 SOCKS 握手
                            let handshake = [0x05, 0x01, 0x00]; // SOCKS5 + 支持的认证方法 (无认证)
                            if let Err(e) = proxy_stream.write_all(&handshake).await {
                                eprintln!("發送代理握手失敗: {}", e);
                                return;
                            }

                            // 2. 接收代理响应的握手数据
                            let mut response = [0u8; 2];
                            if let Err(e) = proxy_stream.read_exact(&mut response).await {
                                eprintln!("讀取代理握手回應失敗: {}", e);
                                return;
                            }
                            if response[0] != 0x05 || response[1] != 0x00 {
                                eprintln!("代理握手失敗: {:?}", response);
                                return;
                            }

                            println!("代理握手成功");

                            // 3. 构建 SOCKS 请求，发送目标地址到代理
                            let target_request = build_socks_request(&target_address).unwrap_or_else(|| {
                               eprintln!("構建 SOCKS 請求失敗");
                               vec![]
                            });

                            if let Err(e) = proxy_stream.write_all(&target_request).await {
                                eprintln!("發送目標位址請求失敗: {}", e);
                                return;
                            }

                            // 4. 接收代理响应的目标连接状态
                            let mut request_response = [0u8; 10];
                            if let Err(e) = proxy_stream.read_exact(&mut request_response).await {
                                eprintln!("讀取代理回應失敗: {}", e);
                                return;
                            }
                            if request_response[1] != 0x00 {
                                eprintln!("代理連線目標失敗，錯誤代碼: {}", request_response[1]);
                                return;
                            }

                            println!("代理成功連線目標: {}", target_address);

                            // 5. 回复 SOCKS 请求，表示客户端连接成功
                            let reply = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                            if let Err(e) = stream.write_all(&reply).await {
                                eprintln!("回覆用戶端 SOCKS 請求失敗: {}", e);
                                return;
                            }

                            // 6. 建立双向数据转发
                            let (mut client_reader, mut client_writer) = tokio::io::split(stream);
                            let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_stream);

                            tokio::spawn(async move {
                                let _ = copy(&mut client_reader, &mut proxy_writer).await;
                            });
                            tokio::spawn(async move {
                                let _ = copy(&mut proxy_reader, &mut client_writer).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("連接目標 SOCKS 服務失敗: {}", e);

                            // 连接失败时返回错误
                            let reply = [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                            if let Err(e) = stream.write_all(&reply).await {
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