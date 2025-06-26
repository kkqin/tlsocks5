use std::collections::HashMap;
use tokio::fs::File;
//use std::io::{BufRead, BufReader};
use bytes::BytesMut;
use std::io;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

#[derive(Debug)]
pub struct Config {
    values_: HashMap<String, HashMap<String, String>>,
}

impl Config {
    fn new() -> Config {
        Config {
            values_: HashMap::new(),
        }
    }

    fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.values_
            .get(section)
            .and_then(|v| v.get(key).map(|v| v.as_str()))
    }

    #[allow(dead_code)]
    pub fn has_section(&self, section: &str) -> bool {
        self.values_.contains_key(section)
    }

    pub fn get_int(&self, section: &str, key: &str) -> Option<i32> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

    pub fn get_str(&self, section: &str, key: &str) -> Option<String> {
        self.get(section, key).map(|v| v.to_string())
    }

    #[allow(dead_code)]
    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

    pub fn get_str_list(&self, section: &str, key: &str) -> Option<Vec<String>> {
        self.get(section, key)
            .map(|v| v.split(',').map(|v| v.trim().to_string()).collect())
    }
}

pub async fn parse_file(file_path: &str) -> Result<Config, io::Error> {
    let path = Path::new(file_path);
    let file = match File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("文件：{file_path}:{e}"),
            ))
        }
    };
    let reader = BufReader::new(file);
    let mut config = Config::new();
    let mut current_section = String::new();

    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = match parts.next() {
            Some(k) => k.trim(),
            None => {
                eprintln!("配置文件格式錯誤：缺少 key");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "配置格式错误：key".to_string()),
                );
            }
        };

        let value = match parts.next() {
            Some(k) => k.trim(),
            None => {
                eprintln!("配置文件格式錯誤：缺少 value");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "配置格式错误：value".to_string()),
                );
            }
        };

        config
            .values_
            .entry(current_section.clone())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }
    Ok(config)
}

/*async fn check_connection(address: &str) -> bool {
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
}*/

/// 加载证书和私钥
pub async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, io::Error> {
    // 读取 cert.pem 文件
    let cert_file = tokio::fs::File::open(cert_path).await?;
    let mut cert_reader = BufReader::new(cert_file);
    let mut buf = BytesMut::with_capacity(4096); // Use BytesMut for buffer management
    cert_reader.read_buf(&mut buf).await?;
    let mut buf = buf.as_ref();

    // 使用 BufReader 解析 PEM 数据
    let certs = rustls_pemfile::certs(&mut buf)
        .map(|item| item.map(|i| Certificate(i.to_vec())))
        .collect::<Result<Vec<Certificate>, _>>()?;

    // 读取 key.pem 文件
    let key_file = tokio::fs::File::open(key_path).await?;
    let mut key_reader = BufReader::new(key_file);
    let mut buf = BytesMut::with_capacity(4096); // Use BytesMut for buffer management
    key_reader.read_buf(&mut buf).await?;
    let mut buf = buf.as_ref();
    let keys = rustls_pemfile::private_key(&mut buf)?;

    if keys.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "未找到有效私钥",
        ));
    }

    // 配置 TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth() // 不要求客户端证书
        .with_single_cert(certs, PrivateKey(keys.unwrap().secret_der().to_vec()))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    Ok(config)
}
