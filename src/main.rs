use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio::time::Duration;
//use mimallocator::Mimalloc;
use std::sync::Arc;
mod config;

//#[global_allocator]
//static GLOBAL: Mimalloc = Mimalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //console_subscriber::init();
    // 建立 TLS 設定
    let tls_config = match config::load_tls_config("cert.pem", "key.pem").await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load TLS config: {}", e);
            return Err(anyhow::Error::new(e));
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let config = match config::parse_file("config.ini").await {
        Ok(t) => t,
        Err(e) => {
            eprint!("Failed to parse config.ini: {}", e);
            return Err(anyhow::Error::new(e));
        },
    };

    let port = config.get_str("base", "listen_port").unwrap_or("1080".to_string());
    let timeout = match config.get_int("base", "time_out") {
        Some(t) => t,
        None => {
            let e = std::io::Error::new(std::io::ErrorKind::Other, "Timeout not specified");
            return Err(anyhow::Error::new(e));
        },
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

    let ip_list = target_hosts.clone();
    /*let ip_list_clone = ip_list.clone();
    tokio::spawn(async move {
        update_ip_list(ip_list_clone, target_hosts).await;
    });*/

    let auth_passwords = config.get_str_list("auth", "auth_passwords").unwrap_or_default();

    let listener = match TcpListener::bind(&host).await{
        Ok(t) => t,
        Err(e) => {
            return Err(anyhow::Error::new(e));
        }
    };

    println!("SOCKS5 伺服器已啟動，監聽 {host} (TLS)");
    println!("SOCKS5 伺服器已啟動，目標 {:?}", ip_list);
    println!("SOCKS5 伺服器已啟動，認證密碼 {:?}", auth_passwords);

    let sem = Arc::new(tokio::sync::Semaphore::new(500)); // 最多同时处理100个连接

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let auth_passwords = auth_passwords.clone();
        let ip_list = ip_list.clone();

        let permit = sem.clone().acquire_owned().await.unwrap(); // 限制并发连接数

        tokio::spawn(async move {
            match tlssocks5::handle::handle_conn(
                &acceptor, stream, timeout, &auth_passwords, &ip_list
            ).await{
                Ok(()) => {println!("優雅結束")},
                Err(e) => {
                    println!("{}", e)
                }
            };

            drop(permit); // 显式释放 permit
        });
    }
}