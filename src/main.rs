use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::Duration;
use tokio_rustls::TlsAcceptor;
mod config;

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    //console_subscriber::init();
    // 建立 TLS 設定
    let tls_config = match config::load_tls_config("cert.pem", "key.pem").await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load TLS config: {e}");
            return Err(anyhow::Error::new(e));
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let config = match config::parse_file("config.ini").await {
        Ok(t) => t,
        Err(e) => {
            eprint!("Failed to parse config.ini: {e}");
            return Err(anyhow::Error::new(e));
        }
    };

    let port = config
        .get_str("base", "listen_port")
        .unwrap_or("1080".to_string());
    let timeout = match config.get_int("base", "time_out") {
        Some(t) => t,
        None => {
            let e = std::io::Error::other("Timeout not specified");
            return Err(anyhow::Error::new(e));
        }
    };
    let timeout = Duration::from_secs(timeout as u64);
    let idle = Duration::from_secs(setting(&config, "idle_timeout", 1800));
    let max_connections =
        tlssocks5::limit::clamp_max_connections(setting(&config, "max_connections", 400) as usize);
    let max_per_ip = setting(&config, "max_per_ip", 64) as usize;
    let gate = tlssocks5::limit::Gate::new(max_connections, max_per_ip);
    let host = "0.0.0.0".to_string() + ":" + &port;
    let connect_ips: Vec<String> = config
        .get_str_list("trans", "connect_ips") // 从配置文件中读取多个IP
        .unwrap_or_default();
    let connect_ports = config
        .get_str_list("trans", "connect_ports")
        .unwrap_or_default();
    let target_hosts: Vec<String> = connect_ips
        .iter()
        .zip(connect_ports.iter())
        .map(|(ip, port)| format!("{ip}:{port}"))
        .collect();

    let ip_list = Arc::new(target_hosts.clone());
    /*let ip_list_clone = ip_list.clone();
    tokio::spawn(async move {
        update_ip_list(ip_list_clone, target_hosts).await;
    });*/

    let auth_passwords = Arc::new(
        config
            .get_str_list("auth", "auth_passwords")
            .unwrap_or_default(),
    );

    let listener = match TcpListener::bind(&host).await {
        Ok(t) => t,
        Err(e) => {
            return Err(anyhow::Error::new(e));
        }
    };

    println!("SOCKS5 伺服器已啟動，監聽 {host} (TLS)");
    println!("SOCKS5 伺服器已啟動，目標 {ip_list:?}");
    println!("SOCKS5 伺服器已啟動，認證密碼 {auth_passwords:?}");
    println!(
        "同时连接上限 {max_connections}，单 IP 上限 {}，空闲 {} 秒且两个方向都没数据才断开",
        gate.max_per_ip(),
        idle.as_secs()
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("accept 失败: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let auth_passwords = Arc::clone(&auth_passwords);
        let ip_list = Arc::clone(&ip_list);

        // 满了就立刻丢掉，避免 accept 循环停住把后面的人都堵住。
        let Some(permit) = gate.try_acquire(peer_addr.ip()) else {
            eprintln!("连接已满，拒绝 {peer_addr}");
            drop(stream);
            continue;
        };

        tokio::spawn(async move {
            // 持有到 handle_conn 返回。转发结束前不能 drop。
            let _permit = permit;
            match tlssocks5::handle::handle_conn(
                peer_addr,
                &acceptor,
                stream,
                timeout,
                idle,
                &auth_passwords,
                &ip_list,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    println!("{e}")
                }
            }
        });
    }
}

fn setting(config: &config::Config, key: &str, default: u64) -> u64 {
    match config.get_int("base", key) {
        Some(v) if v > 0 => v as u64,
        Some(_) => {
            eprintln!("{key} 必须大于 0，改用 {default}");
            default
        }
        None => default,
    }
}
