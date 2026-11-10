//! RFC 1928 UDP relay. Datagram payloads remain SOCKS-encapsulated to the upstream.
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{lookup_host, TcpStream, UdpSocket},
};

fn valid_packet(packet: &[u8]) -> bool {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return false;
    }
    let header = match packet[3] {
        1 => 10,
        4 => 22,
        3 if packet.len() >= 5 && packet[4] > 0 => 7 + packet[4] as usize,
        _ => return false,
    };
    packet.len() >= header
}

async fn upstream(host: &str) -> io::Result<(TcpStream, SocketAddr)> {
    let mut control = TcpStream::connect(host).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    control.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::other("Upstream SOCKS authentication rejected"));
    }
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 4];
    control.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!(
            "Upstream UDP ASSOCIATE rejected: {}",
            reply[1]
        )));
    }
    let ip = match reply[3] {
        1 => {
            let mut bytes = [0; 4];
            control.read_exact(&mut bytes).await?;
            IpAddr::from(bytes)
        }
        4 => {
            let mut bytes = [0; 16];
            control.read_exact(&mut bytes).await?;
            IpAddr::from(bytes)
        }
        3 => {
            let len = control.read_u8().await? as usize;
            let mut bytes = vec![0; len];
            control.read_exact(&mut bytes).await?;
            let name = std::str::from_utf8(&bytes)
                .map_err(|_| io::Error::other("Invalid upstream domain"))?;
            let resolved = lookup_host((name, 0))
                .await?
                .next()
                .ok_or_else(|| io::Error::other("Upstream domain has no addresses"))?
                .ip();
            resolved
        }
        _ => return Err(io::Error::other("Invalid upstream address type")),
    };
    let port = control.read_u16().await?;
    if port == 0 {
        return Err(io::Error::other("Upstream returned zero UDP port"));
    }
    let ip = if ip.is_unspecified() {
        control.peer_addr()?.ip()
    } else {
        ip
    };
    Ok((control, SocketAddr::new(ip, port)))
}

async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u8,
    addr: SocketAddr,
) -> io::Result<()> {
    let mut bytes = vec![5, code, 0];
    match addr.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(addr.port().to_be_bytes());
    stream.write_all(&bytes).await
}

pub async fn associate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
    local_ip: IpAddr,
    host: &str,
    timeout: Duration,
    idle: Duration,
) -> anyhow::Result<()> {
    let setup = tokio::time::timeout(timeout, async {
        let (control, remote) = upstream(host).await?;
        let outgoing = UdpSocket::bind(if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        outgoing.connect(remote).await?;
        let incoming = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        Ok::<_, io::Error>((control, outgoing, incoming))
    })
    .await;
    let (mut control, outgoing, incoming) = match setup {
        Ok(Ok(value)) => value,
        other => {
            let _ =
                tokio::time::timeout(timeout, reply(stream, 1, SocketAddr::new(local_ip, 0))).await;
            return Err(anyhow::anyhow!("UDP setup failed: {other:?}"));
        }
    };
    tokio::time::timeout(timeout, reply(stream, 0, incoming.local_addr()?)).await??;
    let mut client = None;
    let mut from_client = vec![0; 65535];
    let mut from_upstream = vec![0; 65535];
    let mut probe_client = [0; 1];
    let mut probe_upstream = [0; 1];
    let deadline = tokio::time::sleep(idle);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            // Association lifetime is tied to both TCP control connections.
            _ = stream.read(&mut probe_client) => break,
            _ = control.read(&mut probe_upstream) => break,
            _ = &mut deadline => break,
            received = incoming.recv_from(&mut from_client) => {
                let (len, source) = received?;
                if source.ip() != peer.ip() || client.is_some_and(|addr| addr != source) || !valid_packet(&from_client[..len]) { continue; }
                client = Some(source);
                tokio::time::timeout(timeout, outgoing.send(&from_client[..len])).await??;
                deadline.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            received = outgoing.recv(&mut from_upstream) => {
                let len = received?;
                if let Some(client) = client {
                    if !valid_packet(&from_upstream[..len]) { continue; }
                    tokio::time::timeout(timeout, incoming.send_to(&from_upstream[..len], client)).await??;
                    deadline.as_mut().reset(tokio::time::Instant::now() + idle);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_headers_and_rejects_fragments() {
        assert!(valid_packet(&[0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42]));
        assert!(valid_packet(&[0, 0, 0, 3, 1, b'a', 0, 53]));
        assert!(valid_packet(
            &[0; 3]
                .into_iter()
                .chain([4])
                .chain([0; 18])
                .collect::<Vec<_>>()
        ));
        for packet in [
            &[0, 0, 1, 1, 127, 0, 0, 1, 0, 53][..],
            &[0, 0, 0, 1],
            &[0, 0, 0, 3, 5, b'a', 0, 53],
            &[1, 0, 0, 1, 127, 0, 0, 1, 0, 53],
        ] {
            assert!(!valid_packet(packet));
        }
    }

    #[tokio::test]
    async fn upstream_rejection_is_reported() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let host = listener.local_addr().unwrap().to_string();
            let upstream_task = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                tcp.read_exact(&mut greeting).await.unwrap();
                tcp.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                tcp.read_exact(&mut request).await.unwrap();
                tcp.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });
            let (mut client, mut server) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                associate(
                    &mut server,
                    "127.0.0.1:1234".parse().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    &host,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .await
            });
            let mut response = [0; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 1]);
            assert!(task.await.unwrap().is_err());
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn idle_association_closes_upstream() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let host = listener.local_addr().unwrap().to_string();
            let upstream_task = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                tcp.read_exact(&mut greeting).await.unwrap();
                tcp.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                tcp.read_exact(&mut request).await.unwrap();
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                reply(&mut tcp, 0, socket.local_addr().unwrap())
                    .await
                    .unwrap();
                let mut byte = [0];
                assert_eq!(tcp.read(&mut byte).await.unwrap(), 0);
            });
            let (mut client, mut server) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                associate(
                    &mut server,
                    "127.0.0.1:1234".parse().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    &host,
                    Duration::from_secs(1),
                    Duration::from_millis(50),
                )
                .await
                .unwrap();
            });
            let mut response = [0; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 0]);
            task.await.unwrap();
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relays_udp_and_closes_with_client() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let host = listener.local_addr().unwrap().to_string();
            let upstream_task = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                tcp.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                tcp.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                tcp.read_exact(&mut request).await.unwrap();
                assert_eq!(request[1], 3);
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                reply(&mut tcp, 0, socket.local_addr().unwrap())
                    .await
                    .unwrap();
                let mut packet = [0; 100];
                let (len, peer) = socket.recv_from(&mut packet).await.unwrap();
                socket.send_to(&packet[..len], peer).await.unwrap();
                let mut byte = [0];
                assert_eq!(tcp.read(&mut byte).await.unwrap(), 0);
            });
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = client.local_addr().unwrap();
            let (mut client_control, mut server_control) = tokio::io::duplex(1024);
            let relay = tokio::spawn(async move {
                associate(
                    &mut server_control,
                    peer,
                    peer.ip(),
                    &host,
                    Duration::from_secs(1),
                    Duration::from_secs(3),
                )
                .await
                .unwrap();
            });
            let mut response = [0; 10];
            client_control.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], &[5, 0, 0, 1]);
            let relay_addr =
                SocketAddr::new(peer.ip(), u16::from_be_bytes([response[8], response[9]]));
            let packet = [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 42];
            // Fragmented packets must not reach the upstream.
            let mut fragmented = packet;
            fragmented[2] = 1;
            client.send_to(&fragmented, relay_addr).await.unwrap();
            client.send_to(&packet, relay_addr).await.unwrap();
            let mut response = [0; 100];
            let (len, _) = client.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[..len], &packet);
            drop(client_control);
            relay.await.unwrap();
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
    }
}
