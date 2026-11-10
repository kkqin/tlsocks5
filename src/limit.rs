use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 同时隧道数和单 IP 隧道数。许可要持有到转发结束。
pub struct Gate {
    global: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

pub struct Permit {
    _global: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

impl Gate {
    pub fn new(max_connections: usize, max_per_ip: usize) -> Self {
        let max_connections = max_connections.max(1);
        let max_per_ip = max_per_ip.max(1).min(max_connections);
        Self {
            global: Arc::new(Semaphore::new(max_connections)),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    pub fn max_per_ip(&self) -> usize {
        self.max_per_ip
    }

    /// 名额已满时返回 None。调用方应立刻关掉新进来的套接字，不要堵在 accept 上。
    pub fn try_acquire(&self, ip: IpAddr) -> Option<Permit> {
        let ip = canonical_ip(ip);
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.get(&ip).copied().unwrap_or(0);
        if count >= self.max_per_ip {
            return None;
        }
        let global = self.global.clone().try_acquire_owned().ok()?;
        *map.entry(ip).or_insert(0) += 1;
        Some(Permit {
            _global: global,
            per_ip: Arc::clone(&self.per_ip),
            ip,
        })
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

/// 按最坏的 UDP 隧道（两个控制连接、两个 UDP 套接字）预留描述符。
pub fn clamp_max_connections(max_connections: usize) -> usize {
    let Some(limit) = nofile_limit() else {
        return max_connections.max(1);
    };
    let budget = (limit as usize).saturating_sub(64) / 4;
    let budget = budget.max(1);
    if max_connections > budget {
        eprintln!(
            "nofile 上限是 {limit}，同时连接从 {max_connections} 降到 {budget}。每条 UDP 隧道要 4 个描述符，请把 nofile 调高后再提高 max_connections"
        );
        budget
    } else {
        max_connections.max(1)
    }
}

#[cfg(unix)]
fn nofile_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    if rc != 0 {
        return None;
    }
    // 无上限时不收缩。Linux 的 RLIM_INFINITY 和 macOS 的值都远大于此。
    if lim.rlim_cur > 1_000_000_000 {
        return None;
    }
    Some(lim.rlim_cur)
}

#[cfg(not(unix))]
fn nofile_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn per_ip_and_global_caps() {
        let gate = Gate::new(2, 1);
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();

        let first = gate.try_acquire(a).expect("first");
        assert!(gate.try_acquire(a).is_none(), "same ip");

        let second = gate.try_acquire(b).expect("second ip");
        assert!(gate.try_acquire(b).is_none(), "global full");

        drop(first);
        assert!(gate.try_acquire(a).is_some(), "slot returns after drop");
        drop(second);
    }

    #[test]
    fn ipv4_mapped_shares_the_slot() {
        let gate = Gate::new(10, 1);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mapped = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        let _permit = gate.try_acquire(v4).expect("v4");
        assert!(gate.try_acquire(mapped).is_none());
    }
}
