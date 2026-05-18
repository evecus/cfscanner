use anyhow::Result;
use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::Rng;
use std::net::IpAddr;
use std::str::FromStr;

const IPV4_CIDRS: &str = include_str!("../assets/ipv4.txt");
const IPV6_CIDRS: &str = include_str!("../assets/ipv6.txt");
const COLO_DATA: &str = include_str!("../assets/colo.txt");

/// 默认采样上限
const DEFAULT_MAX_IPS: usize = 5500;

pub fn load_ips(mode: &str, max_ips: Option<usize>) -> Result<Vec<IpAddr>> {
    let limit = max_ips.unwrap_or(DEFAULT_MAX_IPS);

    let cidrs = match mode {
        "ipv4" => vec![IPV4_CIDRS],
        "ipv6" => vec![IPV6_CIDRS],
        "both" => vec![IPV4_CIDRS, IPV6_CIDRS],
        _ => anyhow::bail!("未知 mode: {}", mode),
    };

    // 先解析出所有网段
    let mut networks: Vec<IpNetwork> = Vec::new();
    for content in cidrs {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match IpNetwork::from_str(line) {
                Ok(net) => networks.push(net),
                Err(_) => {
                    if let Ok(ip) = IpAddr::from_str(line) {
                        // 单个 IP 包装成 /32 或 /128
                        let net = IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 })?;
                        networks.push(net);
                    } else {
                        tracing::warn!("跳过无效行: {}", line);
                    }
                }
            }
        }
    }

    // 打乱网段顺序，保证采样分布均匀（不总是从前几个网段取）
    networks.shuffle(&mut rand::thread_rng());

    // 从各网段按比例采样，总量不超过 limit
    // 策略：每个网段最多贡献 ceil(limit / 网段数) 个 IP
    let per_net = ((limit as f64 / networks.len() as f64).ceil() as usize).max(1);

    let mut ips: Vec<IpAddr> = Vec::with_capacity(limit);
    let mut rng = rand::thread_rng();

    for network in &networks {
        if ips.len() >= limit {
            break;
        }
        let remaining = limit - ips.len();
        let take = per_net.min(remaining);

        sample_from_network(network, take, &mut rng, &mut ips);
    }

    // 最后再整体打乱一次，消除网段顺序带来的偏差
    ips.shuffle(&mut rng);

    Ok(ips)
}

/// 从一个网段中随机采样 `take` 个 IP，直接追加到 `out`
/// 不展开整个网段，通过随机偏移量直接生成目标 IP
fn sample_from_network(network: &IpNetwork, take: usize, rng: &mut impl Rng, out: &mut Vec<IpAddr>) {
    match network {
        IpNetwork::V4(net) => {
            let base = u32::from(net.network());
            let size = net.size(); // u32，/24 = 256，/16 = 65536 ...

            if size <= take as u32 {
                // 网段本身就很小，直接全展开
                for ip in net.iter() {
                    out.push(IpAddr::V4(ip));
                }
            } else {
                // 用 reservoir sampling / 随机偏移，不展开整个网段
                let mut seen = std::collections::HashSet::with_capacity(take);
                let mut attempts = 0;
                while seen.len() < take && attempts < take * 4 {
                    attempts += 1;
                    let offset: u32 = rng.gen_range(0..size);
                    if seen.insert(offset) {
                        let addr = std::net::Ipv4Addr::from(base.wrapping_add(offset));
                        out.push(IpAddr::V4(addr));
                    }
                }
            }
        }
        IpNetwork::V6(net) => {
            let base = u128::from(net.network());
            // IPv6 网段极大，直接随机偏移
            let mask_bits = 128 - net.prefix();
            let size: u128 = if mask_bits >= 128 { u128::MAX } else { 1u128 << mask_bits };

            let mut seen = std::collections::HashSet::with_capacity(take);
            let mut attempts = 0;
            while seen.len() < take && attempts < take * 4 {
                attempts += 1;
                let offset: u128 = if size == u128::MAX {
                    rng.gen()
                } else {
                    rng.gen_range(0..size)
                };
                if seen.insert(offset) {
                    let addr = std::net::Ipv6Addr::from(base.wrapping_add(offset));
                    out.push(IpAddr::V6(addr));
                }
            }
        }
    }
}

pub fn load_colo_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in COLO_DATA.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            map.insert(parts[0].trim().to_uppercase(), parts[1].trim().to_string());
        }
    }
    map
}
