use anyhow::Result;
use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use std::net::IpAddr;
use std::str::FromStr;

const IPV4_CIDRS: &str = include_str!("../assets/ipv4.txt");
const IPV6_CIDRS: &str = include_str!("../assets/ipv6.txt");
const COLO_DATA: &str = include_str!("../assets/colo.txt");

pub fn load_ips(mode: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    match mode {
        "ipv4" => ips.extend(expand_cidrs(IPV4_CIDRS)?),
        "ipv6" => ips.extend(expand_cidrs(IPV6_CIDRS)?),
        "both" => {
            ips.extend(expand_cidrs(IPV4_CIDRS)?);
            ips.extend(expand_cidrs(IPV6_CIDRS)?);
        }
        _ => anyhow::bail!("未知 mode: {}", mode),
    }
    ips.shuffle(&mut rand::thread_rng());
    Ok(ips)
}

fn expand_cidrs(content: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        match IpNetwork::from_str(line) {
            Ok(network) => {
                let prefix = network.prefix();
                if prefix >= 24 {
                    // /24 及以下：全展开（最多 256 个）
                    for ip in network.iter() { ips.push(ip); }
                } else if prefix >= 16 {
                    // /16~/23：随机采样 256 个
                    use rand::Rng;
                    let all: Vec<IpAddr> = network.iter().take(65536).collect();
                    let take = 256.min(all.len());
                    let sample: Vec<IpAddr> = {
                        let mut v = all;
                        v.shuffle(&mut rand::thread_rng());
                        v.into_iter().take(take).collect()
                    };
                    ips.extend(sample);
                } else {
                    // 超大段：只取前 /24 子网的全展开，最多采样 512 个
                    let sample: Vec<IpAddr> = network.iter().take(512).collect();
                    ips.extend(sample);
                }
            }
            Err(_) => {
                if let Ok(ip) = IpAddr::from_str(line) {
                    ips.push(ip);
                } else {
                    tracing::warn!("跳过无效行: {}", line);
                }
            }
        }
    }
    Ok(ips)
}

pub fn load_colo_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in COLO_DATA.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            map.insert(parts[0].trim().to_uppercase(), parts[1].trim().to_string());
        }
    }
    map
}
