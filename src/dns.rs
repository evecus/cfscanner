use crate::config::Config;
use crate::types::IpResult;
use anyhow::{Context, Result};
use tracing::warn;

const CF_API_BASE: &str = "https://api.cloudflare.com";

pub async fn sync_dns(results: &[IpResult], config: &Config) -> Result<()> {
    sync_dns_with_log(results, config).await?;
    Ok(())
}

/// 同 sync_dns，但额外返回每条操作的日志行，供 Web 状态页展示
pub async fn sync_dns_with_log(results: &[IpResult], config: &Config) -> Result<Vec<String>> {
    let dns = &config.dns;
    if !dns.enable {
        return Ok(vec![]);
    }

    let token = dns.token.as_ref().context("dns.token 未配置")?.clone();
    let zone_id = dns.zone_id.as_ref().context("dns.zone_id 未配置")?.clone();

    // 速度达标过滤：min_speed_mbps <= 0 时不过滤（保留旧行为）
    // results 此时已按综合评分（score）降序排好，所以这里保持顺序，
    // 只是从"全部结果"改为"达标结果"里取前 max_records 个
    let min_speed = config.speed_test.min_speed_mbps;
    let top_ips: Vec<IpResult> = results
        .iter()
        .filter(|r| min_speed <= 0.0 || r.speed_mbps.unwrap_or(0.0) >= min_speed)
        .take(dns.max_records)
        .cloned()
        .collect();

    if top_ips.is_empty() {
        let msg = if min_speed > 0.0 {
            format!("没有速度达标（>= {:.2} MB/s）的 IP 可同步", min_speed)
        } else {
            "没有可同步的 IP".to_string()
        };
        warn!("{}", msg);
        return Ok(vec![msg]);
    }

    if min_speed > 0.0 && top_ips.len() < dns.max_records {
        warn!(
            "达标 IP 只有 {} 个，少于配置的 max_records={}，仅同步这 {} 条",
            top_ips.len(), dns.max_records, top_ips.len()
        );
    }

    println!();
    println!("━━━ DNS 同步 ━━━");
    println!("  共 {} 条记录待同步", top_ips.len());
    println!();

    let config_clone = config.clone();

    let log = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
        let mut lines: Vec<String> = vec![];
        let mut ok_count = 0usize;
        let mut fail_count = 0usize;

        for (n, ip_result) in top_ips.iter().enumerate() {
            let domain = config_clone.dns_domain_for(n + 1).context("无法生成域名")?;

            match list_record_ids(&token, &zone_id, &domain) {
                Ok(ids) => {
                    for id in &ids {
                        match delete_record(&token, &zone_id, id) {
                            Ok(_) => println!("  [删除] {} (id={})", domain, id),
                            Err(e) => println!("  [删除失败] {} id={}: {}", domain, id, e),
                        }
                    }
                }
                Err(e) => {
                    println!("  [查询失败] {}: {}", domain, e);
                }
            }

            match create_record(
                &token,
                &zone_id,
                &domain,
                &ip_result.ip,
                &config_clone.dns.record_type,
                config_clone.dns.ttl,
            ) {
                Ok(_) => {
                    ok_count += 1;
                    let line = format!(
                        "[成功] {} → {}  延迟 {}ms",
                        domain, ip_result.ip, ip_result.delay_ms
                    );
                    println!("  {}", line);
                    lines.push(line);
                }
                Err(e) => {
                    fail_count += 1;
                    let line = format!("[失败] {} → {}  {}", domain, ip_result.ip, e);
                    println!("  {}", line);
                    lines.push(line);
                }
            }
        }

        println!();
        println!("DNS 同步完成  成功 {}  失败 {}", ok_count, fail_count);
        lines.push(format!("同步完成  成功 {}  失败 {}", ok_count, fail_count));
        Ok(lines)
    })
    .await
    .context("spawn_blocking 失败")??;

    Ok(log)
}

fn https_request(
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> Result<String> {
    let url = format!("{}{}", CF_API_BASE, path);
    let req = ureq::request(method, &url)
        .set("Authorization", &format!("Bearer {}", token))
        .timeout(std::time::Duration::from_secs(15));

    let resp = if let Some(b) = body {
        req.set("Content-Type", "application/json")
            .send_string(b)
            .map_err(|e| anyhow::anyhow!("HTTP 请求失败: {}", e))?
    } else {
        req.call()
            .map_err(|e| anyhow::anyhow!("HTTP 请求失败: {}", e))?
    };

    resp.into_string().context("读取响应体失败")
}

fn list_record_ids(token: &str, zone_id: &str, name: &str) -> Result<Vec<String>> {
    let path = format!(
        "/client/v4/zones/{}/dns_records?name={}&per_page=100",
        zone_id, name
    );
    let body = https_request("GET", &path, token, None)?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("解析 list_records 响应失败: {}", body))?;
    let ids = v["result"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|r| r["id"].as_str().map(|s| s.to_string()))
        .collect();
    Ok(ids)
}

fn delete_record(token: &str, zone_id: &str, record_id: &str) -> Result<()> {
    let path = format!("/client/v4/zones/{}/dns_records/{}", zone_id, record_id);
    https_request("DELETE", &path, token, None)?;
    Ok(())
}

fn create_record(
    token: &str,
    zone_id: &str,
    name: &str,
    ip: &str,
    record_type: &str,
    ttl: u32,
) -> Result<()> {
    let path = format!("/client/v4/zones/{}/dns_records", zone_id);
    let body = format!(
        r#"{{"type":"{}","name":"{}","content":"{}","ttl":{},"proxied":false}}"#,
        record_type, name, ip, ttl
    );
    let resp = https_request("POST", &path, token, Some(&body))?;
    let v: serde_json::Value = serde_json::from_str(&resp)
        .with_context(|| format!("解析 create_record 响应失败: {}", resp))?;
    if v["success"].as_bool() != Some(true) {
        anyhow::bail!("创建 DNS 记录失败 {}: {}", name, resp);
    }
    Ok(())
}
