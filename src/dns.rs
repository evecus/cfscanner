use crate::config::Config;
use crate::types::IpResult;
use anyhow::{Context, Result};
use tracing::{info, warn};

const CF_API_BASE: &str = "https://api.cloudflare.com";

pub async fn sync_dns(results: &[IpResult], config: &Config) -> Result<()> {
    let dns = &config.dns;
    if !dns.enable {
        return Ok(());
    }

    let token = dns.token.as_ref().context("dns.token 未配置")?.clone();
    let zone_id = dns.zone_id.as_ref().context("dns.zone_id 未配置")?.clone();

    let top_ips: Vec<IpResult> = results.iter().take(dns.max_records).cloned().collect();
    if top_ips.is_empty() {
        warn!("没有可同步的 IP");
        return Ok(());
    }

    info!("开始 DNS 同步，共 {} 条记录", top_ips.len());

    let config_clone = config.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        for (n, ip_result) in top_ips.iter().enumerate() {
            let domain = config_clone.dns_domain_for(n + 1).context("无法生成域名")?;

            let existing_ids = list_record_ids(&token, &zone_id, &domain)?;
            for id in &existing_ids {
                delete_record(&token, &zone_id, id)?;
                info!("删除旧记录 {} id={}", domain, id);
            }

            create_record(
                &token,
                &zone_id,
                &domain,
                &ip_result.ip,
                &config_clone.dns.record_type,
                config_clone.dns.ttl,
            )?;
            info!(
                "DNS 同步: {} → {} ({}ms)",
                domain, ip_result.ip, ip_result.delay_ms
            );
        }
        info!("DNS 同步完成");
        Ok(())
    })
    .await
    .context("spawn_blocking 失败")??;

    Ok(())
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
