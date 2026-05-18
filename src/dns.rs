use crate::config::Config;
use crate::types::IpResult;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio_rustls::rustls::{self, ClientConfig, ServerName};
use tracing::{info, warn};

const CF_API_HOST: &str = "api.cloudflare.com";
const CF_API_PORT: u16 = 443;

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

    // 整个 DNS 同步在 spawn_blocking 里执行，避免在 tokio 线程上做阻塞 DNS 解析
    let tls = make_tls_config();
    let config_clone = config.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        for (n, ip_result) in top_ips.iter().enumerate() {
            let domain = config_clone
                .dns_domain_for(n + 1)
                .context("无法生成域名")?;

            // 删除旧记录
            let existing_ids = list_record_ids(&tls, &token, &zone_id, &domain)?;
            for id in &existing_ids {
                delete_record(&tls, &token, &zone_id, id)?;
                info!("删除旧记录 {} id={}", domain, id);
            }

            // 创建新记录
            create_record(
                &tls,
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

/// 同步 HTTPS 请求，完全在 spawn_blocking 内运行，不依赖 tokio DNS
fn https_request(
    tls: &Arc<ClientConfig>,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> Result<String> {
    // 用标准库同步 DNS + TCP 连接，在 spawn_blocking 内调用完全安全
    let addrs: Vec<std::net::SocketAddr> = format!("{}:{}", CF_API_HOST, CF_API_PORT)
        .parse::<std::net::SocketAddr>()
        .map(|a| vec![a])
        .unwrap_or_else(|_| {
            // 字符串包含域名，走系统 getaddrinfo（此时在 blocking 线程，安全）
            use std::net::ToSocketAddrs;
            format!("{}:{}", CF_API_HOST, CF_API_PORT)
                .to_socket_addrs()
                .map(|iter| iter.collect())
                .unwrap_or_default()
        });

    let addr = addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("无法解析 {} 的地址", CF_API_HOST))?;

    let server_name = ServerName::try_from(CF_API_HOST)?;
    let conn = rustls::ClientConnection::new(Arc::clone(tls), server_name)?;
    let tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    let body_str = body.unwrap_or("");
    let content_type = if body.is_some() {
        "Content-Type: application/json\r\n"
    } else {
        ""
    };
    let content_length = if body.is_some() {
        format!("Content-Length: {}\r\n", body_str.len())
    } else {
        String::new()
    };

    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n{}{}Connection: close\r\n\r\n{}",
        method, path, CF_API_HOST, token, content_type, content_length, body_str
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let response_str = String::from_utf8_lossy(&response);
    if let Some(pos) = response_str.find("\r\n\r\n") {
        Ok(response_str[pos + 4..].to_string())
    } else {
        Ok(response_str.to_string())
    }
}

fn list_record_ids(
    tls: &Arc<ClientConfig>,
    token: &str,
    zone_id: &str,
    name: &str,
) -> Result<Vec<String>> {
    let path = format!(
        "/client/v4/zones/{}/dns_records?name={}&per_page=100",
        zone_id, name
    );
    let body = https_request(tls, "GET", &path, token, None)?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let ids = v["result"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|r| r["id"].as_str().map(|s| s.to_string()))
        .collect();
    Ok(ids)
}

fn delete_record(
    tls: &Arc<ClientConfig>,
    token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<()> {
    let path = format!(
        "/client/v4/zones/{}/dns_records/{}",
        zone_id, record_id
    );
    https_request(tls, "DELETE", &path, token, None)?;
    Ok(())
}

fn create_record(
    tls: &Arc<ClientConfig>,
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
    let resp = https_request(tls, "POST", &path, token, Some(&body))?;
    let v: serde_json::Value = serde_json::from_str(&resp)?;
    if v["success"].as_bool() != Some(true) {
        anyhow::bail!("创建 DNS 记录失败 {}: {}", name, resp);
    }
    Ok(())
}

fn make_tls_config() -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
