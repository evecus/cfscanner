use crate::config::SpeedTestConfig;
use crate::types::IpResult;
use anyhow::Result;
use rustls::{ClientConfig, ServerName};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

pub async fn run_speed_tests(
    results: &mut Vec<IpResult>,
    cfg: &SpeedTestConfig,
    regions_filter: Option<&[String]>,
) -> Result<()> {
    let indices: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            regions_filter
                .map(|regions| regions.iter().any(|reg| reg.eq_ignore_ascii_case(&r.colo)))
                .unwrap_or(true)
        })
        .take(cfg.top_n)
        .map(|(i, _)| i)
        .collect();

    let total = indices.len();
    if total == 0 {
        println!("  没有符合条件的 IP 可供测速");
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(5));
    let cfg_arc = Arc::new(cfg.clone());
    let mut handles = Vec::new();

    for &idx in &indices {
        let ip = results[idx].ip.clone();
        let port = results[idx].port;
        let cfg = cfg_arc.clone();
        let sem = sem.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let _permit = futures_lite::future::block_on(sem.acquire()).unwrap();
            (idx, measure_speed(&ip, port, &cfg))
        }));
    }

    let mut done = 0usize;
    for handle in handles {
        match handle.await {
            Ok((idx, Ok(speed))) => {
                done += 1;
                results[idx].speed_mbps = Some(speed);
                println!(
                    "  [{}/{}] {} | {}ms | {:.2} MB/s",
                    done, total, results[idx].ip, results[idx].delay_ms, speed
                );
            }
            Ok((idx, Err(e))) => {
                done += 1;
                println!(
                    "  [{}/{}] {} | 测速失败: {}",
                    done, total, results[idx].ip, e
                );
                warn!("{} 测速失败: {}", results[idx].ip, e);
            }
            Err(e) => {
                warn!("测速 task panic: {}", e);
            }
        }
    }

    // 按速度降序排列
    results.sort_by(|a, b| {
        b.speed_mbps
            .unwrap_or(0.0)
            .partial_cmp(&a.speed_mbps.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(())
}

fn measure_speed(ip: &str, port: u16, cfg: &SpeedTestConfig) -> Result<f64> {
    let addr = format!("{}:{}", ip, port);
    let tcp = TcpStream::connect_timeout(
        &addr.parse()?,
        std::time::Duration::from_millis(cfg.connect_timeout_ms),
    )?;
    tcp.set_read_timeout(Some(std::time::Duration::from_millis(cfg.duration_ms + 3000)))?;

    let tls_config = make_trust_all_tls();
    let server_name = ServerName::try_from("speed.cloudflare.com")
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    let request = format!(
        "GET /__down?bytes={} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        cfg.download_bytes
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // 跳过 HTTP 头
    let mut header_buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    let header_end_time;
    loop {
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("连接提前关闭"),
            Ok(_) => {
                header_buf.push(byte[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    header_end_time = Instant::now();
                    break;
                }
                if header_buf.len() > 32 * 1024 {
                    anyhow::bail!("HTTP 头过长");
                }
            }
            Err(e) => anyhow::bail!("读头失败: {}", e),
        }
    }

    // 计时读取 body
    let mut total_bytes: u64 = 0;
    let mut buf = vec![0u8; 16 * 1024];
    let max_dur = std::time::Duration::from_millis(cfg.duration_ms);
    loop {
        if header_end_time.elapsed() >= max_dur {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total_bytes += n as u64,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) => {
                debug!("读取中断: {}", e);
                break;
            }
        }
    }

    let elapsed_ms = header_end_time.elapsed().as_millis() as f64;
    if elapsed_ms < 100.0 || total_bytes == 0 {
        anyhow::bail!(
            "数据不足 bytes={} elapsed={}ms",
            total_bytes,
            elapsed_ms
        );
    }

    Ok((total_bytes as f64 * 1000.0) / elapsed_ms / 1_048_576.0)
}

fn make_trust_all_tls() -> ClientConfig {
    use rustls::client::ServerCertVerifier;
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::Certificate,
            _: &[rustls::Certificate],
            _: &ServerName,
            _: &mut dyn Iterator<Item = &[u8]>,
            _: &[u8],
            _: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerify));
    config
}
