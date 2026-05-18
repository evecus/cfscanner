use crate::config::ScanConfig;
use crate::types::IpResult;
use anyhow::Result;
use rand::Rng;
use rustls::{ClientConfig, ServerName};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

pub async fn scan_ips(
    ips: Vec<IpAddr>,
    cfg: &ScanConfig,
    progress_cb: impl Fn(usize, usize, Option<&IpResult>) + Send + Sync + 'static,
) -> Result<Vec<IpResult>> {
    let total = ips.len();
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let cfg = Arc::new(cfg.clone());
    let cb = Arc::new(progress_cb);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<IpResult>>(512);

    let collector = tokio::spawn(async move {
        let mut results = Vec::new();
        let mut done = 0usize;
        while let Some(maybe) = rx.recv().await {
            done += 1;
            cb(done, total, maybe.as_ref());
            if let Some(r) = maybe { results.push(r); }
        }
        results.sort_by_key(|r| r.delay_ms);
        results
    });

    let mut handles = Vec::with_capacity(ips.len());
    for ip in ips {
        let sem = sem.clone();
        let cfg = cfg.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let _ = tx.send(scan_single(ip, &cfg).await).await;
        }));
    }
    drop(tx);

    for h in handles { let _ = h.await; }
    Ok(collector.await?)
}

async fn scan_single(ip: IpAddr, cfg: &ScanConfig) -> Option<IpResult> {
    let addr = format!("{}:{}", ip, cfg.port);
    let delay = tcp_ping(&addr, cfg).await?;
    if delay > cfg.delay_threshold {
        debug!("{} 延迟 {}ms 超阈值", ip, delay);
        return None;
    }
    let colo = fetch_colo(ip, cfg.port).await?;
    debug!("{} delay={}ms colo={}", ip, delay, colo);
    Some(IpResult::new(ip.to_string(), cfg.port, delay, colo))
}

async fn tcp_ping(addr: &str, cfg: &ScanConfig) -> Option<u64> {
    let mut samples = Vec::new();
    let dur = Duration::from_millis(cfg.tcp_timeout_ms);
    for i in 0..cfg.ping_count {
        let start = Instant::now();
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                let ms = start.elapsed().as_millis() as u64;
                if ms > 0 { samples.push(ms); }
            }
            Ok(Err(_)) => return None,
            Err(_) => return None,
        }
        if i < cfg.ping_count - 1 {
            let wait = rand::thread_rng().gen_range(10u64..=30);
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
    }
    samples.into_iter().min()
}

/// 通过 TLS 连接发送 HTTP/1.1 请求获取 colo 字段
async fn fetch_colo(ip: IpAddr, port: u16) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    let request = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
        random_ua()
    );

    // 使用 spawn_blocking 在阻塞线程中做同步 TLS（与 speed_tester 保持一致）
    let result = tokio::task::spawn_blocking(move || -> Option<String> {
        let tcp = std::net::TcpStream::connect_timeout(
            &addr.parse().ok()?,
            Duration::from_millis(1500),
        ).ok()?;
        tcp.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;

        let tls_config = make_trust_all_tls();
        let server_name = ServerName::try_from("speed.cloudflare.com").ok()?;
        let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name).ok()?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);

        stream.write_all(request.as_bytes()).ok()?;
        stream.flush().ok()?;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 512];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 8192 { break; }
                }
                Err(e) if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => break,
                Err(_) => break,
            }
        }

        let body = String::from_utf8_lossy(&buf);
        for line in body.lines() {
            if let Some(colo) = line.strip_prefix("colo=") {
                let c = colo.trim().to_uppercase();
                if !c.is_empty() { return Some(c); }
            }
        }
        None
    }).await.ok()?;

    if result.is_none() {
        warn!("未找到 colo 字段，IP: {}", ip);
    }
    result
}

fn make_trust_all_tls() -> ClientConfig {
    use rustls::client::ServerCertVerifier;
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self, _: &rustls::Certificate, _: &[rustls::Certificate],
            _: &ServerName, _: &mut dyn Iterator<Item = &[u8]>,
            _: &[u8], _: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    config
}

fn random_ua() -> &'static str {
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    ];
    UAS[rand::thread_rng().gen_range(0..UAS.len())]
}
