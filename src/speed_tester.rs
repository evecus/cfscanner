//! speed_tester.rs
//!
//! 移植自 p-box backend/modules/cloudflare 的多线程并发下载测速逻辑：
//!
//! 核心改进：
//!   1. 多连接并发下载同一 IP（download_threads 个线程同时跑），汇总总吞吐
//!   2. 下载量/时长可配，默认 100MB / 8s，足够让速度稳定
//!   3. 计时从发出请求开始（含 TLS 握手），与 p-box 保持一致
//!   4. 综合评分 score = speed*0.6 - latency*0.3 - loss_rate*0.1
//!      替代原来纯按速度排序，低延迟+高速度的 IP 排得更靠前
//!   5. 测速并发数从配置读取（speed_concurrency），默认 3
//!   6. 每个 IP 测速失败时自动重试一次，重试用缩短的 duration 快速确认，
//!      避免重试也等满一整个 duration_ms
//!   7. 达标速度过滤 + 分批补测（min_speed_mbps / max_batches）：
//!      按延迟顺序先测第一批 top_n 个 IP，如果达标（speed_mbps >= min_speed_mbps）
//!      的数量不够 dns.max_records 个，就从候选池里接着取下一批（同样大小）继续测，
//!      直到达标数够了、候选池耗尽、或测满 max_batches 批为止。
//!      min_speed_mbps <= 0 时该功能关闭，行为与之前一致（只测第一批 top_n 个）。

use crate::config::SpeedTestConfig;
use crate::types::IpResult;
use anyhow::Result;
use rustls::{ClientConfig, ServerName};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

// ── 公开入口 ────────────────────────────────────────────────────────────────

pub async fn run_speed_tests(
    results: &mut Vec<IpResult>,
    cfg: &SpeedTestConfig,
    regions_filter: Option<&[String]>,
    required_qualified: usize,
) -> Result<()> {
    // 候选池：按地区过滤后的全部下标，顺序即 results 现有顺序（外部已按延迟升序排好）
    let candidates: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            regions_filter
                .map(|regions| regions.iter().any(|reg| reg.eq_ignore_ascii_case(&r.colo)))
                .unwrap_or(true)
        })
        .map(|(i, _)| i)
        .collect();

    if candidates.is_empty() {
        println!("  没有符合条件的 IP 可供测速");
        return Ok(());
    }

    let batch_size = cfg.top_n.max(1);
    let min_speed = cfg.min_speed_mbps;
    // min_speed_mbps <= 0 表示不限制：只测第一批就结束，等价于旧行为
    let batching_enabled = min_speed > 0.0;
    let max_batches = if batching_enabled { cfg.max_batches.max(1) } else { 1 };
    // 达标数量目标：优先用调用方传入的 dns.max_records，至少测够 batch_size 保底
    let target_qualified = if batching_enabled {
        required_qualified.max(1)
    } else {
        usize::MAX // 不限制时不提前停批（反正只有 1 批）
    };

    let mut tested_count = 0usize;
    let mut qualified_count = 0usize;
    let mut cursor = 0usize; // 候选池游标

    for batch_no in 1..=max_batches {
        if cursor >= candidates.len() {
            break;
        }
        let end = (cursor + batch_size).min(candidates.len());
        let batch_indices = &candidates[cursor..end];
        cursor = end;

        if batching_enabled && batch_no > 1 {
            println!(
                "  达标 IP 不足（{}/{}），补测第 {} 批，共 {} 个候选",
                qualified_count, target_qualified, batch_no, batch_indices.len()
            );
        }

        let batch_qualified = run_one_batch(results, batch_indices, cfg, tested_count).await;
        tested_count += batch_indices.len();
        qualified_count += batch_qualified;

        if qualified_count >= target_qualified {
            break;
        }
        if cursor >= candidates.len() {
            println!(
                "  候选池已耗尽，达标 IP 共 {} 个（目标 {}）",
                qualified_count, target_qualified
            );
            break;
        }
    }

    // 按综合评分降序，没有评分（测速失败）的排到最后
    results.sort_by(|a, b| {
        let sa = a.score.unwrap_or(f64::NEG_INFINITY);
        let sb = b.score.unwrap_or(f64::NEG_INFINITY);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    if batching_enabled {
        println!(
            "  测速结束：共测 {} 个 IP，达标（>= {:.2} MB/s）{} 个",
            tested_count, min_speed, qualified_count
        );
    }

    Ok(())
}

/// 对一批下标做并发测速，写回 results，返回本批中"达标"（speed_mbps >= min_speed_mbps）的数量。
/// min_speed_mbps <= 0 时视为不限制，测速成功即算达标。
async fn run_one_batch(
    results: &mut Vec<IpResult>,
    batch_indices: &[usize],
    cfg: &SpeedTestConfig,
    already_done: usize,
) -> usize {
    let total_in_batch = batch_indices.len();
    let speed_concurrency = cfg.speed_concurrency.max(1);
    let sem = Arc::new(Semaphore::new(speed_concurrency));
    let cfg_arc = Arc::new(cfg.clone());
    let mut handles = Vec::new();

    for &idx in batch_indices {
        let ip   = results[idx].ip.clone();
        let port = results[idx].port;
        let delay = results[idx].delay_ms;
        let cfg  = cfg_arc.clone();
        let sem  = sem.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let _permit = futures_lite::future::block_on(sem.acquire()).unwrap();
            let speed = measure_speed_with_retry(&ip, port, &cfg);
            (idx, delay, speed)
        }));
    }

    let mut done = 0usize;
    let mut qualified = 0usize;
    for handle in handles {
        match handle.await {
            Ok((idx, delay_ms, Ok((speed_mbps, elapsed_ms, total_mb)))) => {
                done += 1;
                results[idx].speed_mbps = Some(speed_mbps);
                results[idx].score = Some(calculate_score(speed_mbps, delay_ms, 0.0));

                let is_qualified = cfg.min_speed_mbps <= 0.0 || speed_mbps >= cfg.min_speed_mbps;
                if is_qualified {
                    qualified += 1;
                }
                let mark = if cfg.min_speed_mbps > 0.0 {
                    if is_qualified { " [达标]" } else { " [不达标]" }
                } else {
                    ""
                };
                println!(
                    "  [{}/{}] {:<20} | {:>4}ms | {:>7.2} MB/s | {:.2}MB/{:.1}s{}",
                    already_done + done, already_done + total_in_batch,
                    results[idx].ip,
                    delay_ms,
                    speed_mbps,
                    total_mb,
                    elapsed_ms / 1000.0,
                    mark,
                );
            }
            Ok((idx, _, Err(e))) => {
                done += 1;
                println!(
                    "  [{}/{}] {:<20} | 测速失败: {}",
                    already_done + done, already_done + total_in_batch, results[idx].ip, e
                );
                warn!("{} 测速失败: {}", results[idx].ip, e);
            }
            Err(e) => {
                warn!("测速 task panic: {}", e);
            }
        }
    }

    qualified
}

// ── 评分公式（对应 p-box calculateScoreWithLoss）───────────────────────────
//
// score = speed_mbps * 0.6  （速度权重 60%）
//       - latency_ms * 0.3  （延迟惩罚  30%，单位 ms 缩放到合理范围）
//       - loss_rate  * 0.1  （丢包惩罚  10%，cfscanner 暂无丢包数据故传 0）
//
// 之所以不做归一化：延迟通常 10~200ms，速度通常 1~50 MB/s，
// 乘以系数后量纲接近，综合排序结果符合直觉：
//   200ms + 30MB/s → 30*0.6 - 200*0.3 = 18 - 60 = -42
//    50ms + 15MB/s → 15*0.6 -  50*0.3 = 9  - 15 = -6   ← 更靠前，符合直觉
//    50ms + 30MB/s → 30*0.6 -  50*0.3 = 18 - 15 = 3    ← 最优
fn calculate_score(speed_mbps: f64, latency_ms: u64, loss_rate: f64) -> f64 {
    speed_mbps * 0.6 - (latency_ms as f64) * 0.3 - loss_rate * 0.1
}

// ── 单 IP 测速（含一次重试）─────────────────────────────────────────────────

fn measure_speed_with_retry(
    ip: &str,
    port: u16,
    cfg: &SpeedTestConfig,
) -> Result<(f64, f64, f64)> {
    match measure_speed_multiconn(ip, port, cfg) {
        Ok(r) => Ok(r),
        Err(e) => {
            debug!("{} 第一次测速失败({})，重试...", ip, e);
            // 重试前等 200ms，避免立即再次超时
            std::thread::sleep(Duration::from_millis(200));

            // 重试用缩短的 duration（最短 2s），只为快速确认这个 IP 是否真的不可用，
            // 避免第一次已经等了 duration_ms，重试又完整等一遍导致该 IP 总耗时翻倍
            let mut retry_cfg = cfg.clone();
            retry_cfg.duration_ms = (cfg.duration_ms / 2).max(2000).min(cfg.duration_ms);
            measure_speed_multiconn(ip, port, &retry_cfg)
        }
    }
}

// ── 多连接并发下载（p-box testSpeedPhase 核心逻辑）─────────────────────────
//
// 对同一个 IP:port 同时建立 download_threads 条 TLS 连接，
// 每条都向 speed.cloudflare.com/__down 发送独立 GET 请求，
// 汇总所有连接的实际读取字节数，计算总吞吐量。
//
// 返回：(speed_mbps, elapsed_ms, total_downloaded_mb)
fn measure_speed_multiconn(
    ip: &str,
    port: u16,
    cfg: &SpeedTestConfig,
) -> Result<(f64, f64, f64)> {
    let threads    = cfg.download_threads.max(1);
    let bytes_each = cfg.download_bytes / threads;  // 每条连接的请求字节数
    let max_dur    = Duration::from_millis(cfg.duration_ms);
    let conn_timeout = Duration::from_millis(cfg.connect_timeout_ms);
    let addr = format!("{}:{}", ip, port);

    // 共享计数器：所有线程写入总字节数
    let total_bytes = Arc::new(Mutex::new(0u64));
    let start = Instant::now();

    // 建立所有连接，收集句柄
    let mut thread_handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let addr        = addr.clone();
        let total_bytes = total_bytes.clone();
        let bytes_each  = bytes_each;
        let max_dur     = max_dur;
        let conn_timeout = conn_timeout;

        let h = std::thread::spawn(move || -> Result<()> {
            // TCP 连接
            let tcp = TcpStream::connect_timeout(&addr.parse()?, conn_timeout)?;
            tcp.set_read_timeout(Some(max_dur + Duration::from_secs(2)))?;

            // TLS 握手（信任所有证书，与 p-box 行为一致）
            let tls_config  = make_trust_all_tls();
            let server_name = ServerName::try_from("speed.cloudflare.com")
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)?;
            let mut stream = rustls::StreamOwned::new(conn, tcp);

            // 发出 GET 请求
            let req = format!(
                "GET /__down?bytes={} HTTP/1.1\r\nHost: speed.cloudflare.com\r\n\
                 User-Agent: Mozilla/5.0 (compatible; cfscanner)\r\n\
                 Accept: */*\r\nConnection: close\r\n\r\n",
                bytes_each
            );
            stream.write_all(req.as_bytes())?;
            stream.flush()?;

            // 跳过 HTTP 响应头（找 \r\n\r\n）
            let mut hbuf = Vec::with_capacity(4096);
            let mut b = [0u8; 1];
            loop {
                match stream.read(&mut b) {
                    Ok(0) => anyhow::bail!("连接提前关闭（读头阶段）"),
                    Ok(_) => {
                        hbuf.push(b[0]);
                        if hbuf.ends_with(b"\r\n\r\n") { break; }
                        if hbuf.len() > 64 * 1024 { anyhow::bail!("HTTP 头过长"); }
                    }
                    Err(e) => anyhow::bail!("读头失败: {}", e),
                }
            }

            // 读取 body，直到超时或连接关闭
            let mut buf = vec![0u8; 32 * 1024];
            let mut local_bytes: u64 = 0;
            loop {
                if start.elapsed() >= max_dur { break; }
                match stream.read(&mut buf) {
                    Ok(0)  => break,
                    Ok(n)  => local_bytes += n as u64,
                    Err(e) if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => break,
                    Err(e) => { debug!("读取中断: {}", e); break; }
                }
            }

            // 写入共享计数器
            *total_bytes.lock().unwrap() += local_bytes;
            Ok(())
        });
        thread_handles.push(h);
    }

    // 等待所有线程结束（最多 duration + 3s）
    let deadline = start + max_dur + Duration::from_secs(3);
    for h in thread_handles {
        // join 超时：若线程仍在跑，主线程继续（read_timeout 会中断线程）
        let _ = h.join();
        if Instant::now() > deadline { break; }
    }

    let elapsed_ms   = start.elapsed().as_millis() as f64;
    let bytes_total  = *total_bytes.lock().unwrap();

    if elapsed_ms < 500.0 || bytes_total == 0 {
        anyhow::bail!(
            "数据不足（bytes={}, elapsed={:.0}ms, threads={}）",
            bytes_total, elapsed_ms, threads
        );
    }

    // MB/s（注意：原代码单位是 MB/s，不是 Mbps；保持一致）
    let speed_mbs   = (bytes_total as f64 * 1000.0) / elapsed_ms / 1_048_576.0;
    let total_mb    = bytes_total as f64 / 1_048_576.0;

    Ok((speed_mbs, elapsed_ms, total_mb))
}

// ── TLS（跳过证书验证，与原代码一致）───────────────────────────────────────

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
    config.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    config
}
