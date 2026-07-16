use crate::config::Config;
use crate::dns;
use crate::ip_loader::load_ips_excluding;
use crate::output::{export_csv, print_scan_summary, print_speed_params, print_speed_table};
use crate::scanner::{scan_ips, scan_ips_quiet};
use crate::speed_tester::run_speed_tests;
use crate::types::{IpResult, ScanState};
use crate::web::WebState;
use anyhow::Result;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{error, info};

/// 加载 IP 并扫描延迟，得到最终结果。
///
/// - `scan.regions` 为空：老行为，一次性采样 `max_ips` 个随机 IP，扫完就结束
///   （不管扫描出多少个可用结果，都不会再补扫）。
/// - `scan.regions` 非空：`max_ips` 变成"目标数量"——凑够这么多个属于目标地区
///   且延迟达标的 IP 才停止；每批采样 `batch_size` 个（不重复已扫过的 IP），
///   扫完累加命中数，不够就再取下一批，直到凑够 max_ips 个，
///   或扫满 max_scan_rounds 轮，或候选池已经耗尽（当批采样不到任何新 IP）为止。
async fn load_and_scan(config: &Config) -> Result<Vec<IpResult>> {
    let scan_cfg = &config.scan;
    let target = scan_cfg.max_ips.unwrap_or(8000);

    // regions 为空：老行为，一次性扫一批就结束
    if scan_cfg.regions.is_empty() {
        let ips = load_ips_excluding(&scan_cfg.mode, scan_cfg.max_ips, &HashSet::new())?;
        return scan_ips(ips, scan_cfg).await;
    }

    // regions 非空：分批扫描，直到凑够 target 个目标地区达标 IP
    let mut all_results: Vec<IpResult> = Vec::new();
    let mut scanned_ips: HashSet<IpAddr> = HashSet::new();

    for round in 1..=scan_cfg.max_scan_rounds {
        let remaining = target.saturating_sub(all_results.len());
        if remaining == 0 {
            break;
        }

        // 每批采样 batch_size 个新 IP（跳过之前已扫过的），不用刻意对齐 remaining，
        // 采样量足够时可以一次性凑够，采样量不够时多扫几轮
        let batch_ips = load_ips_excluding(&scan_cfg.mode, Some(scan_cfg.batch_size), &scanned_ips)?;

        if batch_ips.is_empty() {
            println!(
                "  地区过滤模式：候选池已耗尽（尝试第 {} 轮时采样不到新 IP），停止扫描",
                round
            );
            break;
        }

        if round > 1 {
            println!(
                "  地区过滤模式：目标 {} 个，已凑够 {} 个，补扫第 {} 轮（{} 个新 IP）",
                target, all_results.len(), round, batch_ips.len()
            );
        }

        for ip in &batch_ips {
            scanned_ips.insert(*ip);
        }

        let mut batch_results = if round == 1 {
            scan_ips(batch_ips, scan_cfg).await?
        } else {
            scan_ips_quiet(batch_ips, scan_cfg).await?
        };
        all_results.append(&mut batch_results);
    }

    if all_results.len() < target {
        println!(
            "  地区过滤模式：最终凑到 {} 个（目标 {}），候选池已耗尽或已达最大轮数 {}",
            all_results.len(), target, scan_cfg.max_scan_rounds
        );
    }

    // 多批结果合并后，整体按延迟重新排序（每批内部已经排过，合并后顺序会打乱）
    all_results.sort_by_key(|r| r.delay_ms);
    // 按 target 截断，避免因为最后一批"批量凑数"导致结果比目标多出一批的量
    all_results.truncate(target);

    Ok(all_results)
}

/// 完整流程：扫描延迟 → 测速 → DNS 同步
/// web_state: daemon 模式下传入，用于更新 Web 状态页；单次模式传 None
pub async fn run_full(config: &Config, web_state: Option<&WebState>) -> Result<()> {
    // 通知 Web：开始扫描
    if let Some(ws) = web_state {
        ws.set_scanning(true);
    }

    // 1&2. 加载 IP 并扫描延迟（regions 非空时会自动分批凑够 max_ips 个目标地区结果）
    let mut results = load_and_scan(config).await?;

    if results.is_empty() {
        println!("没有找到延迟达标的 IP，退出");
        if let Some(ws) = web_state {
            ws.set_results(vec![], vec!["没有找到延迟达标的 IP".to_string()]);
        }
        return Ok(());
    }

    // 3. 测速
    let mut dns_log: Vec<String> = vec![];

    if config.speed_test.auto_run {
        let regions_filter = if config.speed_test.mode == "region" {
            Some(config.speed_test.regions.as_slice())
        } else {
            None
        };

        print_speed_params(config, regions_filter);
        run_speed_tests(
            &mut results,
            &config.speed_test,
            regions_filter,
            config.dns.max_records,
        )
        .await?;

        let speed_results: Vec<_> = results
            .into_iter()
            .filter(|r| r.speed_mbps.is_some())
            .collect();

        print_speed_table(&speed_results);

        // 保存 state_file
        let state = ScanState::new(speed_results.clone());
        if let Err(e) = state.save(&config.output.state_file) {
            error!("保存状态文件失败: {}", e);
        }

        // 导出 CSV
        if let Some(csv_path) = &config.output.file {
            if let Err(e) = export_csv(&speed_results, csv_path) {
                error!("导出 CSV 失败: {}", e);
            }
        }

        // DNS 同步，收集日志
        if config.dns.enable {
            match dns::sync_dns_with_log(&speed_results, config).await {
                Ok(log) => dns_log = log,
                Err(e) => {
                    let msg = format!("DNS 同步失败: {:#}", e);
                    error!("{}", msg);
                    dns_log.push(msg);
                }
            }
        }

        // 通知 Web：完成，写入结果
        if let Some(ws) = web_state {
            ws.set_results(speed_results, dns_log);
        }
    } else {
        print_speed_table(&results);
        if let Some(ws) = web_state {
            ws.set_results(results, dns_log);
        }
    }

    Ok(())
}

/// 仅扫描延迟，不测速，不保存 state_file
pub async fn run_scan_only(config: &Config) -> Result<()> {
    let results = load_and_scan(config).await?;
    print_scan_summary(&results);
    Ok(())
}

/// 对上次测速结果重新测速（读 state_file）
pub async fn run_speed_only(
    config: &Config,
    regions_override: Option<Vec<String>>,
    all: bool,
) -> Result<()> {
    let mut state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到上次扫描结果，请先运行 scan 命令"))?;

    info!(
        "读取上次扫描结果（{}），共 {} 个 IP",
        state
            .scanned_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %Z"),
        state.results.len()
    );

    let (mode, regions) = if all {
        ("full".to_string(), vec![])
    } else if let Some(r) = regions_override {
        ("region".to_string(), r)
    } else {
        (
            config.speed_test.mode.clone(),
            config.speed_test.regions.clone(),
        )
    };

    let regions_filter = if mode == "region" && !regions.is_empty() {
        Some(regions.as_slice())
    } else {
        None
    };

    print_speed_params(config, regions_filter);
    run_speed_tests(
        &mut state.results,
        &config.speed_test,
        regions_filter,
        config.dns.max_records,
    )
    .await?;

    let speed_results: Vec<_> = state
        .results
        .into_iter()
        .filter(|r| r.speed_mbps.is_some())
        .collect();

    print_speed_table(&speed_results);

    let new_state = ScanState::new(speed_results.clone());
    new_state.save(&config.output.state_file)?;

    if let Some(csv_path) = &config.output.file {
        export_csv(&speed_results, csv_path)?;
    }

    if config.dns.enable {
        dns::sync_dns_with_log(&speed_results, config).await?;
    }

    Ok(())
}

/// 仅同步 DNS
pub async fn run_sync_only(config: &Config) -> Result<()> {
    let state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到测速结果，请先运行完整流程"))?;
    dns::sync_dns_with_log(&state.results, config).await?;
    Ok(())
}

/// 显示上次测速结果
pub fn run_show(config: &Config) -> Result<()> {
    let state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到测速结果，请先运行完整流程"))?;
    println!(
        "上次扫描时间: {}",
        state
            .scanned_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %Z")
    );
    print_speed_table(&state.results);
    Ok(())
}
