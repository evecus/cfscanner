use crate::config::Config;
use crate::dns;
use crate::ip_loader::load_ips;
use crate::output::{export_csv, print_summary, print_table};
use crate::scanner::scan_ips;
use crate::speed_tester::run_speed_tests;
use crate::types::ScanState;
use anyhow::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{error, info};

/// 完整的一次运行：扫描 → 测速（如配置）→ DNS 同步
pub async fn run_full(config: &Config) -> Result<()> {
    info!("=== cfscanner 开始运行 ===");

    // 1. 加载 IP 列表
    info!("加载 IP 列表，模式: {}", config.scan.mode);
    let ips = load_ips(&config.scan.mode)?;
    info!("共加载 {} 个 IP", ips.len());

    // 2. 扫描延迟
    let done_count = Arc::new(AtomicUsize::new(0));
    let total = ips.len();
    let done_count_cb = done_count.clone();

    let mut results = scan_ips(ips, &config.scan, move |done, total, result| {
        done_count_cb.store(done, Ordering::Relaxed);
        if let Some(r) = result {
            // 实时打印命中的 IP
            println!(
                "[{}/{}] ✓ {} | {}ms | {}",
                done, total, r.ip, r.delay_ms, r.colo
            );
        }
    })
    .await?;

    print_summary(&results);

    // 3. 保存扫描状态
    let state = ScanState::new(results.clone());
    if let Err(e) = state.save(&config.output.state_file) {
        error!("保存状态文件失败: {}", e);
    } else {
        info!("扫描结果已保存至: {}", config.output.state_file);
    }

    // 4. 测速（如配置 auto_run）
    if config.speed_test.auto_run && !results.is_empty() {
        let regions_filter = if config.speed_test.mode == "region" {
            Some(config.speed_test.regions.as_slice())
        } else {
            None
        };
        run_speed_tests(&mut results, &config.speed_test, regions_filter).await?;

        // 更新状态文件（含速度）
        let state = ScanState::new(results.clone());
        if let Err(e) = state.save(&config.output.state_file) {
            error!("保存测速结果失败: {}", e);
        }
    }

    // 5. 打印结果表格
    print_table(&results);

    // 6. 导出 CSV
    if let Some(csv_path) = &config.output.file {
        if let Err(e) = export_csv(&results, csv_path) {
            error!("导出 CSV 失败: {}", e);
        }
    }

    // 7. DNS 同步
    if config.dns.enable {
        if let Err(e) = dns::sync_dns(&results, config).await {
            error!("DNS 同步失败: {}", e);
        }
    }

    info!("=== cfscanner 运行完成 ===");
    Ok(())
}

/// 仅测速（读取上次扫描结果）
pub async fn run_speed_only(
    config: &Config,
    regions_override: Option<Vec<String>>,
    all: bool,
) -> Result<()> {
    let mut state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到上次扫描结果，请先运行 scan 命令"))?;

    info!(
        "读取上次扫描结果（{}），共 {} 个 IP",
        state.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        state.results.len()
    );

    let (mode, regions) = if all {
        ("full".to_string(), vec![])
    } else if let Some(r) = regions_override {
        ("region".to_string(), r)
    } else {
        (config.speed_test.mode.clone(), config.speed_test.regions.clone())
    };

    let regions_filter = if mode == "region" && !regions.is_empty() {
        Some(regions.as_slice())
    } else {
        None
    };

    run_speed_tests(&mut state.results, &config.speed_test, regions_filter).await?;

    // 保存含测速结果
    state.save(&config.output.state_file)?;

    print_table(&state.results);

    if let Some(csv_path) = &config.output.file {
        export_csv(&state.results, csv_path)?;
    }

    if config.dns.enable {
        dns::sync_dns(&state.results, config).await?;
    }

    Ok(())
}

/// 仅扫描延迟，不测速
pub async fn run_scan_only(config: &Config) -> Result<()> {
    let ips = load_ips(&config.scan.mode)?;
    info!("共加载 {} 个 IP", ips.len());

    let total = ips.len();
    let mut results = scan_ips(ips, &config.scan, move |done, _total, result| {
        if let Some(r) = result {
            println!(
                "[{}/{}] ✓ {} | {}ms | {}",
                done, total, r.ip, r.delay_ms, r.colo
            );
        }
    })
    .await?;

    print_summary(&results);

    let state = ScanState::new(results);
    state.save(&config.output.state_file)?;
    info!("扫描结果已保存至: {}", config.output.state_file);

    Ok(())
}

/// 仅同步 DNS（读取上次结果）
pub async fn run_sync_only(config: &Config) -> Result<()> {
    let state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到上次扫描结果，请先运行 scan 命令"))?;

    dns::sync_dns(&state.results, config).await?;
    Ok(())
}

/// 显示上次扫描结果
pub fn run_show(config: &Config) -> Result<()> {
    let state = ScanState::load(&config.output.state_file)
        .map_err(|_| anyhow::anyhow!("找不到上次结果，请先运行 scan 命令"))?;

    println!(
        "上次扫描时间: {}",
        state.scanned_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    print_table(&state.results);
    Ok(())
}
