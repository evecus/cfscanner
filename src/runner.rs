use crate::config::Config;
use crate::dns;
use crate::ip_loader::load_ips;
use crate::output::{export_csv, print_scan_summary, print_speed_params, print_speed_table};
use crate::scanner::scan_ips;
use crate::speed_tester::run_speed_tests;
use crate::types::ScanState;
use crate::web::WebState;
use anyhow::Result;
use tracing::{error, info};

/// 完整流程：扫描延迟 → 测速 → DNS 同步
/// web_state: daemon 模式下传入，用于更新 Web 状态页；单次模式传 None
pub async fn run_full(config: &Config, web_state: Option<&WebState>) -> Result<()> {
    // 通知 Web：开始扫描
    if let Some(ws) = web_state {
        ws.set_scanning(true);
    }

    // 1. 加载 IP 列表
    let ips = load_ips(&config.scan.mode, config.scan.max_ips)?;

    // 2. 扫描延迟
    let mut results = scan_ips(ips, &config.scan).await?;

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
        run_speed_tests(&mut results, &config.speed_test, regions_filter).await?;

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
    let ips = load_ips(&config.scan.mode, config.scan.max_ips)?;
    let results = scan_ips(ips, &config.scan).await?;
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
    run_speed_tests(&mut state.results, &config.speed_test, regions_filter).await?;

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
