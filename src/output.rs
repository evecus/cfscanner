use crate::config::{Config, ScanConfig};
use crate::ip_loader::load_colo_map;
use crate::types::IpResult;
use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use std::collections::HashMap;

/// 扫描前打印参数
pub fn print_scan_params(cfg: &ScanConfig, total_ips: usize) {
    println!();
    println!("━━━ 延迟扫描参数 ━━━");
    println!("  模式        : {}", cfg.mode);
    println!("  端口        : {}", cfg.port);
    println!("  并发数      : {}", cfg.concurrency);
    println!("  延迟上限    : {} ms", cfg.delay_threshold);
    println!("  Ping 次数   : {}", cfg.ping_count);
    println!("  IP 总数     : {}", total_ips);
    println!();
}

/// 测速前打印参数
pub fn print_speed_params(config: &Config, regions_filter: Option<&[String]>) {
    let cfg = &config.speed_test;
    println!();
    println!("━━━ 测速参数 ━━━");
    println!("  模式        : {}", cfg.mode);
    if let Some(regions) = regions_filter {
        println!("  地区筛选    : {}", regions.join(", "));
    }
    println!("  测速数量    : top {}", cfg.top_n);
    println!("  下载量      : {} MB", cfg.download_bytes / 1024 / 1024);
    println!("  持续时长    : {} ms", cfg.duration_ms);
    println!();
    println!("  IP                  延迟     速度");
    println!("  {}", "─".repeat(42));
}

/// 扫描完成后的摘要（scan only 子命令用）
pub fn print_scan_summary(results: &[IpResult]) {
    if results.is_empty() {
        println!("延迟扫描：未找到可用 IP");
        return;
    }
    let mut by_colo: HashMap<&str, usize> = HashMap::new();
    for r in results {
        *by_colo.entry(r.colo.as_str()).or_insert(0) += 1;
    }
    let mut list: Vec<(&str, usize)> = by_colo.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1));

    println!("\n延迟扫描完成  共 {} 个可用 IP", results.len());
    for (colo, n) in &list {
        println!("  {:<6}  {} 个", colo, n);
    }
}

/// 测速结果表格（测速完成后展示）
pub fn print_speed_table(results: &[IpResult]) {
    println!();
    if results.is_empty() {
        println!("没有测速结果");
        return;
    }

    let colo_map = load_colo_map();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("IP 地址").add_attribute(Attribute::Bold),
            Cell::new("端口").add_attribute(Attribute::Bold),
            Cell::new("延迟(ms)").add_attribute(Attribute::Bold),
            Cell::new("节点").add_attribute(Attribute::Bold),
            Cell::new("城市").add_attribute(Attribute::Bold),
            Cell::new("速度").add_attribute(Attribute::Bold),
        ]);

    for (i, r) in results.iter().enumerate() {
        let city = colo_map
            .get(&r.colo)
            .cloned()
            .unwrap_or_else(|| r.colo.clone());

        let delay_cell = if r.delay_ms < 100 {
            Cell::new(r.delay_ms).fg(Color::Green)
        } else if r.delay_ms < 200 {
            Cell::new(r.delay_ms).fg(Color::Yellow)
        } else {
            Cell::new(r.delay_ms).fg(Color::Red)
        };

        let speed_cell = match r.speed_mbps {
            Some(s) if s >= 5.0 => Cell::new(format!("{:.2} MB/s", s)).fg(Color::Green),
            Some(s) if s >= 1.0 => Cell::new(format!("{:.2} MB/s", s)).fg(Color::Yellow),
            Some(s) => Cell::new(format!("{:.2} MB/s", s)).fg(Color::Red),
            None => Cell::new("-"),
        };

        table.add_row(vec![
            Cell::new(i + 1),
            Cell::new(&r.ip),
            Cell::new(r.port),
            delay_cell,
            Cell::new(&r.colo),
            Cell::new(&city),
            speed_cell,
        ]);
    }

    println!("{}", table);
}

/// 导出 CSV
pub fn export_csv(results: &[IpResult], path: &str) -> Result<()> {
    use std::fmt::Write as FmtWrite;
    let mut csv = String::new();
    writeln!(csv, "ip,port,delay_ms,colo,speed_mbps")?;
    for r in results {
        writeln!(
            csv,
            "{},{},{},{},{}",
            r.ip,
            r.port,
            r.delay_ms,
            r.colo,
            r.speed_mbps
                .map(|s| format!("{:.4}", s))
                .unwrap_or_default()
        )?;
    }
    std::fs::write(path, &csv)?;
    println!("结果已导出: {}", path);
    Ok(())
}
