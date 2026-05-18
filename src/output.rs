use crate::config::Config;
use crate::ip_loader::load_colo_map;
use crate::types::IpResult;
use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use std::collections::HashMap;

/// 打印结果表格到 stdout
pub fn print_table(results: &[IpResult]) {
    if results.is_empty() {
        println!("没有结果");
        return;
    }

    let colo_map = load_colo_map();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("IP").add_attribute(Attribute::Bold),
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

/// 打印扫描统计摘要
pub fn print_summary(results: &[IpResult]) {
    if results.is_empty() {
        println!("扫描结果为空");
        return;
    }

    let colo_map = load_colo_map();
    let mut colo_counts: HashMap<String, usize> = HashMap::new();
    for r in results {
        *colo_counts.entry(r.colo.clone()).or_insert(0) += 1;
    }

    println!("\n扫描完成！统计信息：");
    println!("可用 IP：{} 个", results.len());

    let mut colo_list: Vec<(String, usize)> = colo_counts.into_iter().collect();
    colo_list.sort_by(|a, b| b.1.cmp(&a.1));

    println!("地区统计（共 {} 个不同地区）：", colo_list.len());
    for (colo, count) in &colo_list {
        let city = colo_map.get(colo).cloned().unwrap_or_else(|| colo.clone());
        println!("  {} ({}): {}个IP", colo, city, count);
    }
}

/// 导出 CSV 文件
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
            r.speed_mbps.map(|s| format!("{:.4}", s)).unwrap_or_default()
        )?;
    }

    std::fs::write(path, &csv)?;
    println!("结果已导出到: {}", path);
    Ok(())
}
