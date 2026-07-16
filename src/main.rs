mod config;
mod dns;
mod ip_loader;
mod output;
mod runner;
mod scanner;
mod speed_tester;
mod types;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use cron::Schedule;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "cfscanner",
    version = "0.1.0",
    about = "Cloudflare IP 延迟扫描 + 测速 + DNS 同步工具"
)]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 完整流程：扫描延迟 → 测速（按配置）→ DNS 同步
    Run,
    /// 仅扫描延迟
    Scan,
    /// 对上次扫描结果进行测速
    Speed {
        #[arg(long, value_delimiter = ',')]
        region: Option<Vec<String>>,
        #[arg(long, default_value_t = false)]
        all: bool,
    },
    /// 显示上次测速结果
    Show,
    /// 将上次结果同步到 Cloudflare DNS
    Sync,
    /// 生成示例配置文件
    Init {
        #[arg(default_value = "config.toml")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::Init { output }) = &cli.command {
        return write_example_config(output);
    }

    let config = if cli.config.exists() {
        Config::load(&cli.config)?
    } else if cli.config.to_string_lossy() == "config.toml" {
        // 未指定 -c 且默认路径不存在，使用内置默认值
        println!("未找到配置文件，使用内置默认参数运行...");
        Config::default_config()?
    } else {
        // 用户明确用 -c 指定了路径但文件不存在，报错
        Config::load(&cli.config)?
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.output.log_level)),
        )
        .without_time()
        .init();

    // ── 判断运行模式 ──────────────────────────────────────────────
    // 子命令优先；无子命令时根据 schedule 配置决定行为
    match cli.command {
        Some(Commands::Run) => {
            runner::run_full(&config, None).await?;
        }
        Some(Commands::Scan) => {
            runner::run_scan_only(&config).await?;
        }
        Some(Commands::Speed { region, all }) => {
            runner::run_speed_only(&config, region, all).await?;
        }
        Some(Commands::Show) => {
            runner::run_show(&config)?;
        }
        Some(Commands::Sync) => {
            runner::run_sync_only(&config).await?;
        }
        Some(Commands::Init { .. }) => unreachable!(),

        // 无子命令：根据 schedule 配置决定
        None => {
            if is_daemon_mode(&config) {
                run_daemon(config).await?;
            } else {
                runner::run_full(&config, None).await?;
            }
        }
    }

    Ok(())
}

/// 将用户输入的 cron 表达式统一为 6 段式（cron 库要求有秒字段）
/// 用户写 5 段（分 时 日 月 周）时，自动在最前面补 "0"（秒固定为 0）
fn normalize_cron(expr: &str) -> String {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() == 5 {
        format!("0 {}", expr)
    } else {
        expr.to_string()
    }
}

/// 判断是否应该进入 daemon 模式：
/// schedule.enable=true 且 cron 表达式能被正确解析
fn is_daemon_mode(config: &Config) -> bool {
    if !config.schedule.enable {
        return false;
    }
    let expr = normalize_cron(&config.schedule.cron);
    match Schedule::from_str(&expr) {
        Ok(_) => {
            info!("检测到有效的 cron 配置，进入 daemon 模式");
            true
        }
        Err(e) => {
            tracing::warn!(
                "cron 表达式 \"{}\" 解析失败（{}），退回单次执行模式",
                config.schedule.cron,
                e
            );
            false
        }
    }
}

/// Daemon 模式：
/// - 启动时不立即执行任务
/// - 按 cron 等待触发，执行完后继续等待
/// - web_show=true 时启动 HTTP 状态页
/// - 访问 /retest 可立即触发一次重测
/// - Ctrl+C / SIGTERM 优雅退出
async fn run_daemon(config: Config) -> Result<()> {
    let expr = normalize_cron(&config.schedule.cron);
    let schedule = Schedule::from_str(&expr)?;

    // 启动 Web 状态页
    let web_state = if config.output.web_show {
        let ws = web::WebState::new("3.0.0");
        web::start(config.output.web_port, ws.clone())
            .map_err(|e| anyhow::anyhow!("Web 服务启动失败 (0.0.0.0:{}): {}", config.output.web_port, e))?;
        Some(ws)
    } else {
        None
    };

    println!("━━━ daemon 模式启动 ━━━");
    if expr != config.schedule.cron {
        println!("cron : {}  （已自动补秒，实际: {}）", config.schedule.cron, expr);
    } else {
        println!("cron : {}", config.schedule.cron);
    }

    loop {
        let now_local = chrono::Local::now();
        let next = match schedule.upcoming(chrono::Local).next() {
            Some(t) => t,
            None => anyhow::bail!("cron 没有下一个触发时间，退出"),
        };
        let wait = (next - now_local)
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(1));

        println!(
            "下次执行: {}  (等待 {})",
            next.format("%Y-%m-%d %H:%M:%S %Z"),
            format_duration(wait)
        );

        // 每秒检查一次 retest 标志，同时等待 cron 触发或 Ctrl+C
        let triggered = tokio::select! {
            _ = wait_for_retest(web_state.as_ref()) => {
                println!("\n━━━ /retest 触发，立即执行 ━━━");
                true
            }
            _ = tokio::time::sleep(wait) => {
                println!("\n━━━ cron 触发，开始执行 ━━━");
                true
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n收到退出信号，daemon 停止");
                false
            }
        };

        if !triggered {
            break;
        }

        if let Err(e) = runner::run_full(&config, web_state.as_ref()).await {
            tracing::error!("执行失败: {:#}", e);
        }
    }

    Ok(())
}

/// 轮询 WebState 中的 retest 标志，每 500ms 检查一次
async fn wait_for_retest(ws: Option<&web::WebState>) -> () {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
        if let Some(w) = ws {
            if w.take_retest() {
                return;
            }
        } else {
            // 没有 web_state，永远不触发，让 select! 的其他分支处理
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
        }
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn write_example_config(path: &PathBuf) -> Result<()> {
    const EXAMPLE: &str = r#"# cfscanner 配置文件
#
# 启动行为：
#   schedule.enable=true 且 cron 合法 → daemon 模式（等 cron 触发，不立即执行）
#   否则 → 执行一次完整流程后退出

[scan]
mode = "ipv4"           # ipv4 / ipv6 / both
port = 443
concurrency = 150
delay_threshold = 220   # ms，超过则丢弃
ping_count = 2
tcp_timeout_ms = 1000
max_ips = 5000          # 随机采样上限，删除此行则全量扫描
# regions = ["LAX", "SJC"]   # 扫描阶段就按地区过滤，不填=不限制
                             # 一旦填了，max_ips 变成"目标数量"，会自动分批凑够
batch_size = 3000           # 仅 regions 非空时生效：每批采样量
max_scan_rounds = 10        # 仅 regions 非空时生效：最多补扫几轮

[speed_test]
auto_run = true
mode = "region"         # region / full
regions = ["LAX", "HKG", "NRT"]
top_n = 10
download_bytes = 10485760
duration_ms = 3000
connect_timeout_ms = 3000
min_speed_mbps = 2.0    # 低于此速度不算达标，会自动补测下一批；0=不限制
max_batches = 3         # 最多补测几批（含第一批）

[schedule]
enable = false          # true + 合法 cron → daemon 模式
cron = "0 */6 * * *"   # 每6小时

[dns]
enable = false
token = "your_cloudflare_api_token"
zone_id = "your_zone_id"
domain = "cf.example.com"
record_type = "A"
max_records = 5
ttl = 60

[output]
# file = "/var/log/cfscanner/results.csv"
state_file = "/tmp/cfscanner_state.json"
log_level = "warn"      # daemon 模式建议 warn，减少日志噪声
"#;

    if path.exists() {
        anyhow::bail!("{} 已存在", path.display());
    }
    std::fs::write(path, EXAMPLE)?;
    println!("配置文件已生成: {}", path.display());
    Ok(())
}
