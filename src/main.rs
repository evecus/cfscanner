mod config;
mod dns;
mod ip_loader;
mod output;
mod runner;
mod scanner;
mod speed_tester;
mod types;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use std::path::PathBuf;
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
    /// 显示上次扫描/测速结果
    Show,
    /// 将上次结果同步到 Cloudflare DNS
    Sync,
    /// 常驻进程模式，按 cron 定时触发
    Daemon,
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

    let config = Config::load(&cli.config)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.output.log_level)),
        )
        .init();

    info!("配置文件加载成功: {}", cli.config.display());

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => runner::run_full(&config).await?,
        Commands::Daemon => run_daemon(config).await?,
        Commands::Scan => runner::run_scan_only(&config).await?,
        Commands::Speed { region, all } => runner::run_speed_only(&config, region, all).await?,
        Commands::Show => runner::run_show(&config)?,
        Commands::Sync => runner::run_sync_only(&config).await?,
        Commands::Init { .. } => unreachable!(),
    }

    Ok(())
}

/// 常驻进程：用 cron crate 解析表达式，tokio::time::sleep 等待下次触发
async fn run_daemon(config: Config) -> Result<()> {
    use cron::Schedule;
    use std::str::FromStr;

    if !config.schedule.enable {
        anyhow::bail!("schedule.enable = false，无法启动 daemon 模式");
    }

    let schedule = Schedule::from_str(&config.schedule.cron)
        .map_err(|e| anyhow::anyhow!("cron 表达式解析失败: {}", e))?;

    info!("Daemon 启动，cron: {}", config.schedule.cron);

    // 立即执行一次
    info!("首次立即执行...");
    if let Err(e) = runner::run_full(&config).await {
        tracing::error!("首次运行失败: {}", e);
    }

    loop {
        // 计算下次触发时间
        let now = chrono::Utc::now();
        let next = match schedule.upcoming(chrono::Utc).next() {
            Some(t) => t,
            None => {
                anyhow::bail!("cron 表达式没有下一次触发时间，退出");
            }
        };

        let wait = (next - now).to_std().unwrap_or(std::time::Duration::from_secs(1));
        info!(
            "下次执行时间: {}，等待 {:.0} 秒",
            next.format("%Y-%m-%d %H:%M:%S UTC"),
            wait.as_secs_f64()
        );

        // 等待，同时响应 Ctrl+C
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                info!("定时触发，开始执行");
                if let Err(e) = runner::run_full(&config).await {
                    tracing::error!("定时任务失败: {}", e);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("收到退出信号，daemon 停止");
                break;
            }
        }
    }

    Ok(())
}

fn write_example_config(path: &PathBuf) -> Result<()> {
    const EXAMPLE: &str = r#"# cfscanner 配置文件

[scan]
mode = "ipv4"           # ipv4 / ipv6 / both
port = 443
concurrency = 150
delay_threshold = 220   # ms，超过则丢弃
ping_count = 2
tcp_timeout_ms = 1000

[speed_test]
auto_run = true
mode = "region"         # region / full
regions = ["LAX", "HKG", "NRT"]
top_n = 10
download_bytes = 10485760
duration_ms = 3000
connect_timeout_ms = 3000

[schedule]
enable = true
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
log_level = "info"
"#;

    if path.exists() {
        anyhow::bail!("{} 已存在", path.display());
    }
    std::fs::write(path, EXAMPLE)?;
    println!("配置文件已生成: {}", path.display());
    Ok(())
}
