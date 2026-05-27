use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// 顶层配置
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub scan: ScanConfig,
    pub speed_test: SpeedTestConfig,
    pub schedule: ScheduleConfig,
    pub dns: DnsConfig,
    pub output: OutputConfig,
}

/// 扫描配置
#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    /// ipv4 / ipv6 / both
    #[serde(default = "default_scan_mode")]
    pub mode: String,

    /// TCP 连接端口
    #[serde(default = "default_port")]
    pub port: u16,

    /// 并发数
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// 延迟上限（ms），超过则丢弃
    #[serde(default = "default_delay_threshold")]
    pub delay_threshold: u64,

    /// 每个 IP TCP ping 几次，取最小值
    #[serde(default = "default_ping_count")]
    pub ping_count: usize,

    /// TCP ping 连接超时（ms）
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_ms: u64,

    /// 随机采样 IP 数量上限，不配置默认 5500
    #[serde(default = "default_max_ips")]
    pub max_ips: Option<usize>,
}

/// 测速配置
#[derive(Debug, Deserialize, Clone)]
pub struct SpeedTestConfig {
    /// 扫描完成后是否自动测速
    #[serde(default = "default_auto_run")]
    pub auto_run: bool,

    /// region（按地区）/ full（全部）
    #[serde(default = "default_speed_mode")]
    pub mode: String,

    /// mode=region 时生效，如 ["LAX", "HKG"]
    #[serde(default)]
    pub regions: Vec<String>,

    /// 只测延迟最低的前 N 个 IP
    #[serde(default = "default_top_n")]
    pub top_n: usize,

    /// 测速下载字节数
    #[serde(default = "default_download_bytes")]
    pub download_bytes: usize,

    /// 测速最长持续时间（ms）
    #[serde(default = "default_speed_duration")]
    pub duration_ms: u64,

    /// 测速 TLS 连接超时（ms）
    #[serde(default = "default_speed_timeout")]
    pub connect_timeout_ms: u64,
}

/// 定时调度配置
#[derive(Debug, Deserialize, Clone)]
pub struct ScheduleConfig {
    /// 是否启用定时任务
    #[serde(default)]
    pub enable: bool,

    /// cron 表达式，如 "0 */6 * * *"（每6小时）
    #[serde(default = "default_cron")]
    pub cron: String,
}

/// Cloudflare DNS 同步配置
#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    /// 是否启用 DNS 同步
    #[serde(default)]
    pub enable: bool,

    /// CF API Token
    pub token: Option<String>,

    /// Zone ID
    pub zone_id: Option<String>,

    /// 域名模板，如 "cf.example.com"
    /// max_records=1 时直接用该域名
    /// max_records>1 时生成 cf1.example.com, cf2.example.com ...
    pub domain: Option<String>,

    /// A（IPv4）/ AAAA（IPv6）
    #[serde(default = "default_record_type")]
    pub record_type: String,

    /// 同步前 N 个最优 IP
    #[serde(default = "default_max_records")]
    pub max_records: usize,

    /// DNS TTL（秒）
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

/// 输出配置
#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    /// 结果 CSV 文件路径，None 则不写文件
    pub file: Option<String>,

    /// 状态文件路径（持久化扫描结果）
    #[serde(default = "default_state_file")]
    pub state_file: String,

    /// 日志级别：trace / debug / info / warn / error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 是否开启 Web 状态页（仅 daemon 模式生效）
    #[serde(default)]
    pub web_show: bool,

    /// Web 状态页监听端口（默认 5000）
    #[serde(default = "default_web_port")]
    pub web_port: u16,
}

// ── 默认值函数 ──────────────────────────────────────────────────

fn default_auto_run() -> bool {
    true
}
fn default_scan_mode() -> String {
    "ipv4".into()
}
fn default_max_ips() -> Option<usize> {
    Some(8000)
}
fn default_port() -> u16 {
    443
}
fn default_concurrency() -> usize {
    100
}
fn default_delay_threshold() -> u64 {
    220
}
fn default_ping_count() -> usize {
    2
}
fn default_tcp_timeout() -> u64 {
    1000
}
fn default_speed_mode() -> String {
    "full".into()
}
fn default_top_n() -> usize {
    10
}
fn default_download_bytes() -> usize {
    10 * 1024 * 1024
} // 10 MB
fn default_speed_duration() -> u64 {
    3000
}
fn default_speed_timeout() -> u64 {
    3000
}
fn default_cron() -> String {
    "0 */6 * * *".into()
}
fn default_record_type() -> String {
    "A".into()
}
fn default_max_records() -> usize {
    5
}
fn default_ttl() -> u32 {
    60
}
fn default_web_port() -> u16 {
    5000
}
fn default_state_file() -> String {
    "/tmp/cfscanner_state.json".into()
}
fn default_log_level() -> String {
    "info".into()
}

// ── 加载函数 ────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let config: Config = toml::from_str(&content).with_context(|| "配置文件解析失败")?;
        config.validate()?;
        Ok(config)
    }

    /// 不依赖配置文件，全部使用内置默认值运行一次
    pub fn default_config() -> Result<Self> {
        // 用最小合法 TOML 触发所有 serde default
        let minimal = "[scan]\n[speed_test]\n[schedule]\n[dns]\n[output]\n";
        let config: Config = toml::from_str(minimal).context("内置默认配置解析失败")?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let valid_modes = ["ipv4", "ipv6", "both"];
        if !valid_modes.contains(&self.scan.mode.as_str()) {
            anyhow::bail!(
                "scan.mode 必须是 ipv4 / ipv6 / both，当前: {}",
                self.scan.mode
            );
        }

        let valid_speed_modes = ["region", "full"];
        if !valid_speed_modes.contains(&self.speed_test.mode.as_str()) {
            anyhow::bail!(
                "speed_test.mode 必须是 region / full，当前: {}",
                self.speed_test.mode
            );
        }

        if self.speed_test.mode == "region" && self.speed_test.regions.is_empty() {
            anyhow::bail!("speed_test.mode=region 时，speed_test.regions 不能为空");
        }

        if self.dns.enable {
            if self.dns.token.is_none() {
                anyhow::bail!("dns.enable=true 时必须提供 dns.token");
            }
            if self.dns.zone_id.is_none() {
                anyhow::bail!("dns.enable=true 时必须提供 dns.zone_id");
            }
            if self.dns.domain.is_none() {
                anyhow::bail!("dns.enable=true 时必须提供 dns.domain");
            }
        }

        Ok(())
    }

    /// 根据模板域名和编号生成子域名
    /// max_records=1 → "cf.example.com"
    /// max_records=5, n=1 → "cf1.example.com"
    pub fn dns_domain_for(&self, n: usize) -> Option<String> {
        let domain = self.dns.domain.as_ref()?;
        if self.dns.max_records == 1 {
            Some(domain.clone())
        } else {
            // "cf.example.com" → "cf{n}.example.com"
            let mut parts: Vec<&str> = domain.splitn(2, '.').collect();
            if parts.len() == 2 {
                Some(format!("{}{}.{}", parts[0], n, parts[1]))
            } else {
                Some(format!("{}{}", domain, n))
            }
        }
    }
}
