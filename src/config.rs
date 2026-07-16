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

    /// 随机采样 IP 数量上限
    #[serde(default = "default_max_ips")]
    pub max_ips: Option<usize>,
}

/// 测速配置（新增 download_threads / speed_concurrency）
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

    /// 每个 IP 测速时的并发下载连接数（对应 p-box download_threads）
    /// 多条连接同时下载同一 IP，汇总吞吐量，避免单连接被限速
    #[serde(default = "default_download_threads")]
    pub download_threads: usize,

    /// 同时对几个 IP 并行测速（区别于单 IP 内的 download_threads）
    #[serde(default = "default_speed_concurrency")]
    pub speed_concurrency: usize,

    /// 每个连接请求的字节数（总下载量 = download_threads * download_bytes）
    #[serde(default = "default_download_bytes")]
    pub download_bytes: usize,

    /// 测速最长持续时间（ms），超时后停止读取并计算当前速度
    #[serde(default = "default_speed_duration")]
    pub duration_ms: u64,

    /// 测速 TLS 连接超时（ms）
    #[serde(default = "default_speed_timeout")]
    pub connect_timeout_ms: u64,

    /// 速度达标下限（MB/s）。低于此值的 IP 不计入"达标"结果，
    /// 会继续从候选池取下一批 IP 补测，直到凑够 dns.max_records 个达标 IP 或候选池耗尽。
    /// 不填或 <=0 表示不限制（测完 top_n 就结束，行为与之前一致）。
    #[serde(default)]
    pub min_speed_mbps: f64,

    /// 补测时最多再取几批（每批大小 = top_n）。
    /// 防止候选池里全是慢 IP 时无限测下去。
    #[serde(default = "default_max_batches")]
    pub max_batches: usize,
}


/// 定时调度配置
#[derive(Debug, Deserialize, Clone)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_cron")]
    pub cron: String,
}

/// Cloudflare DNS 同步配置
#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    #[serde(default)]
    pub enable: bool,
    pub token: Option<String>,
    pub zone_id: Option<String>,
    pub domain: Option<String>,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

/// 输出配置
#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    pub file: Option<String>,
    #[serde(default = "default_state_file")]
    pub state_file: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub web_show: bool,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
}

// ── 默认值 ──────────────────────────────────────────────────────────────────

fn default_auto_run()          -> bool         { true }
fn default_scan_mode()         -> String       { "ipv4".into() }
fn default_max_ips()           -> Option<usize>{ Some(8000) }
fn default_port()              -> u16          { 443 }
fn default_concurrency()       -> usize        { 100 }
fn default_delay_threshold()   -> u64          { 220 }
fn default_ping_count()        -> usize        { 2 }
fn default_tcp_timeout()       -> u64          { 1000 }
fn default_speed_mode()        -> String       { "full".into() }
fn default_top_n()             -> usize        { 10 }
fn default_download_threads()  -> usize        { 4 }   // 每个 IP 4 条并发连接
fn default_speed_concurrency() -> usize        { 3 }   // 同时测 3 个 IP
fn default_download_bytes()    -> usize        { 100 * 1024 * 1024 } // 每连接 100MB
fn default_speed_duration()    -> u64          { 8000 } // 8 秒
fn default_speed_timeout()     -> u64          { 5000 }
fn default_max_batches()       -> usize        { 3 }   // 最多再补测 3 批
fn default_cron()              -> String       { "0 */6 * * *".into() }
fn default_record_type()       -> String       { "A".into() }
fn default_max_records()       -> usize        { 5 }
fn default_ttl()               -> u32          { 60 }
fn default_web_port()          -> u16          { 5000 }
fn default_state_file()        -> String       { "/tmp/cfscanner_state.json".into() }
fn default_log_level()         -> String       { "info".into() }

// ── 加载 ─────────────────────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| "配置文件解析失败")?;
        config.validate()?;
        Ok(config)
    }

    pub fn default_config() -> Result<Self> {
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
        if self.speed_test.min_speed_mbps < 0.0 {
            anyhow::bail!("speed_test.min_speed_mbps 不能为负数");
        }
        if self.speed_test.max_batches == 0 {
            anyhow::bail!("speed_test.max_batches 必须 >= 1");
        }
        if self.dns.enable {
            if self.dns.token.is_none()   { anyhow::bail!("dns.enable=true 时必须提供 dns.token");   }
            if self.dns.zone_id.is_none() { anyhow::bail!("dns.enable=true 时必须提供 dns.zone_id"); }
            if self.dns.domain.is_none()  { anyhow::bail!("dns.enable=true 时必须提供 dns.domain");  }
        }
        Ok(())
    }

    pub fn dns_domain_for(&self, n: usize) -> Option<String> {
        let domain = self.dns.domain.as_ref()?;
        if self.dns.max_records == 1 {
            Some(domain.clone())
        } else {
            let mut parts: Vec<&str> = domain.splitn(2, '.').collect();
            if parts.len() == 2 {
                Some(format!("{}{}.{}", parts[0], n, parts[1]))
            } else {
                Some(format!("{}{}", domain, n))
            }
        }
    }
}
