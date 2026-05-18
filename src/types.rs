use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 单个 IP 的扫描 + 测速结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpResult {
    pub ip: String,
    pub port: u16,
    /// TCP 最低延迟（ms）
    pub delay_ms: u64,
    /// Cloudflare 节点三字码，如 "HKG"
    pub colo: String,
    /// 下载速度（MB/s），None 表示未测速
    pub speed_mbps: Option<f64>,
}

impl IpResult {
    pub fn new(ip: String, port: u16, delay_ms: u64, colo: String) -> Self {
        Self { ip, port, delay_ms, colo, speed_mbps: None }
    }

    /// 用于表格显示的速度字符串
    pub fn speed_display(&self) -> String {
        match self.speed_mbps {
            Some(s) => format!("{:.2} MB/s", s),
            None => "-".into(),
        }
    }
}

/// 一次完整扫描的状态，序列化后存到 state_file
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanState {
    pub scanned_at: DateTime<Utc>,
    pub results: Vec<IpResult>,
}

impl ScanState {
    pub fn new(results: Vec<IpResult>) -> Self {
        Self { scanned_at: Utc::now(), results }
    }

    /// 保存到文件
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// 从文件加载
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let state = serde_json::from_str(&json)?;
        Ok(state)
    }
}
