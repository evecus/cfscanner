/// 极简 HTTP 状态页
///
/// GET /          → 状态页（扫描中 / 上次结果）
/// GET /status    → 同上（图片里那个 JSON 端点）
/// GET /retest    → 触发立即重测（测试中则返回 scanning）
///
/// 仅在 daemon 模式 + web_show=true 时启动。
/// 用标准库 TcpListener 实现，零额外依赖。

use crate::types::{IpResult, ScanState};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use chrono::{DateTime, Local};

/// 全局共享状态
#[derive(Clone)]
pub struct WebState {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    scanning: bool,
    last_run: Option<SystemTime>,
    results: Vec<IpResult>,
    dns_log: Vec<String>,       // DNS 同步摘要行
    trigger_retest: bool,       // retest 请求标志
    version: String,
}

impl WebState {
    pub fn new(version: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                scanning: false,
                last_run: None,
                results: vec![],
                dns_log: vec![],
                trigger_retest: false,
                version: version.to_string(),
            })),
        }
    }

    pub fn set_scanning(&self, v: bool) {
        self.inner.lock().unwrap().scanning = v;
    }

    pub fn set_results(&self, results: Vec<IpResult>, dns_log: Vec<String>) {
        let mut g = self.inner.lock().unwrap();
        g.results = results;
        g.dns_log = dns_log;
        g.last_run = Some(SystemTime::now());
        g.scanning = false;
    }

    /// daemon 主循环调用：检查并消费 retest 标志
    pub fn take_retest(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.trigger_retest {
            g.trigger_retest = false;
            true
        } else {
            false
        }
    }
}

/// 在独立线程中启动 HTTP 服务
pub fn start(port: u16, state: WebState) {
    std::thread::spawn(move || {
        let addr = format!("0.0.0.0:{}", port);
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => {
                println!("Web 状态页已启动: http://{}", addr);
                l
            }
            Err(e) => {
                eprintln!("Web 服务启动失败 ({}): {}", addr, e);
                return;
            }
        };

        for stream in listener.incoming() {
            match stream {
                Ok(mut s) => {
                    let state = state.clone();
                    std::thread::spawn(move || {
                        let path = read_request_path(&s);
                        let resp = handle(&path, &state);
                        let _ = s.write_all(resp.as_bytes());
                    });
                }
                Err(_) => {}
            }
        }
    });
}

fn read_request_path(stream: &std::net::TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    let _ = reader.read_line(&mut first_line);
    // "GET /path HTTP/1.1"
    first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string()
}

fn handle(path: &str, state: &WebState) -> String {
    match path {
        "/retest" => handle_retest(state),
        "/status" | "/" => handle_status(state),
        _ => http_response(404, "text/plain", "Not Found"),
    }
}

fn handle_retest(state: &WebState) -> String {
    let scanning = state.inner.lock().unwrap().scanning;
    if scanning {
        // 正在扫描，拒绝重复触发
        let body = r#"{"status":"scanning","message":"scanning and speedtesting"}"#;
        http_response(200, "application/json", body)
    } else {
        state.inner.lock().unwrap().trigger_retest = true;
        let body = r#"{"status":"ok","message":"retest triggered"}"#;
        http_response(200, "application/json", body)
    }
}

fn handle_status(state: &WebState) -> String {
    let g = state.inner.lock().unwrap();

    // 格式化 last_run
    let last_run_str = g.last_run
        .map(|t| {
            let dt: DateTime<Local> = t.into();
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "never".to_string());

    if g.scanning {
        // 扫描中：返回简洁 JSON，网页显示 scanning and speedtesting
        let body = format!(
            r#"{{"last_run":"{}","status":"scanning","version":"{}"}}"#,
            last_run_str, g.version
        );
        return http_response(200, "application/json", &body);
    }

    if g.results.is_empty() {
        // 还没跑过
        let body = format!(
            r#"{{"last_run":"{}","status":"idle","version":"{}"}}"#,
            last_run_str, g.version
        );
        return http_response(200, "application/json", &body);
    }

    // 有结果：构建完整 JSON
    let results_json: Vec<String> = g.results.iter().enumerate().map(|(i, r)| {
        format!(
            r#"{{"rank":{},"ip":"{}","port":{},"delay_ms":{},"colo":"{}","speed_mbps":{}}}"#,
            i + 1,
            r.ip,
            r.port,
            r.delay_ms,
            r.colo,
            r.speed_mbps.map(|s| format!("{:.2}", s)).unwrap_or("null".to_string())
        )
    }).collect();

    let dns_json: Vec<String> = g.dns_log.iter()
        .map(|l| format!("\"{}\"", l.replace('"', "\\\"")))
        .collect();

    let body = format!(
        r#"{{"last_run":"{}","status":"idle","version":"{}","results":[{}],"dns_log":[{}]}}"#,
        last_run_str,
        g.version,
        results_json.join(","),
        dns_json.join(",")
    );

    http_response(200, "application/json", &body)
}

fn http_response(code: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        code,
        if code == 200 { "OK" } else { "Not Found" },
        content_type,
        body.len(),
        body
    )
}
