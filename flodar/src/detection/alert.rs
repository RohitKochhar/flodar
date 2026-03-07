use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    pub target_ip: Option<Ipv4Addr>,
    pub window_secs: u64,
    pub indicators: Vec<String>,
    #[allow(dead_code)]
    pub triggered_at: std::time::SystemTime,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub fn log_alert(alert: &Alert) {
    let indicators = alert.indicators.join(" | ");
    tracing::warn!(
        rule        = %alert.rule,
        severity    = ?alert.severity,
        target_ip   = ?alert.target_ip,
        window_secs = alert.window_secs,
        indicators  = %indicators,
        "ALERT"
    );
}
