use std::net::Ipv4Addr;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub id: Option<i64>,
    pub rule: String,
    pub severity: Severity,
    pub target_ip: Option<Ipv4Addr>,
    pub window_secs: u64,
    pub indicators: Vec<String>,
    pub triggered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
        }
    }
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
