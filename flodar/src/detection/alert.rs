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

/// Render an alert as a structured block for human-readable (`--log-format pretty`) output.
/// This replaces the single tracing::warn! line so the terminal output matches what the
/// project website shows: a clear, scannable block with threshold context.
pub fn format_alert_pretty(alert: &Alert) -> String {
    let rule_display = alert.rule.replace('_', " ");
    let severity = format!("{}", alert.severity).to_uppercase();
    let sep = "━".repeat(40);

    let target_line = if let Some(ip) = alert.target_ip {
        format!("Target:  {ip}\n")
    } else {
        String::new()
    };

    let window_line = format!("Window:  {} seconds\n", alert.window_secs);

    let indicators = alert
        .indicators
        .iter()
        .map(|i| format!("  → {i}"))
        .collect::<Vec<_>>()
        .join("\n");

    let time = alert.triggered_at.format("%Y-%m-%d %H:%M:%S UTC");

    format!(
        "\n{sep}\nALERT  {rule_display}  [{severity}]\n{sep}\n{target_line}{window_line}\nIndicators:\n{indicators}\n\nTime:  {time}\n{sep}"
    )
}

pub fn log_alert(alert: &Alert, pretty: bool) {
    if pretty {
        // Bypass tracing formatting entirely so the block renders cleanly on the terminal.
        eprintln!("{}", format_alert_pretty(alert));
    } else {
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
}
