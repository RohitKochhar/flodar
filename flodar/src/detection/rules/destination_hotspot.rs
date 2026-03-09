use serde::Deserialize;

use crate::analytics::metrics::WindowMetrics;
use crate::detection::alert::{Alert, Severity};

#[derive(Debug, Deserialize)]
pub struct DestinationHotspotConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_traffic_ratio")]
    pub min_traffic_ratio: f64,
    #[serde(default = "default_min_bytes_per_sec")]
    pub min_bytes_per_sec: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_min_traffic_ratio() -> f64 {
    0.80
}
fn default_min_bytes_per_sec() -> f64 {
    100.0
}

impl Default for DestinationHotspotConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_traffic_ratio: default_min_traffic_ratio(),
            min_bytes_per_sec: default_min_bytes_per_sec(),
        }
    }
}

pub fn evaluate(metrics: &WindowMetrics, config: &DestinationHotspotConfig) -> Option<Alert> {
    if metrics.bytes == 0 || metrics.bytes_per_sec < config.min_bytes_per_sec {
        return None;
    }

    if let Some((top_dst, top_bytes)) = metrics.top_dst_ips.first() {
        let ratio = *top_bytes as f64 / metrics.bytes as f64;
        if ratio >= config.min_traffic_ratio {
            return Some(Alert {
                rule: "destination_hotspot".to_string(),
                severity: Severity::Medium,
                target_ip: Some(*top_dst),
                window_secs: metrics.window_secs,
                indicators: vec![
                    format!(
                        "destination {} received {:.0}% of total traffic in {}s window (threshold: {:.0}%)",
                        top_dst,
                        ratio * 100.0,
                        metrics.window_secs,
                        config.min_traffic_ratio * 100.0
                    ),
                    format!(
                        "traffic rate: {:.1} MB/sec",
                        metrics.bytes_per_sec / 1_000_000.0
                    ),
                ],
                triggered_at: chrono::Utc::now(),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn make_metrics(top_ratio: f64, bytes_per_sec: f64) -> WindowMetrics {
        let total_bytes = (bytes_per_sec * 10.0) as u64;
        let top_bytes = (total_bytes as f64 * top_ratio) as u64;
        let top_dst = Ipv4Addr::new(1, 1, 1, 1);

        WindowMetrics {
            window_secs: 10,
            flows: 10,
            packets: 10,
            bytes: total_bytes,
            flows_per_sec: 1.0,
            packets_per_sec: 1.0,
            bytes_per_sec,
            unique_src_ips: 5,
            unique_dst_ips: 2,
            top_src_ips: vec![],
            top_dst_ips: vec![
                (top_dst, top_bytes),
                (Ipv4Addr::new(2, 2, 2, 2), total_bytes - top_bytes),
            ],
            protocol_dist: HashMap::new(),
            tcp_flows: 10,
            syn_only_flows: 0,
            avg_flow_duration_ms: 0,
            src_dst_ports: HashMap::new(),
        }
    }

    #[test]
    fn fires_when_traffic_concentrated() {
        let m = make_metrics(0.90, 50_000.0);
        assert!(evaluate(&m, &DestinationHotspotConfig::default()).is_some());
    }

    #[test]
    fn no_fire_when_ratio_too_low() {
        let m = make_metrics(0.70, 50_000.0);
        assert!(evaluate(&m, &DestinationHotspotConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_rate_too_low() {
        let m = make_metrics(0.95, 50.0); // 50 bytes/sec below 100 threshold
        assert!(evaluate(&m, &DestinationHotspotConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_no_bytes() {
        let mut m = make_metrics(0.95, 50_000.0);
        m.bytes = 0;
        assert!(evaluate(&m, &DestinationHotspotConfig::default()).is_none());
    }

    #[test]
    fn alert_reports_target_ip() {
        let m = make_metrics(0.90, 50_000.0);
        let alert = evaluate(&m, &DestinationHotspotConfig::default()).unwrap();
        assert_eq!(alert.target_ip, Some(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn alert_has_at_least_two_indicators() {
        let m = make_metrics(0.90, 50_000.0);
        let alert = evaluate(&m, &DestinationHotspotConfig::default()).unwrap();
        assert!(alert.indicators.len() >= 2);
    }
}
