use serde::Deserialize;

use crate::analytics::metrics::WindowMetrics;
use crate::detection::alert::{Alert, Severity};

#[derive(Debug, Deserialize)]
pub struct SynFloodConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_packets_per_sec")]
    pub min_packets_per_sec: f64,
    #[serde(default = "default_min_syn_ratio")]
    pub min_syn_ratio: f64,
    #[serde(default = "default_max_avg_flow_duration_ms")]
    pub max_avg_flow_duration_ms: u32,
}

fn default_enabled() -> bool {
    true
}
fn default_min_packets_per_sec() -> f64 {
    500.0
}
fn default_min_syn_ratio() -> f64 {
    0.70
}
fn default_max_avg_flow_duration_ms() -> u32 {
    500
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_packets_per_sec: default_min_packets_per_sec(),
            min_syn_ratio: default_min_syn_ratio(),
            max_avg_flow_duration_ms: default_max_avg_flow_duration_ms(),
        }
    }
}

pub fn evaluate(metrics: &WindowMetrics, config: &SynFloodConfig) -> Option<Alert> {
    if metrics.tcp_flows == 0 {
        return None;
    }

    let syn_ratio = metrics.syn_only_flows as f64 / metrics.tcp_flows as f64;

    let pps_ok = metrics.packets_per_sec >= config.min_packets_per_sec;
    let ratio_ok = syn_ratio >= config.min_syn_ratio;
    let duration_ok = metrics.avg_flow_duration_ms <= config.max_avg_flow_duration_ms;

    if pps_ok && ratio_ok && duration_ok {
        let top_dsts = metrics
            .top_dst_ips
            .iter()
            .map(|(ip, bytes)| format!("{ip}({bytes}B)"))
            .collect::<Vec<_>>()
            .join(", ");
        Some(Alert {
            rule: "syn_flood".to_string(),
            severity: Severity::High,
            target_ip: None,
            window_secs: metrics.window_secs,
            indicators: vec![
                format!(
                    "packets/sec: {:.0} (threshold: {:.0})",
                    metrics.packets_per_sec, config.min_packets_per_sec
                ),
                format!(
                    "SYN-only ratio: {:.0}% of TCP flows (threshold: {:.0}%)",
                    syn_ratio * 100.0,
                    config.min_syn_ratio * 100.0
                ),
                format!(
                    "average flow duration: {}ms (threshold: {}ms)",
                    metrics.avg_flow_duration_ms, config.max_avg_flow_duration_ms
                ),
                format!("unique destination IPs: {}", metrics.unique_dst_ips),
                format!("top destination IPs: {}", top_dsts),
            ],
            triggered_at: chrono::Utc::now(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_metrics() -> WindowMetrics {
        WindowMetrics {
            window_secs: 10,
            flows: 100,
            packets: 5000,
            bytes: 200000,
            flows_per_sec: 10.0,
            packets_per_sec: 500.0,
            bytes_per_sec: 20000.0,
            unique_src_ips: 50,
            unique_dst_ips: 1,
            top_src_ips: vec![],
            top_dst_ips: vec![],
            protocol_dist: {
                let mut m = HashMap::new();
                m.insert(6u8, 100u64);
                m
            },
            tcp_flows: 100,
            syn_only_flows: 75, // 75% SYN-only
            avg_flow_duration_ms: 100,
            src_dst_ports: HashMap::new(),
        }
    }

    #[test]
    fn fires_when_all_conditions_met() {
        let m = base_metrics();
        assert!(evaluate(&m, &SynFloodConfig::default()).is_some());
    }

    #[test]
    fn no_fire_when_no_tcp_flows() {
        let mut m = base_metrics();
        m.tcp_flows = 0;
        assert!(evaluate(&m, &SynFloodConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_pps_too_low() {
        let mut m = base_metrics();
        m.packets_per_sec = 499.0;
        assert!(evaluate(&m, &SynFloodConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_syn_ratio_too_low() {
        let mut m = base_metrics();
        m.syn_only_flows = 60; // 60%, below 70% threshold
        assert!(evaluate(&m, &SynFloodConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_flow_duration_too_long() {
        let mut m = base_metrics();
        m.avg_flow_duration_ms = 501;
        assert!(evaluate(&m, &SynFloodConfig::default()).is_none());
    }

    #[test]
    fn alert_has_at_least_two_indicators() {
        let m = base_metrics();
        let alert = evaluate(&m, &SynFloodConfig::default()).unwrap();
        assert!(alert.indicators.len() >= 2);
    }
}
