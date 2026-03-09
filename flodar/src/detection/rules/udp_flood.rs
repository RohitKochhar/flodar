use serde::Deserialize;

use crate::analytics::metrics::WindowMetrics;
use crate::detection::alert::{Alert, Severity};

#[derive(Debug, Deserialize)]
pub struct UdpFloodConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_packets_per_sec")]
    pub min_packets_per_sec: f64,
    #[serde(default = "default_min_udp_ratio")]
    pub min_udp_ratio: f64,
    #[serde(default = "default_min_unique_sources")]
    pub min_unique_sources: usize,
}

fn default_enabled() -> bool {
    true
}
fn default_min_packets_per_sec() -> f64 {
    1000.0
}
fn default_min_udp_ratio() -> f64 {
    0.80
}
fn default_min_unique_sources() -> usize {
    10
}

impl Default for UdpFloodConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_packets_per_sec: default_min_packets_per_sec(),
            min_udp_ratio: default_min_udp_ratio(),
            min_unique_sources: default_min_unique_sources(),
        }
    }
}

pub fn evaluate(metrics: &WindowMetrics, config: &UdpFloodConfig) -> Option<Alert> {
    if metrics.flows == 0 {
        return None;
    }

    let udp_flows = *metrics.protocol_dist.get(&17).unwrap_or(&0);
    let udp_ratio = udp_flows as f64 / metrics.flows as f64;

    let pps_ok = metrics.packets_per_sec >= config.min_packets_per_sec;
    let ratio_ok = udp_ratio >= config.min_udp_ratio;
    let sources_ok = metrics.unique_src_ips >= config.min_unique_sources;

    if pps_ok && ratio_ok && sources_ok {
        let top_dsts = metrics
            .top_dst_ips
            .iter()
            .map(|(ip, bytes)| format!("{ip}({bytes}B)"))
            .collect::<Vec<_>>()
            .join(", ");
        Some(Alert {
            id: None,
            rule: "udp_flood".to_string(),
            severity: Severity::High,
            target_ip: None,
            window_secs: metrics.window_secs,
            indicators: vec![
                format!(
                    "packets/sec: {:.0} (threshold: {:.0})",
                    metrics.packets_per_sec, config.min_packets_per_sec
                ),
                format!(
                    "UDP ratio: {:.0}% of flows (threshold: {:.0}%)",
                    udp_ratio * 100.0,
                    config.min_udp_ratio * 100.0
                ),
                format!(
                    "unique source IPs: {} (threshold: {})",
                    metrics.unique_src_ips, config.min_unique_sources
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
            packets: 10000,
            bytes: 500000,
            flows_per_sec: 10.0,
            packets_per_sec: 1000.0,
            bytes_per_sec: 50000.0,
            unique_src_ips: 20,
            unique_dst_ips: 2,
            top_src_ips: vec![],
            top_dst_ips: vec![],
            protocol_dist: {
                let mut m = HashMap::new();
                m.insert(17u8, 90u64); // 90% UDP
                m.insert(6u8, 10u64);
                m
            },
            tcp_flows: 10,
            syn_only_flows: 0,
            avg_flow_duration_ms: 0,
            src_dst_ports: HashMap::new(),
        }
    }

    #[test]
    fn fires_when_all_conditions_met() {
        let m = base_metrics();
        let cfg = UdpFloodConfig::default();
        assert!(evaluate(&m, &cfg).is_some());
    }

    #[test]
    fn no_fire_when_pps_below_threshold() {
        let mut m = base_metrics();
        m.packets_per_sec = 999.0;
        assert!(evaluate(&m, &UdpFloodConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_udp_ratio_too_low() {
        let mut m = base_metrics();
        // Set UDP flows to 50% of total
        m.protocol_dist.insert(17, 50);
        assert!(evaluate(&m, &UdpFloodConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_too_few_sources() {
        let mut m = base_metrics();
        m.unique_src_ips = 5;
        assert!(evaluate(&m, &UdpFloodConfig::default()).is_none());
    }

    #[test]
    fn fires_at_exact_thresholds() {
        let mut m = base_metrics();
        m.packets_per_sec = 1000.0;
        m.unique_src_ips = 10;
        // 80% UDP
        m.flows = 100;
        m.protocol_dist.insert(17, 80);
        assert!(evaluate(&m, &UdpFloodConfig::default()).is_some());
    }

    #[test]
    fn alert_has_at_least_two_indicators() {
        let m = base_metrics();
        let alert = evaluate(&m, &UdpFloodConfig::default()).unwrap();
        assert!(alert.indicators.len() >= 2);
    }
}
