use serde::Deserialize;

use crate::analytics::metrics::WindowMetrics;
use crate::detection::alert::{Alert, Severity};

#[derive(Debug, Deserialize)]
pub struct PortScanConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_unique_dst_ports")]
    pub min_unique_dst_ports: usize,
    #[serde(default = "default_max_bytes_per_flow")]
    pub max_bytes_per_flow: f64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_enabled() -> bool {
    true
}
fn default_min_unique_dst_ports() -> usize {
    50
}
fn default_max_bytes_per_flow() -> f64 {
    100.0
}
fn default_window_secs() -> u64 {
    60
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_unique_dst_ports: default_min_unique_dst_ports(),
            max_bytes_per_flow: default_max_bytes_per_flow(),
            window_secs: default_window_secs(),
        }
    }
}

pub fn evaluate(metrics: &WindowMetrics, config: &PortScanConfig) -> Option<Alert> {
    if metrics.window_secs != config.window_secs || metrics.flows == 0 {
        return None;
    }

    let avg_bytes_per_flow = metrics.bytes as f64 / metrics.flows as f64;
    if avg_bytes_per_flow > config.max_bytes_per_flow {
        return None;
    }

    for (src_ip, dst_ports) in &metrics.src_dst_ports {
        if dst_ports.len() >= config.min_unique_dst_ports {
            return Some(Alert {
                rule: "port_scan".to_string(),
                severity: Severity::Medium,
                target_ip: Some(*src_ip),
                window_secs: metrics.window_secs,
                indicators: vec![
                    format!(
                        "source {} contacted {} unique destination ports in {}s (threshold: {})",
                        src_ip,
                        dst_ports.len(),
                        metrics.window_secs,
                        config.min_unique_dst_ports
                    ),
                    format!(
                        "average bytes per flow: {:.0} bytes (threshold: {:.0})",
                        avg_bytes_per_flow, config.max_bytes_per_flow
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
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;

    fn make_metrics(src: Ipv4Addr, num_ports: usize, bytes_per_flow: u64) -> WindowMetrics {
        let flows = num_ports as u64;
        let ports: HashSet<u16> = (1u16..=(num_ports as u16)).collect();
        let mut src_dst_ports = HashMap::new();
        src_dst_ports.insert(src, ports);

        WindowMetrics {
            window_secs: 60,
            flows,
            packets: flows,
            bytes: flows * bytes_per_flow,
            flows_per_sec: flows as f64 / 60.0,
            packets_per_sec: flows as f64 / 60.0,
            bytes_per_sec: (flows * bytes_per_flow) as f64 / 60.0,
            unique_src_ips: 1,
            unique_dst_ips: num_ports,
            top_src_ips: vec![],
            top_dst_ips: vec![],
            protocol_dist: HashMap::new(),
            tcp_flows: flows,
            syn_only_flows: 0,
            avg_flow_duration_ms: 0,
            src_dst_ports,
        }
    }

    #[test]
    fn fires_when_many_ports_small_flows() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let m = make_metrics(src, 100, 44);
        assert!(evaluate(&m, &PortScanConfig::default()).is_some());
    }

    #[test]
    fn no_fire_when_too_few_ports() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let m = make_metrics(src, 30, 44);
        assert!(evaluate(&m, &PortScanConfig::default()).is_none());
    }

    #[test]
    fn no_fire_when_bytes_too_large() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let m = make_metrics(src, 100, 200); // 200 bytes per flow > threshold
        assert!(evaluate(&m, &PortScanConfig::default()).is_none());
    }

    #[test]
    fn no_fire_on_wrong_window() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let mut m = make_metrics(src, 100, 44);
        m.window_secs = 10; // not the 60s window
        assert!(evaluate(&m, &PortScanConfig::default()).is_none());
    }

    #[test]
    fn alert_reports_correct_source_ip() {
        let src = Ipv4Addr::new(10, 0, 0, 99);
        let m = make_metrics(src, 100, 44);
        let alert = evaluate(&m, &PortScanConfig::default()).unwrap();
        assert_eq!(alert.target_ip, Some(src));
    }

    #[test]
    fn alert_has_at_least_two_indicators() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let m = make_metrics(src, 100, 44);
        let alert = evaluate(&m, &PortScanConfig::default()).unwrap();
        assert!(alert.indicators.len() >= 2);
    }
}
