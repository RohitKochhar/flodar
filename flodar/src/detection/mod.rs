pub mod alert;
pub mod rules;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use alert::log_alert;
use rules::{destination_hotspot, port_scan, syn_flood, udp_flood};

pub use rules::destination_hotspot::DestinationHotspotConfig;
pub use rules::port_scan::PortScanConfig;
pub use rules::syn_flood::SynFloodConfig;
pub use rules::udp_flood::UdpFloodConfig;

use crate::analytics::metrics::WindowMetrics;
use crate::api::{FlodarMetrics, SharedState};

#[derive(Debug, serde::Deserialize)]
pub struct DetectionConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default)]
    pub udp_flood: UdpFloodConfig,
    #[serde(default)]
    pub syn_flood: SynFloodConfig,
    #[serde(default)]
    pub port_scan: PortScanConfig,
    #[serde(default)]
    pub destination_hotspot: DestinationHotspotConfig,
}

fn default_enabled() -> bool {
    true
}
fn default_cooldown_secs() -> u64 {
    60
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            cooldown_secs: default_cooldown_secs(),
            udp_flood: UdpFloodConfig::default(),
            syn_flood: SynFloodConfig::default(),
            port_scan: PortScanConfig::default(),
            destination_hotspot: DestinationHotspotConfig::default(),
        }
    }
}

pub async fn run(
    mut rx: tokio::sync::broadcast::Receiver<WindowMetrics>,
    config: DetectionConfig,
    shared_state: SharedState,
    prom_metrics: Arc<FlodarMetrics>,
) {
    if !config.enabled {
        tracing::info!("detection engine disabled");
        return;
    }

    let mut cooldowns: HashMap<(String, Option<Ipv4Addr>), Instant> = HashMap::new();
    let cooldown_duration = std::time::Duration::from_secs(config.cooldown_secs);

    loop {
        match rx.recv().await {
            Ok(metrics) => {
                let mut candidates = Vec::new();

                match metrics.window_secs {
                    10 => {
                        if config.udp_flood.enabled {
                            if let Some(a) = udp_flood::evaluate(&metrics, &config.udp_flood) {
                                candidates.push(a);
                            }
                        }
                        if config.syn_flood.enabled {
                            if let Some(a) = syn_flood::evaluate(&metrics, &config.syn_flood) {
                                candidates.push(a);
                            }
                        }
                        if config.destination_hotspot.enabled {
                            if let Some(a) =
                                destination_hotspot::evaluate(&metrics, &config.destination_hotspot)
                            {
                                candidates.push(a);
                            }
                        }
                    }
                    60 => {
                        if config.port_scan.enabled {
                            if let Some(a) = port_scan::evaluate(&metrics, &config.port_scan) {
                                candidates.push(a);
                            }
                        }
                    }
                    _ => {}
                }

                let now = Instant::now();
                for alert in candidates {
                    let key = (alert.rule.clone(), alert.target_ip);
                    let suppressed = cooldowns
                        .get(&key)
                        .map(|last| now.duration_since(*last) < cooldown_duration)
                        .unwrap_or(false);

                    if !suppressed {
                        log_alert(&alert);
                        prom_metrics
                            .alerts_total
                            .with_label_values(&[&alert.rule])
                            .inc();

                        let mut state = shared_state.write().await;
                        if state.recent_alerts.len() >= 100 {
                            state.recent_alerts.pop_front();
                        }
                        state.recent_alerts.push_back(alert.clone());
                        drop(state);

                        cooldowns.insert(key, now);
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(dropped = n, "detection receiver lagged, snapshots dropped");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                tracing::info!("detection channel closed, shutting down");
                break;
            }
        }
    }
}
