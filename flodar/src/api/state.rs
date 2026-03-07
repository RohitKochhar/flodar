use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use crate::analytics::metrics::WindowMetrics;
use crate::detection::alert::Alert;

pub struct AppState {
    pub window_10s: Option<WindowMetrics>,
    pub window_60s: Option<WindowMetrics>,
    pub window_300s: Option<WindowMetrics>,
    pub recent_alerts: VecDeque<Alert>,
    pub total_flows: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    /// Maps exporter IP to the last time a record was received from it.
    pub exporter_last_seen: HashMap<IpAddr, Instant>,
    pub uptime_started: SystemTime,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            window_10s: None,
            window_60s: None,
            window_300s: None,
            recent_alerts: VecDeque::new(),
            total_flows: 0,
            total_packets: 0,
            total_bytes: 0,
            exporter_last_seen: HashMap::new(),
            uptime_started: SystemTime::now(),
        }
    }
}

pub type SharedState = std::sync::Arc<tokio::sync::RwLock<AppState>>;
