use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use super::metrics::FlodarMetrics;
use super::state::SharedState;

#[derive(Clone)]
pub struct ApiState {
    pub shared: SharedState,
    pub registry: Arc<prometheus::Registry>,
    pub prom_metrics: Arc<FlodarMetrics>,
}

pub async fn health(State(state): State<ApiState>) -> impl IntoResponse {
    let shared = state.shared.read().await;
    let uptime_secs = shared
        .uptime_started
        .elapsed()
        .unwrap_or(Duration::ZERO)
        .as_secs();

    Json(serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
        "version": "0.4.0",
    }))
}

pub async fn metrics(State(state): State<ApiState>) -> Response {
    // Update gauges from current AppState before rendering.
    {
        let shared = state.shared.read().await;
        let five_min = Duration::from_secs(300);

        let active = shared
            .exporter_last_seen
            .values()
            .filter(|t| t.elapsed() < five_min)
            .count();
        state.prom_metrics.active_exporters.set(active as f64);

        for (window_label, maybe_metrics) in [
            ("10s", &shared.window_10s),
            ("60s", &shared.window_60s),
            ("300s", &shared.window_300s),
        ] {
            if let Some(m) = maybe_metrics {
                state
                    .prom_metrics
                    .flows_per_sec
                    .with_label_values(&[window_label])
                    .set(m.flows_per_sec);
                state
                    .prom_metrics
                    .packets_per_sec
                    .with_label_values(&[window_label])
                    .set(m.packets_per_sec);
                state
                    .prom_metrics
                    .bytes_per_sec
                    .with_label_values(&[window_label])
                    .set(m.bytes_per_sec);
                state
                    .prom_metrics
                    .unique_src_ips
                    .with_label_values(&[window_label])
                    .set(m.unique_src_ips as f64);
                state
                    .prom_metrics
                    .unique_dst_ips
                    .with_label_values(&[window_label])
                    .set(m.unique_dst_ips as f64);
            }
        }
    }

    let encoder = prometheus::TextEncoder::new();
    let metric_families = state.registry.gather();
    let body = encoder
        .encode_to_string(&metric_families)
        .unwrap_or_default();

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

pub async fn summary(State(state): State<ApiState>) -> Response {
    let shared = state.shared.read().await;

    let Some(ref m) = shared.window_10s else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "no data"})),
        )
            .into_response();
    };

    let active_exporters = shared
        .exporter_last_seen
        .values()
        .filter(|t| t.elapsed() < Duration::from_secs(300))
        .count();

    let uptime_secs = shared
        .uptime_started
        .elapsed()
        .unwrap_or(Duration::ZERO)
        .as_secs();

    Json(serde_json::json!({
        "window_secs": m.window_secs,
        "flows_per_sec": m.flows_per_sec,
        "packets_per_sec": m.packets_per_sec,
        "bytes_per_sec": m.bytes_per_sec,
        "unique_src_ips": m.unique_src_ips,
        "unique_dst_ips": m.unique_dst_ips,
        "active_exporters": active_exporters,
        "uptime_secs": uptime_secs,
    }))
    .into_response()
}

pub async fn top_talkers(State(state): State<ApiState>) -> Response {
    let shared = state.shared.read().await;

    let Some(ref m) = shared.window_60s else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "no data"})),
        )
            .into_response();
    };

    let window_secs = m.window_secs as f64;

    let top_sources: Vec<_> = m
        .top_src_ips
        .iter()
        .map(|(ip, bytes)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "bytes": bytes,
                "bytes_per_sec": *bytes as f64 / window_secs,
            })
        })
        .collect();

    let top_destinations: Vec<_> = m
        .top_dst_ips
        .iter()
        .map(|(ip, bytes)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "bytes": bytes,
                "bytes_per_sec": *bytes as f64 / window_secs,
            })
        })
        .collect();

    Json(serde_json::json!({
        "window_secs": m.window_secs,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct AlertsQuery {
    limit: Option<usize>,
}

pub async fn alerts(
    State(state): State<ApiState>,
    Query(params): Query<AlertsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100);
    let shared = state.shared.read().await;

    let total = shared.recent_alerts.len();
    let alerts: Vec<_> = shared
        .recent_alerts
        .iter()
        .rev()
        .take(limit)
        .map(|a| {
            serde_json::json!({
                "rule": a.rule,
                "severity": format!("{:?}", a.severity),
                "target_ip": a.target_ip.map(|ip| ip.to_string()),
                "window_secs": a.window_secs,
                "indicators": a.indicators,
                "triggered_at": format_system_time(a.triggered_at),
            })
        })
        .collect();

    Json(serde_json::json!({
        "total": total,
        "alerts": alerts,
    }))
}

fn format_system_time(t: std::time::SystemTime) -> String {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let s = d.as_secs();
            let sec = s % 60;
            let min = (s / 60) % 60;
            let hour = (s / 3600) % 24;
            let days = s / 86400;
            let (year, month, day) = epoch_days_to_ymd(days);
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                year, month, day, hour, min, sec
            )
        }
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
    }
}

/// Civil date from days since Unix epoch (Howard Hinnant's algorithm).
fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
