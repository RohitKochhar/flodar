use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use super::metrics::FlodarMetrics;
use super::state::SharedState;
use crate::storage::{SharedAlertStore, SharedFlowStore};

#[derive(Clone)]
pub struct ApiState {
    pub shared: SharedState,
    pub registry: Arc<prometheus::Registry>,
    pub prom_metrics: Arc<FlodarMetrics>,
    pub alert_store: SharedAlertStore,
    pub flow_store: SharedFlowStore,
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
        "version": "0.7.0",
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
    ip: Option<String>,
    rule: Option<String>,
}

pub async fn alerts(
    State(state): State<ApiState>,
    Query(params): Query<AlertsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100);

    // When an alert store is available, read from persistent storage.
    if let Some(ref store) = state.alert_store {
        let result = if let Some(ref rule) = params.rule {
            store.query_by_rule(rule, limit).await
        } else if let Some(ref ip_str) = params.ip {
            match ip_str.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => store.query_by_ip(ip, limit).await,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid IP address"})),
                    )
                        .into_response();
                }
            }
        } else {
            store.query_recent(limit).await
        };

        match result {
            Ok(alerts) => {
                let total = alerts.len();
                let items: Vec<_> = alerts.iter().map(alert_to_json).collect();
                return Json(serde_json::json!({ "total": total, "alerts": items }))
                    .into_response();
            }
            Err(e) => {
                tracing::warn!(error = %e, "alert store query failed, falling back to in-memory");
            }
        }
    }

    // Fall back to in-memory ring buffer when no store is configured.
    let shared = state.shared.read().await;
    let total = shared.recent_alerts.len();
    let alerts: Vec<_> = shared
        .recent_alerts
        .iter()
        .rev()
        .take(limit)
        .map(alert_to_json)
        .collect();

    Json(serde_json::json!({
        "total": total,
        "alerts": alerts,
    }))
    .into_response()
}

fn alert_to_json(a: &crate::detection::alert::Alert) -> serde_json::Value {
    serde_json::json!({
        "id": a.id,
        "rule": a.rule,
        "severity": a.severity.to_string(),
        "target_ip": a.target_ip.map(|ip| ip.to_string()),
        "window_secs": a.window_secs,
        "indicators": a.indicators,
        "triggered_at": a.triggered_at.to_rfc3339(),
    })
}

pub async fn alert_by_id(State(state): State<ApiState>, Path(id): Path<i64>) -> impl IntoResponse {
    let Some(ref store) = state.alert_store else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "alert storage is not enabled",
                "hint": "set [storage] enabled = true in flodar.toml"
            })),
        )
            .into_response();
    };

    match store.query_by_id(id).await {
        Ok(Some(alert)) => Json(alert_to_json(&alert)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("alert {id} not found") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct FlowsQuery {
    start: Option<String>,
    end: Option<String>,
    limit: Option<usize>,
}

pub async fn flows(State(state): State<ApiState>, Query(params): Query<FlowsQuery>) -> Response {
    let Some(ref store) = state.flow_store else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "flow storage is not enabled",
                "hint": "set [storage] enabled = true in flodar.toml"
            })),
        )
            .into_response();
    };

    let limit = params.limit.unwrap_or(100).min(1000);

    let end = match params.end {
        Some(ref s) => parse_timestamp(s).unwrap_or_else(SystemTime::now),
        None => SystemTime::now(),
    };
    let start = match params.start {
        Some(ref s) => parse_timestamp(s).unwrap_or_else(|| end - Duration::from_secs(3600)),
        None => end - Duration::from_secs(3600),
    };

    match store.query_range(start, end, limit).await {
        Ok(records) => {
            let total = records.len();
            let flows: Vec<_> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "src_ip": r.src_ip.to_string(),
                        "dst_ip": r.dst_ip.to_string(),
                        "src_port": r.src_port,
                        "dst_port": r.dst_port,
                        "protocol": r.protocol,
                        "packets": r.packets,
                        "bytes": r.bytes,
                        "received_at": format_system_time(r.received_at),
                    })
                })
                .collect();
            Json(serde_json::json!({ "total": total, "flows": flows })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn parse_timestamp(s: &str) -> Option<SystemTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(SystemTime::from)
}

fn format_system_time(t: SystemTime) -> String {
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
