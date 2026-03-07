mod metrics;
mod window;

use metrics::WindowMetrics;
use window::SlidingWindow;

use crate::decoder::flow_record::FlowRecord;

pub async fn run(
    mut rx: tokio::sync::broadcast::Receiver<FlowRecord>,
    snapshot_interval_secs: u64,
) {
    let mut windows = vec![
        SlidingWindow::new(10),
        SlidingWindow::new(60),
        SlidingWindow::new(300),
    ];

    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(snapshot_interval_secs));
    // Skip missed ticks rather than bursting on backlog
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(record) => {
                        for window in &mut windows {
                            window.push(record.clone());
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "analytics receiver lagged, records dropped");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("analytics channel closed, shutting down");
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                for window in &mut windows {
                    window.evict_expired();
                    let metrics = window.compute();
                    log_metrics(&metrics);
                }
            }
        }
    }
}

fn log_metrics(m: &WindowMetrics) {
    let top_src = m
        .top_src_ips
        .iter()
        .map(|(ip, b)| format!("{ip}={b}"))
        .collect::<Vec<_>>()
        .join(",");

    let top_dst = m
        .top_dst_ips
        .iter()
        .map(|(ip, b)| format!("{ip}={b}"))
        .collect::<Vec<_>>()
        .join(",");

    let proto_dist = m
        .protocol_dist
        .iter()
        .map(|(p, c)| format!("{p}={c}"))
        .collect::<Vec<_>>()
        .join(",");

    tracing::info!(
        window_secs     = m.window_secs,
        flows           = m.flows,
        packets         = m.packets,
        bytes           = m.bytes,
        flows_per_sec   = m.flows_per_sec,
        packets_per_sec = m.packets_per_sec,
        bytes_per_sec   = m.bytes_per_sec,
        unique_src_ips  = m.unique_src_ips,
        unique_dst_ips  = m.unique_dst_ips,
        top_src_ips     = %top_src,
        top_dst_ips     = %top_dst,
        protocol_dist   = %proto_dist,
        "window_metrics"
    );
}
