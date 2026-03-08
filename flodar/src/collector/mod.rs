// TODO(v1.0): no unwrap() in production paths
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::api::{FlodarMetrics, SharedState};
use crate::decoder::flow_record::FlowRecord;
use crate::decoder::template_cache::TemplateCache;

pub async fn run(
    bind_addr: SocketAddr,
    tx: tokio::sync::broadcast::Sender<FlowRecord>,
    shared_state: SharedState,
    prom_metrics: Arc<FlodarMetrics>,
    ipfix_addr: Option<SocketAddr>,
    accepted_versions: Vec<u16>,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    tracing::info!(address = %bind_addr, "collector listening");

    let ipfix_socket = if let Some(addr) = ipfix_addr {
        let s = tokio::net::UdpSocket::bind(addr).await?;
        tracing::info!(address = %addr, "ipfix collector listening");
        Some(s)
    } else {
        None
    };

    let mut buf = vec![0u8; 65535];
    let mut ipfix_buf = vec![0u8; 65535];
    let mut cache = TemplateCache::new();

    loop {
        let (len, peer) = if let Some(ref ipfix_socket) = ipfix_socket {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    let (len, peer) = result?;
                    handle_packet(
                        &buf[..len],
                        peer.ip(),
                        &accepted_versions,
                        &mut cache,
                        &tx,
                        &shared_state,
                        &prom_metrics,
                    ).await;
                    continue;
                }
                result = ipfix_socket.recv_from(&mut ipfix_buf) => {
                    let (len, peer) = result?;
                    handle_packet(
                        &ipfix_buf[..len],
                        peer.ip(),
                        &accepted_versions,
                        &mut cache,
                        &tx,
                        &shared_state,
                        &prom_metrics,
                    ).await;
                    continue;
                }
            }
        } else {
            let result = tokio::select! {
                result = socket.recv_from(&mut buf) => result?,
                _ = std::future::pending::<()>() => unreachable!(),
            };
            result
        };

        handle_packet(
            &buf[..len],
            peer.ip(),
            &accepted_versions,
            &mut cache,
            &tx,
            &shared_state,
            &prom_metrics,
        )
        .await;
    }
}

async fn handle_packet(
    data: &[u8],
    exporter_ip: std::net::IpAddr,
    accepted_versions: &[u16],
    cache: &mut TemplateCache,
    tx: &tokio::sync::broadcast::Sender<FlowRecord>,
    shared_state: &SharedState,
    prom_metrics: &Arc<FlodarMetrics>,
) {
    // Version filter
    if !accepted_versions.is_empty() {
        if data.len() < 2 {
            tracing::warn!(exporter = %exporter_ip, "packet too short to read version, dropping");
            return;
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        if !accepted_versions.contains(&version) {
            tracing::debug!(
                version,
                exporter = %exporter_ip,
                "dropping packet: version not in accepted_versions"
            );
            return;
        }
    }

    match crate::decoder::decode_packet(data, exporter_ip, cache) {
        Ok(records) => {
            for r in records {
                log_flow(&r);

                prom_metrics.flows_total.inc();
                prom_metrics.packets_total.inc_by(r.packets as f64);
                prom_metrics.bytes_total.inc_by(r.bytes as f64);

                {
                    let mut state = shared_state.write().await;
                    state.total_flows += 1;
                    state.total_packets += r.packets as u64;
                    state.total_bytes += r.bytes as u64;
                    state
                        .exporter_last_seen
                        .insert(r.exporter_ip, Instant::now());
                }

                let _ = tx.send(r);
            }
        }
        Err(e) => {
            tracing::warn!(exporter = %exporter_ip, error = %e, "decode error");
        }
    }
}

fn log_flow(r: &FlowRecord) {
    tracing::info!(
        src_ip = %r.src_ip,
        dst_ip = %r.dst_ip,
        src_port = r.src_port,
        dst_port = r.dst_port,
        protocol = r.protocol,
        packets = r.packets,
        bytes = r.bytes,
        start_time = r.start_time,
        end_time = r.end_time,
        tcp_flags = r.tcp_flags,
        exporter_ip = %r.exporter_ip,
        received_at = ?r.received_at,
        "flow"
    );
}
