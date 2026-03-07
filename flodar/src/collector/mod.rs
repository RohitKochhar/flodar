use crate::decoder::flow_record::FlowRecord;

pub async fn run(bind_addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    tracing::info!(address = %bind_addr, "collector listening");
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        match crate::decoder::netflow_v5::parse(&buf[..len], peer.ip()) {
            Ok(records) => {
                for r in records {
                    log_flow(&r);
                }
            }
            Err(e) => {
                tracing::warn!(exporter = %peer, error = %e, "decode error");
            }
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
