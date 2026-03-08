//! Integration tests: exercise the full async pipeline end-to-end.
//!
//! Each test spins up real Tokio tasks (collector and/or detection) bound to
//! ephemeral loopback ports, sends crafted UDP packets, then asserts on the
//! shared application state.  No external processes are required.
//!
//! Layout:
//!   - Protocol decoding tests (v5 / v9 / IPFIX) — exercise collector → shared state
//!   - Prometheus metrics test                    — exercise instrumentation counters
//!   - Dual-socket test                           — exercise secondary IPFIX port
//!   - Version filter tests (v9 + IPFIX)          — exercise accepted_versions gate
//!   - Detection test                             — exercise detection engine in isolation
//!   - SIGTERM test (Unix only)                   — exercise graceful shutdown

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use flodar::analytics::metrics::WindowMetrics;
use flodar::api::{AppState, FlodarMetrics, SharedState};
use flodar::detection::{DetectionConfig, UdpFloodConfig};

// ── test infrastructure ────────────────────────────────────────────────────────

/// Bind to an OS-assigned loopback port, record the address, then release the
/// socket so the collector task can rebind to it.  The race window is negligible
/// on loopback; this is the standard Rust testing pattern for ephemeral ports.
async fn ephemeral_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Fresh SharedState + an isolated Prometheus registry/metrics pair.
/// Using a fresh registry per test avoids duplicate-metric registration panics
/// when tests run in parallel.
fn make_infra() -> (SharedState, Arc<FlodarMetrics>) {
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(FlodarMetrics::new(&registry).unwrap());
    let state: SharedState = Arc::new(tokio::sync::RwLock::new(AppState::default()));
    (state, metrics)
}

// ── packet builders ────────────────────────────────────────────────────────────
//
// These mirror the private helpers in the decoder unit tests exactly, so the
// same wire formats are validated end-to-end here.

/// Build a single NetFlow v5 record (48 bytes):
/// src 10.0.0.1 → dst 10.0.0.2, TCP port 1024→80, 100 pkts, 5 000 bytes.
fn nf5_record() -> Vec<u8> {
    let mut r = Vec::with_capacity(48);
    r.extend_from_slice(&[10, 0, 0, 1]); // src_ip
    r.extend_from_slice(&[10, 0, 0, 2]); // dst_ip
    r.extend_from_slice(&[0u8; 4]); // nexthop
    r.extend_from_slice(&0u16.to_be_bytes()); // input if
    r.extend_from_slice(&0u16.to_be_bytes()); // output if
    r.extend_from_slice(&100u32.to_be_bytes()); // packets
    r.extend_from_slice(&5000u32.to_be_bytes()); // bytes
    r.extend_from_slice(&0u32.to_be_bytes()); // first
    r.extend_from_slice(&1000u32.to_be_bytes()); // last
    r.extend_from_slice(&1024u16.to_be_bytes()); // src_port
    r.extend_from_slice(&80u16.to_be_bytes()); // dst_port
    r.push(0); // pad1
    r.push(0x10); // tcp_flags (ACK)
    r.push(6); // protocol (TCP)
    r.push(0); // tos
    r.extend_from_slice(&0u16.to_be_bytes()); // src_as
    r.extend_from_slice(&0u16.to_be_bytes()); // dst_as
    r.push(0); // src_mask
    r.push(0); // dst_mask
    r.extend_from_slice(&0u16.to_be_bytes()); // pad2
    r
}

/// Build a complete NetFlow v5 UDP payload containing `count` identical records.
fn nf5_packet(count: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&5u16.to_be_bytes()); // version
    pkt.extend_from_slice(&count.to_be_bytes()); // record count
    pkt.extend_from_slice(&100_000u32.to_be_bytes()); // sys_uptime
    pkt.extend_from_slice(&0u32.to_be_bytes()); // unix_secs
    pkt.extend_from_slice(&0u32.to_be_bytes()); // unix_nsecs
    pkt.extend_from_slice(&0u32.to_be_bytes()); // flow_seq
    pkt.push(0); // engine_type
    pkt.push(0); // engine_id
    pkt.extend_from_slice(&0u16.to_be_bytes()); // sampling_interval
    for _ in 0..count {
        pkt.extend_from_slice(&nf5_record());
    }
    pkt
}

// Standard 10-field template used by both the unit tests and flowgen.
// record_len = 4+4+2+2+1+4+4+4+4+1 = 30 bytes.
const FIELDS: &[(u16, u16)] = &[
    (8, 4),  // IPV4_SRC_ADDR
    (12, 4), // IPV4_DST_ADDR
    (7, 2),  // L4_SRC_PORT
    (11, 2), // L4_DST_PORT
    (4, 1),  // PROTOCOL
    (2, 4),  // IN_PKTS
    (1, 4),  // IN_BYTES
    (22, 4), // FIRST_SWITCHED
    (21, 4), // LAST_SWITCHED
    (6, 1),  // TCP_FLAGS
];

/// Data record bytes matching FIELDS (30 bytes).
fn flow_record_bytes() -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&[10, 0, 0, 1]); // src_ip
    r.extend_from_slice(&[10, 0, 0, 2]); // dst_ip
    r.extend_from_slice(&1024u16.to_be_bytes()); // src_port
    r.extend_from_slice(&80u16.to_be_bytes()); // dst_port
    r.push(6); // protocol (TCP)
    r.extend_from_slice(&100u32.to_be_bytes()); // packets
    r.extend_from_slice(&5000u32.to_be_bytes()); // bytes
    r.extend_from_slice(&1000u32.to_be_bytes()); // first_switched
    r.extend_from_slice(&2000u32.to_be_bytes()); // last_switched
    r.push(0x02); // tcp_flags (SYN)
    r
}

/// Build a NetFlow v9 UDP payload: template flowset (ID=0) + data flowset (ID=256).
fn nf9_packet() -> Vec<u8> {
    let field_count = FIELDS.len() as u16;
    let template_flowset_len = 4 + 4 + field_count as usize * 4; // hdr + tmpl hdr + fields

    let rec = flow_record_bytes();
    let padding = (4 - (4 + rec.len()) % 4) % 4;
    let data_flowset_len = 4 + rec.len() + padding;

    let mut pkt = Vec::new();
    // NF9 header (20 bytes)
    pkt.extend_from_slice(&9u16.to_be_bytes()); // version
    pkt.extend_from_slice(&2u16.to_be_bytes()); // count (2 flowsets)
    pkt.extend_from_slice(&100_000u32.to_be_bytes()); // sys_uptime
    pkt.extend_from_slice(&0u32.to_be_bytes()); // unix_secs
    pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence
    pkt.extend_from_slice(&0u32.to_be_bytes()); // source_id

    // Template flowset
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flowset_id = 0
    pkt.extend_from_slice(&(template_flowset_len as u16).to_be_bytes());
    pkt.extend_from_slice(&256u16.to_be_bytes()); // template_id
    pkt.extend_from_slice(&field_count.to_be_bytes());
    for (ftype, flen) in FIELDS {
        pkt.extend_from_slice(&ftype.to_be_bytes());
        pkt.extend_from_slice(&flen.to_be_bytes());
    }

    // Data flowset
    pkt.extend_from_slice(&256u16.to_be_bytes()); // flowset_id = template_id
    pkt.extend_from_slice(&(data_flowset_len as u16).to_be_bytes());
    pkt.extend_from_slice(&rec);
    pkt.extend(std::iter::repeat_n(0u8, padding));

    pkt
}

/// Build an IPFIX UDP payload: template set (ID=2) + data set (ID=256).
fn ipfix_packet() -> Vec<u8> {
    let field_count = FIELDS.len() as u16;
    let template_set_len = 4 + 4 + field_count as usize * 4; // set hdr + tmpl hdr + fields

    let rec = flow_record_bytes();
    let padding = (4 - (4 + rec.len()) % 4) % 4;
    let data_set_len = 4 + rec.len() + padding;

    let total_len = 16 + template_set_len + data_set_len;

    let mut pkt = Vec::new();
    // IPFIX header (16 bytes)
    pkt.extend_from_slice(&10u16.to_be_bytes()); // version = 10
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes()); // message length
    pkt.extend_from_slice(&0u32.to_be_bytes()); // export_time
    pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
    pkt.extend_from_slice(&0u32.to_be_bytes()); // observation_domain_id

    // Template set
    pkt.extend_from_slice(&2u16.to_be_bytes()); // set_id = 2
    pkt.extend_from_slice(&(template_set_len as u16).to_be_bytes());
    pkt.extend_from_slice(&256u16.to_be_bytes()); // template_id
    pkt.extend_from_slice(&field_count.to_be_bytes());
    for (ftype, flen) in FIELDS {
        pkt.extend_from_slice(&ftype.to_be_bytes());
        pkt.extend_from_slice(&flen.to_be_bytes());
    }

    // Data set
    pkt.extend_from_slice(&256u16.to_be_bytes()); // set_id = template_id
    pkt.extend_from_slice(&(data_set_len as u16).to_be_bytes());
    pkt.extend_from_slice(&rec);
    pkt.extend(std::iter::repeat_n(0u8, padding));

    pkt
}

/// A WindowMetrics snapshot that exceeds every UDP flood threshold used in the
/// detection test below.
fn udp_flood_metrics() -> WindowMetrics {
    WindowMetrics {
        window_secs: 10,
        flows: 100,
        packets: 10_000,
        bytes: 500_000,
        flows_per_sec: 10.0,
        packets_per_sec: 200.0, // well above the 1.0 threshold set in the test
        bytes_per_sec: 50_000.0,
        unique_src_ips: 5, // above the min_unique_sources = 1 threshold
        unique_dst_ips: 2,
        top_src_ips: vec![],
        top_dst_ips: vec![],
        protocol_dist: {
            let mut m = HashMap::new();
            m.insert(17u8, 90u64); // 90 / 100 = 90% UDP > 50% threshold
            m.insert(6u8, 10u64);
            m
        },
        tcp_flows: 10,
        syn_only_flows: 0,
        avg_flow_duration_ms: 0,
        src_dst_ports: HashMap::new(),
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

/// NetFlow v5: three records in one packet increment total_flows by three.
#[tokio::test]
async fn v5_flows_are_counted() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics, None, vec![]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await; // let the collector bind
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&nf5_packet(3), addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(
        flows, 3,
        "three v5 records should produce three flow entries"
    );
}

/// NetFlow v9: a datagram with a template flowset followed by a data flowset is
/// decoded and produces exactly one flow entry.
#[tokio::test]
async fn v9_flows_are_decoded() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics, None, vec![]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&nf9_packet(), addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(flows, 1, "one v9 data record should produce one flow entry");
}

/// IPFIX: a datagram with a template set followed by a data set is decoded and
/// produces exactly one flow entry.
#[tokio::test]
async fn ipfix_flows_are_decoded() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics, None, vec![]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&ipfix_packet(), addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(
        flows, 1,
        "one IPFIX data record should produce one flow entry"
    );
}

/// accepted_versions: when configured to accept only v5, a NetFlow v9 packet
/// must be silently dropped leaving the flow counter at zero.
#[tokio::test]
async fn accepted_versions_filter_drops_unlisted() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics, None, vec![5]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&nf9_packet(), addr).await.unwrap(); // v9 not in [5]
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(
        flows, 0,
        "v9 packet should be dropped when accepted_versions = [5]"
    );
}

/// Detection engine: injecting a WindowMetrics that satisfies all UDP flood
/// thresholds causes exactly one alert to be recorded in the shared state.
///
/// This test bypasses the collector and analytics stages and drives the detection
/// task directly via its broadcast channel, isolating the rule evaluation logic.
#[tokio::test]
async fn udp_flood_detection_fires_alert() {
    let (state, metrics) = make_infra();
    let (metrics_tx, metrics_rx) = tokio::sync::broadcast::channel(16);

    // Use minimal thresholds so the crafted WindowMetrics triggers immediately.
    let config = DetectionConfig {
        enabled: true,
        cooldown_secs: 0,
        udp_flood: UdpFloodConfig {
            enabled: true,
            min_packets_per_sec: 1.0,
            min_udp_ratio: 0.5,
            min_unique_sources: 1,
        },
        ..DetectionConfig::default()
    };

    let s = state.clone();
    let handle =
        tokio::spawn(async move { flodar::detection::run(metrics_rx, config, s, metrics).await });

    metrics_tx.send(udp_flood_metrics()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (alert_count, alert_rule) = {
        let guard = state.read().await;
        let count = guard.recent_alerts.len();
        let rule = guard
            .recent_alerts
            .front()
            .map(|a| a.rule.clone())
            .unwrap_or_default();
        (count, rule)
    };
    handle.abort();

    assert_eq!(alert_count, 1, "exactly one alert should have fired");
    assert_eq!(alert_rule, "udp_flood");
}

/// Prometheus counters (flows, packets, bytes) increment when flows are received.
/// This validates that the collector's instrumentation path is wired correctly,
/// independent of the shared-state assertions in the protocol decoding tests.
#[tokio::test]
async fn prometheus_metrics_increment() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    // Clone the Arc so we can inspect the counters after the collector runs.
    let metrics_for_collector = metrics.clone();
    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics_for_collector, None, vec![]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&nf5_packet(2), addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.abort();

    assert_eq!(
        metrics.flows_total.get(),
        2.0,
        "flows_total should equal record count"
    );
    assert!(
        metrics.packets_total.get() > 0.0,
        "packets_total should be non-zero"
    );
    assert!(
        metrics.bytes_total.get() > 0.0,
        "bytes_total should be non-zero"
    );
}

/// Dual-socket: when `ipfix_addr` is set, flows sent to the secondary IPFIX port
/// are decoded and counted alongside flows on the primary port.
#[tokio::test]
async fn dual_socket_ipfix_port() {
    let main_addr = ephemeral_addr().await;
    let ipfix_addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(main_addr, flow_tx, s, metrics, Some(ipfix_addr), vec![]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Send directly to the secondary IPFIX port, not the main collector port.
    sender.send_to(&ipfix_packet(), ipfix_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(
        flows, 1,
        "IPFIX flows on the secondary port should be decoded"
    );
}

/// accepted_versions: when configured to accept only v5, an IPFIX (v10) packet
/// must be silently dropped, leaving the flow counter at zero.
#[tokio::test]
async fn accepted_versions_filter_drops_ipfix() {
    let addr = ephemeral_addr().await;
    let (state, metrics) = make_infra();
    let (flow_tx, _rx) = tokio::sync::broadcast::channel(64);

    let s = state.clone();
    let handle = tokio::spawn(async move {
        flodar::collector::run(addr, flow_tx, s, metrics, None, vec![5]).await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&ipfix_packet(), addr).await.unwrap(); // v10 not in [5]
    tokio::time::sleep(Duration::from_millis(100)).await;

    let flows = state.read().await.total_flows;
    handle.abort();

    assert_eq!(
        flows, 0,
        "IPFIX packet should be dropped when accepted_versions = [5]"
    );
}

/// SIGTERM: the binary exits with code 0 when sent SIGTERM.
/// Uses `CARGO_BIN_EXE_flodar` so the test always runs against the binary that was
/// just compiled — no stale artifacts.
///
/// Readiness is detected by polling the HTTP API port rather than parsing log output,
/// which makes the test independent of log format and tracing configuration.
#[cfg(unix)]
#[tokio::test]
async fn sigterm_exits_cleanly() {
    use std::process::{Command, Stdio};

    // Acquire two free ports for the config file.
    let collector_port = ephemeral_addr().await.port();
    let api_port = ephemeral_addr().await.port();

    // Use the process ID in the filename so parallel test runs don't collide.
    let config_path =
        std::env::temp_dir().join(format!("flodar-sigterm-test-{}.toml", std::process::id()));
    std::fs::write(
        &config_path,
        format!("[collector]\nbind_port = {collector_port}\n\n[api]\nbind_port = {api_port}\n"),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_flodar");
    let mut child = Command::new(binary)
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn flodar binary");

    // Poll the HTTP API port until the server is accepting connections.
    // This is format-agnostic and confirms the process is fully initialised.
    let api_addr = format!("127.0.0.1:{api_port}");
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(&api_addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);

    assert!(ready, "flodar API port did not become reachable within 5 s");

    let pid = child.id();
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();

    let status = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || child.wait().unwrap()),
    )
    .await
    .expect("flodar did not exit within 5 s after SIGTERM")
    .unwrap();

    let _ = std::fs::remove_file(&config_path);

    assert!(
        status.success(),
        "expected exit code 0 after SIGTERM, got {:?}",
        status
    );
}
