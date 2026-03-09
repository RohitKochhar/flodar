use clap::Parser;
use std::net::UdpSocket;
use std::time::Duration;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum Mode {
    #[default]
    Normal,
    UdpFlood,
    SynFlood,
    PortScan,
    Hotspot,
    NetflowV9,
    Ipfix,
}

#[derive(Parser)]
#[command(name = "flowgen", version = "0.4.0")]
struct Args {
    /// Target address to send NetFlow v5 packets to
    #[arg(long, default_value = "127.0.0.1:2055")]
    target: String,

    /// POST a synthetic alert payload to this URL and print the HTTP response, then exit
    #[arg(long)]
    webhook_test: Option<String>,

    // --- Normal mode args ---
    /// Number of flows per batch (normal mode)
    #[arg(long, default_value_t = 5)]
    flows: u16,

    /// Number of times to send the packet batch (normal mode)
    #[arg(long, default_value_t = 1)]
    repeat: u32,

    /// Milliseconds to wait between sends (normal mode)
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,

    // --- Mode selection ---
    /// Attack simulation mode
    #[arg(long, default_value = "normal")]
    mode: Mode,

    // --- Shared attack args ---
    /// Target packets-per-second for the flodar metrics (udp-flood, syn-flood)
    #[arg(long, default_value_t = 1000)]
    pps: u64,

    /// How long to run the attack simulation in seconds
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,

    // --- Port scan args ---
    /// Fixed source IP for port scan mode
    #[arg(long, default_value = "10.0.0.99")]
    src_ip: String,

    /// Number of unique destination ports to scan
    #[arg(long, default_value_t = 200)]
    ports: u16,

    // --- Hotspot args ---
    /// Destination IP that should receive most traffic (hotspot mode)
    #[arg(long, default_value = "1.1.1.1")]
    dst_ip: String,

    /// Fraction of traffic to concentrate on dst-ip (0.0–1.0)
    #[arg(long, default_value_t = 0.95)]
    ratio: f64,
}

fn main() {
    let args = Args::parse();

    // --webhook-test: POST a synthetic alert payload and exit.
    if let Some(ref url) = args.webhook_test {
        run_webhook_test(url);
        return;
    }

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

    match args.mode {
        Mode::Normal => run_normal(&socket, &args),
        Mode::UdpFlood => run_udp_flood(&socket, &args),
        Mode::SynFlood => run_syn_flood(&socket, &args),
        Mode::PortScan => run_port_scan(&socket, &args),
        Mode::Hotspot => run_hotspot(&socket, &args),
        Mode::NetflowV9 => run_netflow_v9(&socket, &args),
        Mode::Ipfix => run_ipfix(&socket, &args),
    }
}

// --- Webhook test ---

fn run_webhook_test(url: &str) {
    let payload = serde_json::json!({
        "rule": "udp_flood",
        "severity": "High",
        "target_ip": null,
        "window_secs": 10,
        "indicators": [
            "packets/sec: 3400 (threshold: 1000)",
            "UDP ratio: 92% of flows (threshold: 80%)",
            "unique source IPs: 3400 (threshold: 10)"
        ],
        "triggered_at": chrono::Utc::now().to_rfc3339(),
    });

    println!("flowgen: posting synthetic alert to {url}");

    let client = reqwest::blocking::Client::new();
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_secs(10))
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            println!("flowgen: HTTP {status}");
            if !body.is_empty() {
                println!("flowgen: response body: {body}");
            }
            if status.is_success() {
                println!("flowgen: webhook test succeeded");
            } else {
                eprintln!("flowgen: webhook test failed — non-2xx status");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("flowgen: webhook test error: {e}");
            std::process::exit(1);
        }
    }
}

// --- Normal mode (unchanged behavior) ---

fn run_normal(socket: &UdpSocket, args: &Args) {
    const MAX_PER_PACKET: u16 = 30;
    let mut total_sent = 0u64;

    for iteration in 0..args.repeat {
        let mut remaining = args.flows;
        let mut sequence: u32 = iteration * (args.flows as u32 / MAX_PER_PACKET as u32 + 1) + 1;

        while remaining > 0 {
            let count = remaining.min(MAX_PER_PACKET);
            let offset = args.flows - remaining;
            let packet = build_packet(count, sequence, offset, FlowParams::default());
            socket.send_to(&packet, &args.target).expect("send failed");
            remaining -= count;
            sequence += 1;
        }

        total_sent += args.flows as u64;
        println!(
            "flowgen: [{}/{}] sent {} flow(s) to {}",
            iteration + 1,
            args.repeat,
            args.flows,
            args.target
        );

        if iteration + 1 < args.repeat {
            std::thread::sleep(Duration::from_millis(args.interval_ms));
        }
    }

    println!("flowgen: done — {} total flow(s) sent", total_sent);
}

// --- UDP flood ---
// Generates high-rate UDP flows from many source IPs.
// Each flow has packets=1 so flodar's packets_per_sec ≈ flows sent per second.

fn run_udp_flood(socket: &UdpSocket, args: &Args) {
    let batch_interval = Duration::from_millis(100);
    // flows per 100ms batch to hit target pps (each flow = 1 packet)
    let flows_per_batch = (args.pps / 10).max(1) as u16;
    let total_batches = args.duration_secs * 10;
    let mut sequence: u32 = 1;

    println!(
        "flowgen: udp-flood — {} flows/batch at 10 Hz for {}s → ~{} pps",
        flows_per_batch, args.duration_secs, args.pps
    );

    for batch in 0..total_batches {
        let offset = ((batch * flows_per_batch as u64) & 0xffff) as u16;
        let params = FlowParams {
            protocol: 17, // UDP
            tcp_flags: 0x00,
            packets: 1,
            bytes: 512,
            start_uptime: 0,
            end_uptime: 50,
            src_ip_base: 0x0a000001, // 10.0.0.1 cycling through many sources
            src_ip_vary: true,
            dst_ip: 0x0a010101, // 10.1.1.1
            dst_port: 53,
        };
        send_flows(
            socket,
            &args.target,
            flows_per_batch,
            sequence,
            offset,
            params,
        );
        sequence = sequence.wrapping_add(1);
        std::thread::sleep(batch_interval);
    }

    println!("flowgen: udp-flood done");
}

// --- SYN flood ---
// Generates high-rate TCP SYN-only flows with very short durations.

fn run_syn_flood(socket: &UdpSocket, args: &Args) {
    let batch_interval = Duration::from_millis(100);
    let flows_per_batch = (args.pps / 10).max(1) as u16;
    let total_batches = args.duration_secs * 10;
    let mut sequence: u32 = 1;

    println!(
        "flowgen: syn-flood — {} flows/batch at 10 Hz for {}s → ~{} pps",
        flows_per_batch, args.duration_secs, args.pps
    );

    for batch in 0..total_batches {
        let offset = ((batch * flows_per_batch as u64) & 0xffff) as u16;
        let params = FlowParams {
            protocol: 6,     // TCP
            tcp_flags: 0x02, // SYN only (no ACK)
            packets: 1,
            bytes: 40,
            start_uptime: 0,
            end_uptime: 50, // 50ms duration — well below 500ms threshold
            src_ip_base: 0x0a000001,
            src_ip_vary: true,
            dst_ip: 0xc0000201, // 192.0.2.1
            dst_port: 80,
        };
        send_flows(
            socket,
            &args.target,
            flows_per_batch,
            sequence,
            offset,
            params,
        );
        sequence = sequence.wrapping_add(1);
        std::thread::sleep(batch_interval);
    }

    println!("flowgen: syn-flood done");
}

// --- Port scan ---
// One source IP contacts many distinct destination ports with tiny flows.

fn run_port_scan(socket: &UdpSocket, args: &Args) {
    let src_ip: std::net::Ipv4Addr = args
        .src_ip
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(10, 0, 0, 99));
    let src_ip_u32 = u32::from(src_ip);
    let total_ports = args.ports;
    let duration = Duration::from_secs(args.duration_secs);
    let start = std::time::Instant::now();
    let mut sequence: u32 = 1;
    let mut port_cursor: u16 = 1;

    // Spread ports evenly across duration
    let sleep_per_port = duration / total_ports as u32;

    println!(
        "flowgen: port-scan — src={} scanning {} unique dst ports over {}s",
        src_ip, total_ports, args.duration_secs
    );

    while start.elapsed() < duration {
        let dst_port = port_cursor;
        let pkt = build_port_scan_packet(src_ip_u32, dst_port, sequence);
        socket.send_to(&pkt, &args.target).expect("send failed");
        sequence = sequence.wrapping_add(1);
        port_cursor = port_cursor % total_ports + 1;
        std::thread::sleep(sleep_per_port);
    }

    println!("flowgen: port-scan done");
}

fn build_port_scan_packet(src_ip: u32, dst_port: u16, sequence: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 48);

    // Header (24 bytes)
    buf.extend_from_slice(&5u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // count = 1
    buf.extend_from_slice(&100_000u32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());

    // Flow record: fixed src IP, varying dst port, small bytes
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&0x08080808u32.to_be_bytes()); // 8.8.8.8
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes()); // packets = 1
    buf.extend_from_slice(&44u32.to_be_bytes()); // bytes = 44 (small)
    buf.extend_from_slice(&0u32.to_be_bytes()); // first uptime
    buf.extend_from_slice(&10u32.to_be_bytes()); // last uptime
    buf.extend_from_slice(&54321u16.to_be_bytes()); // src port
    buf.extend_from_slice(&dst_port.to_be_bytes()); // dst port (scanned)
    buf.push(0);
    buf.push(0x02); // SYN
    buf.push(6); // TCP
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

// --- Destination hotspot ---
// Most traffic (by bytes) goes to a single destination IP.

fn run_hotspot(socket: &UdpSocket, args: &Args) {
    let dst_ip: std::net::Ipv4Addr = args
        .dst_ip
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(1, 1, 1, 1));
    let dst_ip_u32 = u32::from(dst_ip);

    let batch_interval = Duration::from_millis(100);
    let total_batches = args.duration_secs * 10;
    // 10 flows per batch: ratio*10 hot flows, rest cold
    let hot_flows = (args.ratio * 10.0).round().max(1.0) as u16;
    let cold_flows: u16 = 10u16.saturating_sub(hot_flows);
    let mut sequence: u32 = 1;

    println!(
        "flowgen: hotspot — dst={} ratio={:.0}% ({} hot / {} cold flows/batch) for {}s",
        dst_ip,
        args.ratio * 100.0,
        hot_flows,
        cold_flows,
        args.duration_secs
    );

    for _ in 0..total_batches {
        if hot_flows > 0 {
            let params = FlowParams {
                protocol: 6,
                tcp_flags: 0x18,
                packets: 10,
                bytes: 50_000,
                start_uptime: 0,
                end_uptime: 100_000,
                src_ip_base: 0x0a000001,
                src_ip_vary: true,
                dst_ip: dst_ip_u32,
                dst_port: 443,
            };
            send_flows(socket, &args.target, hot_flows, sequence, 0, params);
            sequence = sequence.wrapping_add(1);
        }

        if cold_flows > 0 {
            let params = FlowParams {
                protocol: 6,
                tcp_flags: 0x18,
                packets: 10,
                bytes: 50_000,
                start_uptime: 0,
                end_uptime: 100_000,
                src_ip_base: 0x0a000001,
                src_ip_vary: true,
                dst_ip: 0x08080808, // 8.8.8.8
                dst_port: 443,
            };
            send_flows(socket, &args.target, cold_flows, sequence, 0, params);
            sequence = sequence.wrapping_add(1);
        }

        std::thread::sleep(batch_interval);
    }

    println!("flowgen: hotspot done");
}

// --- Packet building helpers ---

#[derive(Clone)]
struct FlowParams {
    protocol: u8,
    tcp_flags: u8,
    packets: u32,
    bytes: u32,
    start_uptime: u32,
    end_uptime: u32,
    src_ip_base: u32,
    src_ip_vary: bool,
    dst_ip: u32,
    dst_port: u16,
}

impl Default for FlowParams {
    fn default() -> Self {
        Self {
            protocol: 6,
            tcp_flags: 0x18,
            packets: 12,
            bytes: 5840,
            start_uptime: 90_000,
            end_uptime: 100_000,
            src_ip_base: 0x0a000005,
            src_ip_vary: true,
            dst_ip: 0x01010101,
            dst_port: 443,
        }
    }
}

fn send_flows(
    socket: &UdpSocket,
    target: &str,
    count: u16,
    sequence: u32,
    offset: u16,
    params: FlowParams,
) {
    const MAX_PER_PACKET: u16 = 30;
    let mut remaining = count;
    let mut seq = sequence;

    while remaining > 0 {
        let batch = remaining.min(MAX_PER_PACKET);
        let pkt_offset = count - remaining + offset;
        let pkt = build_packet(batch, seq, pkt_offset, params.clone());
        socket.send_to(&pkt, target).expect("send failed");
        remaining -= batch;
        seq = seq.wrapping_add(1);
    }
}

fn build_packet(count: u16, sequence: u32, offset: u16, params: FlowParams) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 48 * count as usize);

    // Header (24 bytes)
    buf.extend_from_slice(&5u16.to_be_bytes()); // version = 5
    buf.extend_from_slice(&count.to_be_bytes()); // count
    buf.extend_from_slice(&100_000u32.to_be_bytes()); // sysuptime (ms)
    buf.extend_from_slice(&0u32.to_be_bytes()); // unix secs
    buf.extend_from_slice(&0u32.to_be_bytes()); // unix nsecs
    buf.extend_from_slice(&sequence.to_be_bytes()); // sequence
    buf.push(0);
    buf.push(0); // engine type/id
    buf.extend_from_slice(&0u16.to_be_bytes()); // sampling interval

    // Flow records (48 bytes each)
    for i in 0..count {
        let src_ip = if params.src_ip_vary {
            params.src_ip_base.wrapping_add((offset + i) as u32)
        } else {
            params.src_ip_base
        };

        buf.extend_from_slice(&src_ip.to_be_bytes());
        buf.extend_from_slice(&params.dst_ip.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // nexthop
        buf.extend_from_slice(&0u16.to_be_bytes()); // snmp in
        buf.extend_from_slice(&0u16.to_be_bytes()); // snmp out
        buf.extend_from_slice(&params.packets.to_be_bytes());
        buf.extend_from_slice(&params.bytes.to_be_bytes());
        buf.extend_from_slice(&params.start_uptime.to_be_bytes());
        buf.extend_from_slice(&params.end_uptime.to_be_bytes());
        buf.extend_from_slice(&54321u16.to_be_bytes()); // src port
        buf.extend_from_slice(&params.dst_port.to_be_bytes());
        buf.push(0); // padding
        buf.push(params.tcp_flags);
        buf.push(params.protocol);
        buf.push(0); // tos
        buf.extend_from_slice(&0u16.to_be_bytes()); // src AS
        buf.extend_from_slice(&0u16.to_be_bytes()); // dst AS
        buf.push(0);
        buf.push(0); // src/dst mask
        buf.extend_from_slice(&0u16.to_be_bytes()); // padding
    }

    buf
}

// --- NetFlow v9 mode ---
// Sends a single UDP datagram containing a template flowset + data flowset.

fn run_netflow_v9(socket: &UdpSocket, args: &Args) {
    let flows = args.flows as usize;
    let pkt = build_netflow_v9_packet(flows);
    socket.send_to(&pkt, &args.target).expect("send failed");
    println!(
        "flowgen: netflow-v9 — sent {} flow(s) to {}",
        flows, args.target
    );
}

fn build_netflow_v9_packet(flows: usize) -> Vec<u8> {
    const TEMPLATE_ID: u16 = 256;
    // Fields: (type, length)
    let fields: &[(u16, u16)] = &[
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
    let record_len: usize = fields.iter().map(|(_, l)| *l as usize).sum(); // 30

    // Template FlowSet:
    // 4-byte flowset header + 4-byte template record header + 10*4 = 40 bytes field defs = 48 bytes
    let tmpl_flowset_len: u16 = 4 + 4 + (fields.len() as u16) * 4; // 48

    // Data FlowSet:
    let data_payload = flows * record_len;
    let data_with_header = 4 + data_payload;
    let data_padding = (4 - data_with_header % 4) % 4;
    let data_flowset_len = data_with_header + data_padding;

    let mut pkt = Vec::new();

    // NF9 Header (20 bytes)
    pkt.extend_from_slice(&9u16.to_be_bytes()); // version = 9
    pkt.extend_from_slice(&2u16.to_be_bytes()); // count = 2 flowsets
    pkt.extend_from_slice(&100_000u32.to_be_bytes()); // sysuptime
    pkt.extend_from_slice(&0u32.to_be_bytes()); // unix_secs
    pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence
    pkt.extend_from_slice(&0u32.to_be_bytes()); // source_id

    // Template FlowSet header
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flowset ID = 0
    pkt.extend_from_slice(&tmpl_flowset_len.to_be_bytes());

    // Template record header
    pkt.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    pkt.extend_from_slice(&(fields.len() as u16).to_be_bytes());

    // Field definitions
    for (ftype, flen) in fields {
        pkt.extend_from_slice(&ftype.to_be_bytes());
        pkt.extend_from_slice(&flen.to_be_bytes());
    }

    // Data FlowSet header
    pkt.extend_from_slice(&TEMPLATE_ID.to_be_bytes()); // flowset ID = 256
    pkt.extend_from_slice(&(data_flowset_len as u16).to_be_bytes());

    // Flow records
    for i in 0..flows {
        let src_ip: u32 = 0x0a000001u32.wrapping_add(i as u32);
        let dst_ip: u32 = 0x0a010101;
        pkt.extend_from_slice(&src_ip.to_be_bytes()); // IPV4_SRC_ADDR
        pkt.extend_from_slice(&dst_ip.to_be_bytes()); // IPV4_DST_ADDR
        pkt.extend_from_slice(&54321u16.to_be_bytes()); // L4_SRC_PORT
        pkt.extend_from_slice(&443u16.to_be_bytes()); // L4_DST_PORT
        pkt.push(6u8); // PROTOCOL = TCP
        pkt.extend_from_slice(&12u32.to_be_bytes()); // IN_PKTS
        pkt.extend_from_slice(&5840u32.to_be_bytes()); // IN_BYTES
        pkt.extend_from_slice(&90_000u32.to_be_bytes()); // FIRST_SWITCHED
        pkt.extend_from_slice(&100_000u32.to_be_bytes()); // LAST_SWITCHED
        pkt.push(0x18u8); // TCP_FLAGS
    }

    // Padding
    pkt.extend(std::iter::repeat_n(0u8, data_padding));

    pkt
}

// --- IPFIX mode ---
// Sends a single UDP datagram containing a template set + data set.
// IANA default port for IPFIX is 4739; users can override with --target.

fn run_ipfix(socket: &UdpSocket, args: &Args) {
    let flows = args.flows as usize;
    let pkt = build_ipfix_packet(flows);
    socket.send_to(&pkt, &args.target).expect("send failed");
    println!("flowgen: ipfix — sent {} flow(s) to {}", flows, args.target);
}

fn build_ipfix_packet(flows: usize) -> Vec<u8> {
    const TEMPLATE_ID: u16 = 256;
    let fields: &[(u16, u16)] = &[
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
    let record_len: usize = fields.iter().map(|(_, l)| *l as usize).sum(); // 30

    // Template Set:
    // 4-byte set header + 4-byte template record header + 10*4 field defs = 48 bytes total
    let tmpl_set_len: u16 = 4 + 4 + (fields.len() as u16) * 4; // 48

    // Data Set:
    let data_payload = flows * record_len;
    let data_with_header = 4 + data_payload;
    let data_padding = (4 - data_with_header % 4) % 4;
    let data_set_len = data_with_header + data_padding;

    let total_len: u16 = 16 + tmpl_set_len + data_set_len as u16;

    let mut pkt = Vec::new();

    // IPFIX Header (16 bytes)
    pkt.extend_from_slice(&10u16.to_be_bytes()); // version = 10
    pkt.extend_from_slice(&total_len.to_be_bytes()); // length
    pkt.extend_from_slice(&0u32.to_be_bytes()); // export_time
    pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence
    pkt.extend_from_slice(&0u32.to_be_bytes()); // observation_domain_id

    // Template Set header
    pkt.extend_from_slice(&2u16.to_be_bytes()); // set ID = 2
    pkt.extend_from_slice(&tmpl_set_len.to_be_bytes());

    // Template record header
    pkt.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    pkt.extend_from_slice(&(fields.len() as u16).to_be_bytes());

    // Field specifiers
    for (ftype, flen) in fields {
        pkt.extend_from_slice(&ftype.to_be_bytes());
        pkt.extend_from_slice(&flen.to_be_bytes());
    }

    // Data Set header
    pkt.extend_from_slice(&TEMPLATE_ID.to_be_bytes()); // set ID = 256
    pkt.extend_from_slice(&(data_set_len as u16).to_be_bytes());

    // Flow records
    for i in 0..flows {
        let src_ip: u32 = 0x0a000001u32.wrapping_add(i as u32);
        let dst_ip: u32 = 0x0a010101;
        pkt.extend_from_slice(&src_ip.to_be_bytes()); // IPV4_SRC_ADDR
        pkt.extend_from_slice(&dst_ip.to_be_bytes()); // IPV4_DST_ADDR
        pkt.extend_from_slice(&54321u16.to_be_bytes()); // L4_SRC_PORT
        pkt.extend_from_slice(&443u16.to_be_bytes()); // L4_DST_PORT
        pkt.push(6u8); // PROTOCOL = TCP
        pkt.extend_from_slice(&12u32.to_be_bytes()); // IN_PKTS
        pkt.extend_from_slice(&5840u32.to_be_bytes()); // IN_BYTES
        pkt.extend_from_slice(&90_000u32.to_be_bytes()); // FIRST_SWITCHED
        pkt.extend_from_slice(&100_000u32.to_be_bytes()); // LAST_SWITCHED
        pkt.push(0x18u8); // TCP_FLAGS
    }

    // Padding
    pkt.extend(std::iter::repeat_n(0u8, data_padding));

    pkt
}
