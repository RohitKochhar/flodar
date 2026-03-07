use clap::Parser;
use std::net::UdpSocket;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:2055")]
    target: String,

    #[arg(long, default_value_t = 5)]
    flows: u16,
}

fn main() {
    let args = Args::parse();
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

    const MAX_PER_PACKET: u16 = 30;
    let mut remaining = args.flows;
    let mut sequence: u32 = 1;

    while remaining > 0 {
        let count = remaining.min(MAX_PER_PACKET);
        let packet = build_netflow_v5_packet(count, sequence, args.flows - remaining);
        socket.send_to(&packet, &args.target).expect("send failed");
        remaining -= count;
        sequence += 1;
    }

    println!("flowgen: sent {} flow(s) to {}", args.flows, args.target);
}

fn build_netflow_v5_packet(count: u16, sequence: u32, offset: u16) -> Vec<u8> {
    let mut buf = Vec::new();

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
        let src_ip: u32 = 0x0a000005 + (offset + i) as u32; // 10.0.0.5, 10.0.0.6 ...
        let dst_ip: u32 = 0x01010101; // 1.1.1.1

        buf.extend_from_slice(&src_ip.to_be_bytes()); // src ip
        buf.extend_from_slice(&dst_ip.to_be_bytes()); // dst ip
        buf.extend_from_slice(&0u32.to_be_bytes()); // nexthop
        buf.extend_from_slice(&0u16.to_be_bytes()); // snmp in
        buf.extend_from_slice(&0u16.to_be_bytes()); // snmp out
        buf.extend_from_slice(&12u32.to_be_bytes()); // packets
        buf.extend_from_slice(&5840u32.to_be_bytes()); // bytes
        buf.extend_from_slice(&90_000u32.to_be_bytes()); // first uptime
        buf.extend_from_slice(&100_000u32.to_be_bytes()); // last uptime
        buf.extend_from_slice(&54321u16.to_be_bytes()); // src port
        buf.extend_from_slice(&443u16.to_be_bytes()); // dst port
        buf.push(0); // padding
        buf.push(0x18); // tcp flags (ACK+PSH)
        buf.push(6); // protocol (TCP)
        buf.push(0); // tos
        buf.extend_from_slice(&0u16.to_be_bytes()); // src AS
        buf.extend_from_slice(&0u16.to_be_bytes()); // dst AS
        buf.push(0);
        buf.push(0); // src/dst mask
        buf.extend_from_slice(&0u16.to_be_bytes()); // padding
    }

    buf
}
