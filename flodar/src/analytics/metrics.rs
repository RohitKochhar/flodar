use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::decoder::flow_record::FlowRecord;

#[derive(Debug, Clone)]
pub struct WindowMetrics {
    pub window_secs: u64,
    pub flows: u64,
    pub packets: u64,
    pub bytes: u64,
    pub flows_per_sec: f64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub unique_src_ips: usize,
    pub unique_dst_ips: usize,
    pub top_src_ips: Vec<(Ipv4Addr, u64)>,
    pub top_dst_ips: Vec<(Ipv4Addr, u64)>,
    pub protocol_dist: HashMap<u8, u64>,
}

pub fn compute<'a>(
    records: impl Iterator<Item = &'a (FlowRecord, Instant)>,
    window_secs: u64,
) -> WindowMetrics {
    let mut flows: u64 = 0;
    let mut packets: u64 = 0;
    let mut bytes: u64 = 0;
    let mut src_ip_bytes: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut dst_ip_bytes: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut protocol_dist: HashMap<u8, u64> = HashMap::new();

    for (r, _) in records {
        flows += 1;
        packets += r.packets as u64;
        bytes += r.bytes as u64;
        *src_ip_bytes.entry(r.src_ip).or_insert(0) += r.bytes as u64;
        *dst_ip_bytes.entry(r.dst_ip).or_insert(0) += r.bytes as u64;
        *protocol_dist.entry(r.protocol).or_insert(0) += 1;
    }

    let unique_src_ips = src_ip_bytes.len();
    let unique_dst_ips = dst_ip_bytes.len();
    let top_src_ips = top_n(src_ip_bytes, 5);
    let top_dst_ips = top_n(dst_ip_bytes, 5);

    let secs = window_secs as f64;
    WindowMetrics {
        window_secs,
        flows,
        packets,
        bytes,
        flows_per_sec: flows as f64 / secs,
        packets_per_sec: packets as f64 / secs,
        bytes_per_sec: bytes as f64 / secs,
        unique_src_ips,
        unique_dst_ips,
        top_src_ips,
        top_dst_ips,
        protocol_dist,
    }
}

fn top_n(map: HashMap<Ipv4Addr, u64>, n: usize) -> Vec<(Ipv4Addr, u64)> {
    let mut v: Vec<(Ipv4Addr, u64)> = map.into_iter().collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    v.truncate(n);
    v
}
