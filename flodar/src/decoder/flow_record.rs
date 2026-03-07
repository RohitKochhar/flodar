use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u32,
    pub bytes: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub tcp_flags: u8,
    pub exporter_ip: IpAddr,
    pub received_at: SystemTime,
}
