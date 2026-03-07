use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;
use thiserror::Error;

use super::flow_record::FlowRecord;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("packet too short: expected {expected}, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("length mismatch: header count {header}, data fits {fits}")]
    LengthMismatch { header: u16, fits: usize },
}

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 48;

pub fn parse(data: &[u8], exporter_ip: IpAddr) -> Result<Vec<FlowRecord>, DecodeError> {
    if data.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            expected: HEADER_LEN,
            actual: data.len(),
        });
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 5 {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let count = u16::from_be_bytes([data[2], data[3]]);
    let expected_len = HEADER_LEN + (count as usize) * RECORD_LEN;

    if data.len() != expected_len {
        let fits = (data.len().saturating_sub(HEADER_LEN)) / RECORD_LEN;
        return Err(DecodeError::LengthMismatch {
            header: count,
            fits,
        });
    }

    let received_at = SystemTime::now();
    let mut records = Vec::with_capacity(count as usize);

    for i in 0..count as usize {
        let offset = HEADER_LEN + i * RECORD_LEN;
        let rec = &data[offset..offset + RECORD_LEN];

        let src_ip = Ipv4Addr::new(rec[0], rec[1], rec[2], rec[3]);
        let dst_ip = Ipv4Addr::new(rec[4], rec[5], rec[6], rec[7]);
        // rec[8..12] next hop — discard
        // rec[12..14] input SNMP — discard
        // rec[14..16] output SNMP — discard
        let packets = u32::from_be_bytes([rec[16], rec[17], rec[18], rec[19]]);
        let bytes = u32::from_be_bytes([rec[20], rec[21], rec[22], rec[23]]);
        let start_time = u32::from_be_bytes([rec[24], rec[25], rec[26], rec[27]]);
        let end_time = u32::from_be_bytes([rec[28], rec[29], rec[30], rec[31]]);
        let src_port = u16::from_be_bytes([rec[32], rec[33]]);
        let dst_port = u16::from_be_bytes([rec[34], rec[35]]);
        // rec[36] padding — discard
        let tcp_flags = rec[37];
        let protocol = rec[38];
        // rec[39] ToS — discard
        // rec[40..48] AS numbers + masks + padding — discard

        records.push(FlowRecord {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packets,
            bytes,
            start_time,
            end_time,
            tcp_flags,
            exporter_ip,
            received_at,
        });
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(version: u16, count: u16) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN];
        h[0..2].copy_from_slice(&version.to_be_bytes());
        h[2..4].copy_from_slice(&count.to_be_bytes());
        h
    }

    fn make_record(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packets: u32,
        bytes: u32,
        tcp_flags: u8,
    ) -> Vec<u8> {
        let mut r = vec![0u8; RECORD_LEN];
        r[0..4].copy_from_slice(&src);
        r[4..8].copy_from_slice(&dst);
        r[16..20].copy_from_slice(&packets.to_be_bytes());
        r[20..24].copy_from_slice(&bytes.to_be_bytes());
        r[32..34].copy_from_slice(&src_port.to_be_bytes());
        r[34..36].copy_from_slice(&dst_port.to_be_bytes());
        r[37] = tcp_flags;
        r[38] = protocol;
        r
    }

    #[test]
    fn test_parse_single_record() {
        let exporter: IpAddr = "192.168.1.1".parse().unwrap();
        let mut pkt = make_header(5, 1);
        pkt.extend(make_record(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1024,
            80,
            6,
            100,
            5000,
            0x02,
        ));

        let records = parse(&pkt, exporter).unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(r.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(r.src_port, 1024);
        assert_eq!(r.dst_port, 80);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.packets, 100);
        assert_eq!(r.bytes, 5000);
        assert_eq!(r.tcp_flags, 0x02);
        assert_eq!(r.exporter_ip, exporter);
    }

    #[test]
    fn test_parse_multiple_records() {
        let exporter: IpAddr = "10.1.1.1".parse().unwrap();
        let mut pkt = make_header(5, 3);
        for _ in 0..3 {
            pkt.extend(make_record([1, 2, 3, 4], [5, 6, 7, 8], 0, 0, 17, 1, 64, 0));
        }
        let records = parse(&pkt, exporter).unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_too_short() {
        let exporter: IpAddr = "1.2.3.4".parse().unwrap();
        let err = parse(&[0u8; 10], exporter).unwrap_err();
        assert!(matches!(err, DecodeError::TooShort { .. }));
    }

    #[test]
    fn test_unsupported_version() {
        let exporter: IpAddr = "1.2.3.4".parse().unwrap();
        let pkt = make_header(9, 0);
        let err = parse(&pkt, exporter).unwrap_err();
        assert!(matches!(err, DecodeError::UnsupportedVersion(9)));
    }

    #[test]
    fn test_length_mismatch() {
        let exporter: IpAddr = "1.2.3.4".parse().unwrap();
        // Header says 2 records but we only provide 1
        let mut pkt = make_header(5, 2);
        pkt.extend(make_record([0; 4], [0; 4], 0, 0, 0, 0, 0, 0));
        let err = parse(&pkt, exporter).unwrap_err();
        assert!(matches!(err, DecodeError::LengthMismatch { header: 2, fits: 1 }));
    }
}
