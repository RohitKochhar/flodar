use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use super::flow_record::FlowRecord;
use super::template_cache::{Template, TemplateCache, TemplateField, TemplateKey};
use super::DecodeError;

const HEADER_LEN: usize = 20;
const FLOWSET_HEADER_LEN: usize = 4;

pub fn parse(
    data: &[u8],
    exporter_ip: IpAddr,
    cache: &mut TemplateCache,
) -> Result<Vec<FlowRecord>, DecodeError> {
    if data.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            expected: HEADER_LEN,
            actual: data.len(),
        });
    }

    // Header: version(2) count(2) sysuptime(4) unix_secs(4) sequence(4) source_id(4)
    let source_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    let mut records = Vec::new();
    let mut pos = HEADER_LEN;

    while pos + FLOWSET_HEADER_LEN <= data.len() {
        let flowset_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let flowset_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if flowset_length < FLOWSET_HEADER_LEN {
            break;
        }

        let flowset_end = pos + flowset_length;
        if flowset_end > data.len() {
            break;
        }

        match flowset_id {
            0 => {
                // Template FlowSet
                parse_template_flowset(
                    &data[pos + FLOWSET_HEADER_LEN..flowset_end],
                    exporter_ip,
                    source_id,
                    cache,
                );
            }
            1 => {
                // Options Template FlowSet — skip
            }
            id if id >= 256 => {
                // Data FlowSet
                let mut data_records = parse_data_flowset(
                    &data[pos + FLOWSET_HEADER_LEN..flowset_end],
                    exporter_ip,
                    source_id,
                    id,
                    cache,
                );
                records.append(&mut data_records);
            }
            _ => {
                // Unknown flowset ID, skip
            }
        }

        pos = flowset_end;
    }

    Ok(records)
}

fn parse_template_flowset(
    data: &[u8],
    exporter_ip: IpAddr,
    source_id: u32,
    cache: &mut TemplateCache,
) {
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let template_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let field_count = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + field_count * 4 > data.len() {
            break;
        }

        let mut fields = Vec::with_capacity(field_count);
        let mut total_length: u16 = 0;

        for _ in 0..field_count {
            let field_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let field_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;

            total_length = total_length.saturating_add(field_length);
            fields.push(TemplateField {
                field_type,
                field_length,
                enterprise_id: None,
            });
        }

        let key = TemplateKey {
            exporter_ip,
            observation_domain_id: source_id,
            template_id,
        };

        cache.insert(Template {
            key,
            fields,
            total_length,
        });
    }
}

fn parse_data_flowset(
    data: &[u8],
    exporter_ip: IpAddr,
    source_id: u32,
    template_id: u16,
    cache: &TemplateCache,
) -> Vec<FlowRecord> {
    let key = TemplateKey {
        exporter_ip,
        observation_domain_id: source_id,
        template_id,
    };

    let template = match cache.get(&key) {
        Some(t) => t,
        None => {
            tracing::debug!(
                template_id,
                exporter_ip = %exporter_ip,
                "netflow v9: template not yet received, dropping data flowset"
            );
            return Vec::new();
        }
    };

    let record_len = template.total_length as usize;
    if record_len == 0 {
        return Vec::new();
    }

    let mut records = Vec::new();
    let mut pos = 0;

    while pos + record_len <= data.len() {
        let record_data = &data[pos..pos + record_len];
        if let Some(record) = decode_record(record_data, template, exporter_ip) {
            records.push(record);
        }
        pos += record_len;
    }

    records
}

fn decode_record(data: &[u8], template: &Template, exporter_ip: IpAddr) -> Option<FlowRecord> {
    let mut src_ip: Option<Ipv4Addr> = None;
    let mut dst_ip: Option<Ipv4Addr> = None;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut protocol: Option<u8> = None;
    let mut packets: Option<u32> = None;
    let mut bytes: Option<u32> = None;
    let mut start_time: u32 = 0;
    let mut end_time: u32 = 0;
    let mut tcp_flags: u8 = 0;

    let mut offset = 0usize;

    for field in &template.fields {
        let len = field.field_length as usize;
        if offset + len > data.len() {
            return None;
        }
        let slice = &data[offset..offset + len];

        match field.field_type {
            8 if len == 4 => {
                src_ip = Some(Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]));
            }
            12 if len == 4 => {
                dst_ip = Some(Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]));
            }
            7 if len == 2 => {
                src_port = u16::from_be_bytes([slice[0], slice[1]]);
            }
            11 if len == 2 => {
                dst_port = u16::from_be_bytes([slice[0], slice[1]]);
            }
            4 if len == 1 => {
                protocol = Some(slice[0]);
            }
            2 if len == 4 => {
                packets = Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
            }
            1 if len == 4 => {
                bytes = Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
            }
            22 if len == 4 => {
                start_time = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            }
            21 if len == 4 => {
                end_time = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            }
            6 if len == 1 => {
                tcp_flags = slice[0];
            }
            _ => {}
        }

        offset += len;
    }

    Some(FlowRecord {
        src_ip: src_ip?,
        dst_ip: dst_ip?,
        src_port,
        dst_port,
        protocol: protocol?,
        packets: packets?,
        bytes: bytes?,
        start_time,
        end_time,
        tcp_flags,
        exporter_ip,
        received_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exporter() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    /// Build a minimal NetFlow v9 packet containing a template flowset.
    fn build_template_packet(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let field_count = fields.len() as u16;
        // flowset data: 4 bytes template header + field_count * 4
        let flowset_data_len = 4 + field_count as usize * 4;
        let flowset_len = FLOWSET_HEADER_LEN + flowset_data_len;

        let mut pkt = Vec::new();
        // NF9 header (20 bytes)
        pkt.extend_from_slice(&9u16.to_be_bytes()); // version
        pkt.extend_from_slice(&1u16.to_be_bytes()); // count = 1 flowset
        pkt.extend_from_slice(&100_000u32.to_be_bytes()); // sysuptime
        pkt.extend_from_slice(&0u32.to_be_bytes()); // unix_secs
        pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence
        pkt.extend_from_slice(&0u32.to_be_bytes()); // source_id = 0

        // Template FlowSet header
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flowset ID = 0
        pkt.extend_from_slice(&(flowset_len as u16).to_be_bytes());

        // Template record header
        pkt.extend_from_slice(&template_id.to_be_bytes());
        pkt.extend_from_slice(&field_count.to_be_bytes());

        // Fields
        for (ftype, flen) in fields {
            pkt.extend_from_slice(&ftype.to_be_bytes());
            pkt.extend_from_slice(&flen.to_be_bytes());
        }

        pkt
    }

    /// Build a data flowset appended after the template packet.
    fn build_data_packet(template_pkt: &[u8], template_id: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let record_len: usize = records.first().map(|r| r.len()).unwrap_or(0);
        let data_len = records.len() * record_len;
        // Pad to 4-byte boundary
        let padding = (4 - (FLOWSET_HEADER_LEN + data_len) % 4) % 4;
        let flowset_len = FLOWSET_HEADER_LEN + data_len + padding;

        let mut pkt = template_pkt.to_vec();

        // Patch count in header to 2 flowsets
        pkt[2..4].copy_from_slice(&2u16.to_be_bytes());

        // Data FlowSet header
        pkt.extend_from_slice(&template_id.to_be_bytes());
        pkt.extend_from_slice(&(flowset_len as u16).to_be_bytes());

        for rec in records {
            pkt.extend_from_slice(rec);
        }

        // Padding
        pkt.extend(std::iter::repeat_n(0u8, padding));

        pkt
    }

    fn make_flow_record_bytes() -> Vec<u8> {
        let mut rec = Vec::new();
        rec.extend_from_slice(&[10, 0, 0, 1]); // src_ip (field 8)
        rec.extend_from_slice(&[10, 0, 0, 2]); // dst_ip (field 12)
        rec.extend_from_slice(&1024u16.to_be_bytes()); // src_port (field 7)
        rec.extend_from_slice(&80u16.to_be_bytes()); // dst_port (field 11)
        rec.push(6u8); // protocol (field 4)
        rec.extend_from_slice(&100u32.to_be_bytes()); // packets (field 2)
        rec.extend_from_slice(&5000u32.to_be_bytes()); // bytes (field 1)
        rec.extend_from_slice(&1000u32.to_be_bytes()); // start_time (field 22)
        rec.extend_from_slice(&2000u32.to_be_bytes()); // end_time (field 21)
        rec.push(0x02u8); // tcp_flags (field 6)
        rec
    }

    // Standard 10-field template matching flowgen output
    fn standard_fields() -> Vec<(u16, u16)> {
        vec![
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
        ]
    }

    #[test]
    fn test_parse_template_flowset_inserts_into_cache() {
        let fields = standard_fields();
        let pkt = build_template_packet(256, &fields);
        let mut cache = TemplateCache::new();

        let result = parse(&pkt, exporter(), &mut cache).unwrap();
        assert!(result.is_empty(), "template-only packet yields no records");

        let key = TemplateKey {
            exporter_ip: exporter(),
            observation_domain_id: 0,
            template_id: 256,
        };
        let tmpl = cache.get(&key).expect("template should be cached");
        assert_eq!(tmpl.fields.len(), 10);
        assert_eq!(tmpl.total_length, 30); // 4+4+2+2+1+4+4+4+4+1
    }

    #[test]
    fn test_parse_data_flowset_correct_records() {
        let fields = standard_fields();
        let tmpl_pkt = build_template_packet(256, &fields);
        let record_bytes = make_flow_record_bytes();
        let pkt = build_data_packet(&tmpl_pkt, 256, &[record_bytes]);

        let mut cache = TemplateCache::new();
        let records = parse(&pkt, exporter(), &mut cache).unwrap();

        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(r.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(r.src_port, 1024);
        assert_eq!(r.dst_port, 80);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.packets, 100);
        assert_eq!(r.bytes, 5000);
        assert_eq!(r.start_time, 1000);
        assert_eq!(r.end_time, 2000);
        assert_eq!(r.tcp_flags, 0x02);
    }

    #[test]
    fn test_data_flowset_before_template_returns_empty() {
        // Build a packet that only has a data flowset (no template)
        let record_bytes = make_flow_record_bytes();
        let data_len = record_bytes.len();
        let padding = (4 - (FLOWSET_HEADER_LEN + data_len) % 4) % 4;
        let flowset_len = FLOWSET_HEADER_LEN + data_len + padding;

        let mut pkt = Vec::new();
        // NF9 header
        pkt.extend_from_slice(&9u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&100_000u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // Data flowset for unknown template 256
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(flowset_len as u16).to_be_bytes());
        pkt.extend_from_slice(&record_bytes);
        pkt.extend(std::iter::repeat_n(0u8, padding));

        let mut cache = TemplateCache::new();
        let result = parse(&pkt, exporter(), &mut cache);
        assert!(result.is_ok(), "should not error on missing template");
        assert!(result.unwrap().is_empty(), "should return empty vec");
    }
}
