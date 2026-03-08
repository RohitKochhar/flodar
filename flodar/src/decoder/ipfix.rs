use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use super::flow_record::FlowRecord;
use super::template_cache::{Template, TemplateCache, TemplateField, TemplateKey};
use super::DecodeError;

const HEADER_LEN: usize = 16;
const SET_HEADER_LEN: usize = 4;

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

    // IPFIX header (16 bytes):
    // version(2) length(2) export_time(4) sequence_number(4) observation_domain_id(4)
    let observation_domain_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    let mut records = Vec::new();
    let mut pos = HEADER_LEN;

    while pos + SET_HEADER_LEN <= data.len() {
        let set_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let set_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if set_length < SET_HEADER_LEN {
            break;
        }

        let set_end = pos + set_length;
        if set_end > data.len() {
            break;
        }

        match set_id {
            2 => {
                // Template Set
                parse_template_set(
                    &data[pos + SET_HEADER_LEN..set_end],
                    exporter_ip,
                    observation_domain_id,
                    cache,
                );
            }
            3 => {
                // Options Template Set — skip
            }
            id if id >= 256 => {
                // Data Set
                let mut data_records = parse_data_set(
                    &data[pos + SET_HEADER_LEN..set_end],
                    exporter_ip,
                    observation_domain_id,
                    id,
                    cache,
                );
                records.append(&mut data_records);
            }
            _ => {
                // Unknown set ID, skip
            }
        }

        pos = set_end;
    }

    Ok(records)
}

fn parse_template_set(
    data: &[u8],
    exporter_ip: IpAddr,
    observation_domain_id: u32,
    cache: &mut TemplateCache,
) {
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let template_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let field_count = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let mut fields = Vec::with_capacity(field_count);
        let mut total_length: u16 = 0;
        let mut valid = true;

        for _ in 0..field_count {
            if pos + 4 > data.len() {
                valid = false;
                break;
            }

            let raw_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let field_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;

            let enterprise_bit = raw_type & 0x8000 != 0;
            let field_type = raw_type & 0x7FFF;

            let enterprise_id = if enterprise_bit {
                if pos + 4 > data.len() {
                    valid = false;
                    break;
                }
                let eid =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                Some(eid)
            } else {
                None
            };

            total_length = total_length.saturating_add(field_length);
            fields.push(TemplateField {
                field_type,
                field_length,
                enterprise_id,
            });
        }

        if !valid {
            break;
        }

        let key = TemplateKey {
            exporter_ip,
            observation_domain_id,
            template_id,
        };

        cache.insert(Template {
            key,
            fields,
            total_length,
        });
    }
}

fn parse_data_set(
    data: &[u8],
    exporter_ip: IpAddr,
    observation_domain_id: u32,
    template_id: u16,
    cache: &TemplateCache,
) -> Vec<FlowRecord> {
    let key = TemplateKey {
        exporter_ip,
        observation_domain_id,
        template_id,
    };

    let template = match cache.get(&key) {
        Some(t) => t,
        None => {
            tracing::debug!(
                template_id,
                exporter_ip = %exporter_ip,
                "ipfix: template not yet received, dropping data set"
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

        // Enterprise fields: advance cursor but skip mapping
        if field.enterprise_id.is_none() {
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

    // Standard 10-field template matching flowgen output
    fn standard_fields() -> Vec<(u16, u16, Option<u32>)> {
        vec![
            (8, 4, None),  // IPV4_SRC_ADDR
            (12, 4, None), // IPV4_DST_ADDR
            (7, 2, None),  // L4_SRC_PORT
            (11, 2, None), // L4_DST_PORT
            (4, 1, None),  // PROTOCOL
            (2, 4, None),  // IN_PKTS
            (1, 4, None),  // IN_BYTES
            (22, 4, None), // FIRST_SWITCHED
            (21, 4, None), // LAST_SWITCHED
            (6, 1, None),  // TCP_FLAGS
        ]
    }

    fn build_template_set(template_id: u16, fields: &[(u16, u16, Option<u32>)]) -> Vec<u8> {
        let mut set_data = Vec::new();
        // Template record header
        set_data.extend_from_slice(&template_id.to_be_bytes());
        set_data.extend_from_slice(&(fields.len() as u16).to_be_bytes());

        for (ftype, flen, enterprise) in fields {
            if let Some(eid) = enterprise {
                let raw_type = ftype | 0x8000;
                set_data.extend_from_slice(&raw_type.to_be_bytes());
                set_data.extend_from_slice(&flen.to_be_bytes());
                set_data.extend_from_slice(&eid.to_be_bytes());
            } else {
                set_data.extend_from_slice(&ftype.to_be_bytes());
                set_data.extend_from_slice(&flen.to_be_bytes());
            }
        }

        let set_len = SET_HEADER_LEN + set_data.len();
        let mut set = Vec::new();
        set.extend_from_slice(&2u16.to_be_bytes()); // Set ID = 2 (template)
        set.extend_from_slice(&(set_len as u16).to_be_bytes());
        set.extend_from_slice(&set_data);
        set
    }

    fn build_ipfix_packet(sets: &[Vec<u8>]) -> Vec<u8> {
        let sets_len: usize = sets.iter().map(|s| s.len()).sum();
        let total_len = HEADER_LEN + sets_len;

        let mut pkt = Vec::new();
        // IPFIX header (16 bytes)
        pkt.extend_from_slice(&10u16.to_be_bytes()); // version = 10
        pkt.extend_from_slice(&(total_len as u16).to_be_bytes()); // length
        pkt.extend_from_slice(&0u32.to_be_bytes()); // export_time
        pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence
        pkt.extend_from_slice(&0u32.to_be_bytes()); // observation_domain_id = 0

        for set in sets {
            pkt.extend_from_slice(set);
        }

        pkt
    }

    fn build_data_set(template_id: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let record_len: usize = records.first().map(|r| r.len()).unwrap_or(0);
        let data_len = records.len() * record_len;
        let padding = (4 - (SET_HEADER_LEN + data_len) % 4) % 4;
        let set_len = SET_HEADER_LEN + data_len + padding;

        let mut set = Vec::new();
        set.extend_from_slice(&template_id.to_be_bytes());
        set.extend_from_slice(&(set_len as u16).to_be_bytes());
        for rec in records {
            set.extend_from_slice(rec);
        }
        set.extend(std::iter::repeat_n(0u8, padding));
        set
    }

    fn make_flow_record_bytes() -> Vec<u8> {
        let mut rec = Vec::new();
        rec.extend_from_slice(&[10, 0, 0, 1]); // src_ip
        rec.extend_from_slice(&[10, 0, 0, 2]); // dst_ip
        rec.extend_from_slice(&1024u16.to_be_bytes()); // src_port
        rec.extend_from_slice(&80u16.to_be_bytes()); // dst_port
        rec.push(6u8); // protocol
        rec.extend_from_slice(&100u32.to_be_bytes()); // packets
        rec.extend_from_slice(&5000u32.to_be_bytes()); // bytes
        rec.extend_from_slice(&1000u32.to_be_bytes()); // start_time
        rec.extend_from_slice(&2000u32.to_be_bytes()); // end_time
        rec.push(0x02u8); // tcp_flags
        rec
    }

    #[test]
    fn test_parse_template_set_with_enterprise_field() {
        // Template with one standard field and one enterprise field
        let fields: Vec<(u16, u16, Option<u32>)> = vec![
            (8, 4, None),         // IPV4_SRC_ADDR (standard)
            (12, 4, None),        // IPV4_DST_ADDR (standard)
            (100, 4, Some(9876)), // enterprise field, PEN=9876
        ];

        let tmpl_set = build_template_set(256, &fields);
        let pkt = build_ipfix_packet(&[tmpl_set]);

        let mut cache = TemplateCache::new();
        let result = parse(&pkt, exporter(), &mut cache).unwrap();
        assert!(result.is_empty());

        let key = TemplateKey {
            exporter_ip: exporter(),
            observation_domain_id: 0,
            template_id: 256,
        };
        let tmpl = cache.get(&key).expect("template should be cached");
        assert_eq!(tmpl.fields.len(), 3);

        // Third field should have enterprise_id set
        let enterprise_field = &tmpl.fields[2];
        assert_eq!(enterprise_field.enterprise_id, Some(9876));
        assert_eq!(enterprise_field.field_type, 100);
    }

    #[test]
    fn test_parse_data_set_correct_records() {
        let fields = standard_fields();
        let tmpl_set = build_template_set(256, &fields);
        let record_bytes = make_flow_record_bytes();
        let data_set = build_data_set(256, &[record_bytes]);
        let pkt = build_ipfix_packet(&[tmpl_set, data_set]);

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
    fn test_data_set_before_template_returns_empty() {
        let record_bytes = make_flow_record_bytes();
        let data_set = build_data_set(256, &[record_bytes]);
        let pkt = build_ipfix_packet(&[data_set]);

        let mut cache = TemplateCache::new();
        let result = parse(&pkt, exporter(), &mut cache);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
