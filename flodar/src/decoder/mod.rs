use std::net::IpAddr;
use thiserror::Error;

pub mod flow_record;
pub mod ipfix;
pub mod netflow_v5;
pub mod netflow_v9;
pub mod template_cache;

use flow_record::FlowRecord;
use template_cache::TemplateCache;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("packet too short: expected {expected}, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("length mismatch: header count {header}, data fits {fits}")]
    LengthMismatch { header: u16, fits: usize },
    #[error("template {template_id} not yet received from {exporter_ip}")]
    #[allow(dead_code)]
    TemplateNotFound {
        template_id: u16,
        exporter_ip: IpAddr,
    },
    #[error("required field {field_id} missing from template {template_id}")]
    #[allow(dead_code)]
    RequiredFieldMissing { field_id: u16, template_id: u16 },
}

pub fn decode_packet(
    data: &[u8],
    exporter_ip: IpAddr,
    cache: &mut TemplateCache,
) -> Result<Vec<FlowRecord>, DecodeError> {
    if data.len() < 2 {
        return Err(DecodeError::TooShort {
            expected: 2,
            actual: data.len(),
        });
    }
    let version = u16::from_be_bytes([data[0], data[1]]);
    match version {
        5 => netflow_v5::parse(data, exporter_ip),
        9 => netflow_v9::parse(data, exporter_ip, cache),
        10 => ipfix::parse(data, exporter_ip, cache),
        v => Err(DecodeError::UnsupportedVersion(v)),
    }
}
