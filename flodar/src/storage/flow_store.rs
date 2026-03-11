use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

use super::FlowStore;
use crate::decoder::flow_record::FlowRecord;

pub struct DuckDbFlowStore {
    conn: Arc<Mutex<duckdb::Connection>>,
}

impl DuckDbFlowStore {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).context("failed to create flow store directory")?;
            }
        }
        let conn = duckdb::Connection::open(path).context("failed to open DuckDB flow store")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS flows (
                src_ip       TEXT NOT NULL,
                dst_ip       TEXT NOT NULL,
                src_port     INTEGER,
                dst_port     INTEGER,
                protocol     INTEGER NOT NULL,
                packets      INTEGER NOT NULL,
                bytes        INTEGER NOT NULL,
                start_time   INTEGER,
                end_time     INTEGER,
                tcp_flags    INTEGER,
                exporter_ip  TEXT NOT NULL,
                received_at_ms BIGINT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_flows_received_at ON flows(received_at_ms);
            CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
            CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);",
        )
        .context("failed to initialise flows schema")?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn ms_to_system_time(ms: i64) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_millis(ms as u64)
}

#[async_trait::async_trait]
impl FlowStore for DuckDbFlowStore {
    async fn insert(&self, record: &FlowRecord) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let src_ip = record.src_ip.to_string();
        let dst_ip = record.dst_ip.to_string();
        let src_port = record.src_port as i32;
        let dst_port = record.dst_port as i32;
        let protocol = record.protocol as i32;
        let packets = record.packets as i64;
        let bytes = record.bytes as i64;
        let start_time = record.start_time as i64;
        let end_time = record.end_time as i64;
        let tcp_flags = record.tcp_flags as i32;
        let exporter_ip = record.exporter_ip.to_string();
        let received_at_ms = system_time_to_ms(record.received_at);

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(|_| anyhow::anyhow!("mutex poisoned"))?;
            conn.execute(
                "INSERT INTO flows \
                 (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, \
                  start_time, end_time, tcp_flags, exporter_ip, received_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![
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
                    received_at_ms
                ],
            )
            .context("failed to insert flow record")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("spawn_blocking failed")??;

        Ok(())
    }

    async fn query_range(
        &self,
        start: SystemTime,
        end: SystemTime,
        limit: usize,
    ) -> anyhow::Result<Vec<FlowRecord>> {
        let conn = self.conn.clone();
        let start_ms = system_time_to_ms(start);
        let end_ms = system_time_to_ms(end);
        let limit_i64 = limit as i64;

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(|_| anyhow::anyhow!("mutex poisoned"))?;
            let mut stmt = conn
                .prepare(
                    "SELECT src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, \
                     start_time, end_time, tcp_flags, exporter_ip, received_at_ms \
                     FROM flows \
                     WHERE received_at_ms >= ? AND received_at_ms <= ? \
                     ORDER BY received_at_ms DESC \
                     LIMIT ?",
                )
                .context("failed to prepare range query")?;

            let rows = stmt
                .query_map(duckdb::params![start_ms, end_ms, limit_i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i32>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i32>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, i64>(11)?,
                    ))
                })
                .context("failed to execute range query")?;

            let mut records = Vec::new();
            for row in rows {
                let (
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
                    received_at_ms,
                ) = row.context("row decode error")?;

                let src_ip: Ipv4Addr = src_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                let dst_ip: Ipv4Addr = dst_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                let exporter_ip: IpAddr = exporter_ip
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

                records.push(FlowRecord {
                    src_ip,
                    dst_ip,
                    src_port: src_port as u16,
                    dst_port: dst_port as u16,
                    protocol: protocol as u8,
                    packets: packets as u32,
                    bytes: bytes as u32,
                    start_time: start_time as u32,
                    end_time: end_time as u32,
                    tcp_flags: tcp_flags as u8,
                    exporter_ip,
                    received_at: ms_to_system_time(received_at_ms),
                });
            }

            Ok::<Vec<FlowRecord>, anyhow::Error>(records)
        })
        .await
        .context("spawn_blocking failed")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, UNIX_EPOCH};

    fn make_record(offset_ms: u64) -> FlowRecord {
        FlowRecord {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 54321,
            dst_port: 80,
            protocol: 6,
            packets: 10,
            bytes: 5000,
            start_time: 0,
            end_time: 100,
            tcp_flags: 0x18,
            exporter_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            received_at: UNIX_EPOCH + Duration::from_millis(1_700_000_000_000 + offset_ms),
        }
    }

    #[tokio::test]
    async fn insert_and_query_range() {
        let store = DuckDbFlowStore::new(":memory:").expect("open in-memory DuckDB");

        let t0 = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        let t1 = UNIX_EPOCH + Duration::from_millis(1_700_000_001_000);
        let t2 = UNIX_EPOCH + Duration::from_millis(1_700_000_002_000);

        store.insert(&make_record(500)).await.unwrap(); // at t0+500ms
        store.insert(&make_record(1500)).await.unwrap(); // at t0+1500ms = between t1 and t2

        let results = store.query_range(t1, t2, 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].src_ip, Ipv4Addr::new(10, 0, 0, 1));

        // Query covering both records
        let results = store.query_range(t0, t2, 10).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_range_respects_limit() {
        let store = DuckDbFlowStore::new(":memory:").expect("open in-memory DuckDB");

        let t0 = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        let t_end = UNIX_EPOCH + Duration::from_millis(1_700_000_010_000);

        for i in 0..5 {
            store.insert(&make_record(i * 1000)).await.unwrap();
        }

        let results = store.query_range(t0, t_end, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }
}
