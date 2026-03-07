use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::decoder::flow_record::FlowRecord;

use super::metrics::{self, WindowMetrics};

pub struct SlidingWindow {
    pub duration_secs: u64,
    records: VecDeque<(FlowRecord, Instant)>,
}

impl SlidingWindow {
    pub fn new(duration_secs: u64) -> Self {
        Self {
            duration_secs,
            records: VecDeque::new(),
        }
    }

    pub fn push(&mut self, record: FlowRecord) {
        self.records.push_back((record, Instant::now()));
    }

    pub fn evict_expired(&mut self) {
        let cutoff = Duration::from_secs(self.duration_secs);
        let now = Instant::now();
        while let Some((_, ts)) = self.records.front() {
            if now.duration_since(*ts) > cutoff {
                self.records.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn compute(&self) -> WindowMetrics {
        metrics::compute(self.records.iter(), self.duration_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn make_record(src: u8, bytes: u32, packets: u32) -> FlowRecord {
        FlowRecord {
            src_ip: Ipv4Addr::new(10, 0, 0, src),
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            packets,
            bytes,
            start_time: 0,
            end_time: 0,
            tcp_flags: 0,
            exporter_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            received_at: SystemTime::now(),
        }
    }

    #[test]
    fn push_and_compute() {
        let mut w = SlidingWindow::new(60);
        w.push(make_record(1, 1000, 10));
        w.push(make_record(2, 2000, 20));
        let m = w.compute();
        assert_eq!(m.flows, 2);
        assert_eq!(m.bytes, 3000);
        assert_eq!(m.packets, 30);
        assert_eq!(m.unique_src_ips, 2);
    }

    #[test]
    fn evict_expired_removes_old_records() {
        let mut w = SlidingWindow::new(0); // zero-second window expires everything
        w.push(make_record(1, 500, 5));
        std::thread::sleep(std::time::Duration::from_millis(10));
        w.evict_expired();
        let m = w.compute();
        assert_eq!(m.flows, 0);
    }

    #[test]
    fn evict_keeps_fresh_records() {
        let mut w = SlidingWindow::new(60);
        w.push(make_record(1, 500, 5));
        w.evict_expired();
        let m = w.compute();
        assert_eq!(m.flows, 1);
    }

    #[test]
    fn protocol_distribution() {
        let mut w = SlidingWindow::new(60);
        let mut r1 = make_record(1, 100, 1);
        r1.protocol = 6;
        let mut r2 = make_record(2, 100, 1);
        r2.protocol = 17;
        let mut r3 = make_record(3, 100, 1);
        r3.protocol = 6;
        w.push(r1);
        w.push(r2);
        w.push(r3);
        let m = w.compute();
        assert_eq!(m.protocol_dist[&6], 2);
        assert_eq!(m.protocol_dist[&17], 1);
    }
}
