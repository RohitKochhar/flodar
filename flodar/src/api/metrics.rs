use anyhow::Result;
use prometheus::{Counter, CounterVec, Gauge, GaugeVec, Opts, Registry};

pub struct FlodarMetrics {
    pub flows_total: Counter,
    pub packets_total: Counter,
    pub bytes_total: Counter,
    pub alerts_total: CounterVec,
    pub active_exporters: Gauge,
    pub flows_per_sec: GaugeVec,
    pub packets_per_sec: GaugeVec,
    pub bytes_per_sec: GaugeVec,
    pub unique_src_ips: GaugeVec,
    pub unique_dst_ips: GaugeVec,
}

impl FlodarMetrics {
    pub fn new(registry: &Registry) -> Result<Self> {
        let flows_total = Counter::with_opts(Opts::new(
            "flodar_flows_total",
            "Total flow records ingested since startup",
        ))?;
        let packets_total = Counter::with_opts(Opts::new(
            "flodar_packets_total",
            "Total packets across all flows",
        ))?;
        let bytes_total = Counter::with_opts(Opts::new(
            "flodar_bytes_total",
            "Total bytes across all flows",
        ))?;
        let alerts_total = CounterVec::new(
            Opts::new(
                "flodar_alerts_total",
                "Alerts fired, partitioned by rule name",
            ),
            &["rule"],
        )?;
        let active_exporters = Gauge::with_opts(Opts::new(
            "flodar_active_exporters",
            "Unique exporter IPs seen in last 5 minutes",
        ))?;
        let flows_per_sec = GaugeVec::new(
            Opts::new("flodar_flows_per_sec", "Flows per second by window"),
            &["window"],
        )?;
        let packets_per_sec = GaugeVec::new(
            Opts::new("flodar_packets_per_sec", "Packets per second by window"),
            &["window"],
        )?;
        let bytes_per_sec = GaugeVec::new(
            Opts::new("flodar_bytes_per_sec", "Bytes per second by window"),
            &["window"],
        )?;
        let unique_src_ips = GaugeVec::new(
            Opts::new("flodar_unique_src_ips", "Unique source IPs per window"),
            &["window"],
        )?;
        let unique_dst_ips = GaugeVec::new(
            Opts::new("flodar_unique_dst_ips", "Unique destination IPs per window"),
            &["window"],
        )?;

        registry.register(Box::new(flows_total.clone()))?;
        registry.register(Box::new(packets_total.clone()))?;
        registry.register(Box::new(bytes_total.clone()))?;
        registry.register(Box::new(alerts_total.clone()))?;
        registry.register(Box::new(active_exporters.clone()))?;
        registry.register(Box::new(flows_per_sec.clone()))?;
        registry.register(Box::new(packets_per_sec.clone()))?;
        registry.register(Box::new(bytes_per_sec.clone()))?;
        registry.register(Box::new(unique_src_ips.clone()))?;
        registry.register(Box::new(unique_dst_ips.clone()))?;

        Ok(Self {
            flows_total,
            packets_total,
            bytes_total,
            alerts_total,
            active_exporters,
            flows_per_sec,
            packets_per_sec,
            bytes_per_sec,
            unique_src_ips,
            unique_dst_ips,
        })
    }
}
