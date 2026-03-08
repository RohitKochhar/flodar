# Flodar

Lightweight network flow collector written in Rust. Receives NetFlow v5 over UDP, decodes each packet, emits one structured JSON log line per flow record, continuously computes sliding-window traffic analytics, fires explainable alerts when traffic patterns match known attack signatures, and exposes a Prometheus metrics endpoint and JSON HTTP API for integration with any observability stack.

## Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs))
- A router, switch, or traffic generator exporting NetFlow v5 to UDP port 2055

## Quick start (bare metal)

```bash
cargo build --release
./target/release/flodar
```

## Quick start (Docker)

```bash
# Build
docker build -f docker/Dockerfile -t flodar .

# Run (UDP 2055 for flows, TCP 9090 for metrics/API)
docker run -p 2055:2055/udp -p 9090:9090 flodar
```

ARM64 (Raspberry Pi 4):

```bash
docker buildx build --platform linux/arm64 -f docker/Dockerfile -t flodar:arm64 .
```

## Quickstart (clone and run)

```bash
# Clone and build
git clone https://github.com/your-org/flodar
cd flodar
cargo build --release

# Run with defaults (binds UDP 0.0.0.0:2055, JSON logs)
./target/release/flodar
```

You should see:

```
{"timestamp":"2026-03-06T12:00:00.000Z","level":"INFO","fields":{"address":"0.0.0.0:2055","message":"collector listening"}}
```

Point your router or NetFlow exporter at this host on port 2055. Each arriving flow record produces one JSON log line.

## Installation

```bash
cargo install --path flodar
```

This places the `flodar` binary in `~/.cargo/bin/`.

## Configuration

Flodar looks for a TOML config file passed via `--config`. If no file is given, built-in defaults are used.

**flodar.toml:**

```toml
[collector]
bind_address = "0.0.0.0"   # Interface to listen on. Use "127.0.0.1" to restrict to loopback.
bind_port = 2055            # Standard NetFlow port. Change if your exporter uses a different port.

[logging]
level = "info"              # Log level: error | warn | info | debug | trace
format = "json"             # Log format: json | pretty

[analytics]
snapshot_interval_secs = 10  # How often to emit window_metrics log lines (seconds).

[api]
bind_address = "0.0.0.0"   # Interface for the HTTP API and metrics server.
bind_port = 9090            # Conventional Prometheus exporter port.
enabled = true              # Set to false to disable the HTTP server entirely.

[detection]
enabled = true
cooldown_secs = 60           # Suppress repeat alerts for the same rule+target for this many seconds.

[detection.udp_flood]
min_packets_per_sec = 1000.0
min_udp_ratio = 0.80
min_unique_sources = 10

[detection.syn_flood]
min_packets_per_sec = 500.0
min_syn_ratio = 0.70
max_avg_flow_duration_ms = 500

[detection.port_scan]
min_unique_dst_ports = 50
max_bytes_per_flow = 100.0

[detection.destination_hotspot]
min_traffic_ratio = 0.80
min_bytes_per_sec = 100.0
```

Run with a config file:

```bash
./target/release/flodar --config flodar.toml
```

The `RUST_LOG` environment variable overrides the `logging.level` setting:

```bash
RUST_LOG=debug ./target/release/flodar
```

## CLI Reference

```
Usage: flodar [OPTIONS]

Options:
  -c, --config <CONFIG>          Path to configuration file
      --log-format <LOG_FORMAT>  Log format: json or pretty [default: json] [possible values: json, pretty]
  -h, --help                     Print help
  -V, --version                  Print version
```

## Log Output

### JSON format (default)

One line per flow record, suitable for piping into `jq`, Elasticsearch, or any log aggregator:

```json
{
  "timestamp": "2026-03-06T12:00:01.234Z",
  "level": "INFO",
  "fields": {
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 52100,
    "dst_port": 443,
    "protocol": 6,
    "packets": 42,
    "bytes": 58240,
    "start_time": 123456,
    "end_time": 123789,
    "tcp_flags": 24,
    "exporter_ip": "192.168.1.1",
    "received_at": "SystemTime { tv_sec: 1741262401, tv_nsec: 234000000 }",
    "message": "flow"
  }
}
```

**Field reference:**

| Field | Description |
|---|---|
| `src_ip` / `dst_ip` | Source and destination IPv4 addresses |
| `src_port` / `dst_port` | Layer 4 ports (0 for ICMP) |
| `protocol` | IANA protocol number: `6` = TCP, `17` = UDP, `1` = ICMP |
| `packets` | Number of packets in the flow |
| `bytes` | Total bytes in the flow |
| `start_time` / `end_time` | Router SysUptime (ms) at flow start and end |
| `tcp_flags` | OR of all TCP flags seen in the flow |
| `exporter_ip` | IP address of the router/switch that sent this export |
| `received_at` | Wall-clock time this packet arrived at Flodar |

### Pretty format

Useful for development and manual inspection:

```bash
./target/release/flodar --log-format pretty
```

```
2026-03-06T12:00:01.234Z  INFO flodar: flow
    src_ip: 10.0.0.1
    dst_ip: 10.0.0.2
    src_port: 52100
    dst_port: 443
    protocol: 6
    packets: 42
    bytes: 58240
    ...
```

## HTTP API

Flodar runs an HTTP server (default port `9090`) alongside the flow pipeline. All endpoints are read-only and require no authentication.

### `GET /health`

Liveness check. Returns `200 OK` as long as the process is running.

```json
{"status": "ok", "uptime_secs": 3600, "version": "0.4.0"}
```

### `GET /metrics`

Prometheus text exposition format. Point a Prometheus scrape job here.

```
# HELP flodar_flows_total Total flow records ingested since startup
# TYPE flodar_flows_total counter
flodar_flows_total 14523
# HELP flodar_flows_per_sec Flows per second by window
# TYPE flodar_flows_per_sec gauge
flodar_flows_per_sec{window="10s"} 42.3
flodar_flows_per_sec{window="60s"} 38.1
flodar_flows_per_sec{window="300s"} 35.7
...
```

**Metrics reference:**

| Metric | Type | Labels | Description |
|---|---|---|---|
| `flodar_flows_total` | counter | — | Total flow records ingested since startup |
| `flodar_packets_total` | counter | — | Total packets across all flows |
| `flodar_bytes_total` | counter | — | Total bytes across all flows |
| `flodar_alerts_total` | counter | `rule` | Alerts fired, partitioned by rule name |
| `flodar_active_exporters` | gauge | — | Unique exporter IPs seen in last 5 min |
| `flodar_flows_per_sec` | gauge | `window` | Flows/sec for `10s`, `60s`, `300s` windows |
| `flodar_packets_per_sec` | gauge | `window` | Packets/sec per window |
| `flodar_bytes_per_sec` | gauge | `window` | Bytes/sec per window |
| `flodar_unique_src_ips` | gauge | `window` | Unique source IPs per window |
| `flodar_unique_dst_ips` | gauge | `window` | Unique destination IPs per window |

A ready-to-use Prometheus scrape config is provided in [`examples/prometheus.yml`](examples/prometheus.yml).

### `GET /api/summary`

Current traffic snapshot from the 10 s window. Returns `503` if no window has been computed yet (first 10 s after startup).

```json
{
  "window_secs": 10,
  "flows_per_sec": 42.3,
  "packets_per_sec": 312.1,
  "bytes_per_sec": 184320.0,
  "unique_src_ips": 14,
  "unique_dst_ips": 3,
  "active_exporters": 1,
  "uptime_secs": 3600
}
```

### `GET /api/top-talkers`

Top 5 source and destination IPs by bytes from the 60 s window. Returns `503` if not enough data yet.

```json
{
  "window_secs": 60,
  "top_sources": [
    {"ip": "10.0.0.5", "bytes": 2048000, "bytes_per_sec": 34133.3}
  ],
  "top_destinations": [
    {"ip": "1.1.1.1", "bytes": 1843200, "bytes_per_sec": 30720.0}
  ]
}
```

### `GET /api/alerts`

Most recent alerts, newest first. Optional `?limit=N` parameter (default 20, max 100).

```json
{
  "total": 3,
  "alerts": [
    {
      "rule": "udp_flood",
      "severity": "High",
      "target_ip": null,
      "window_secs": 10,
      "indicators": ["packets/sec: 3400 (threshold: 1000)", "UDP ratio: 92% (threshold: 80%)"],
      "triggered_at": "2026-03-07T15:00:00Z"
    }
  ]
}
```

## Analytics

Flodar continuously aggregates flow records into three sliding windows and emits a `window_metrics` log event on every snapshot interval (default: every 10 s):

| Window | Covers |
|---|---|
| 10 s | Last 10 seconds |
| 60 s | Last 1 minute |
| 300 s | Last 5 minutes |

Each snapshot includes:

| Field | Description |
|---|---|
| `window_secs` | Window duration |
| `flows` | Flow records received in the window |
| `packets` | Total packets across all flows |
| `bytes` | Total bytes across all flows |
| `flows_per_sec` / `packets_per_sec` / `bytes_per_sec` | Per-second rates |
| `unique_src_ips` / `unique_dst_ips` | Distinct source/destination IPs |
| `top_src_ips` | Top 5 source IPs by bytes (`ip=bytes,...`) |
| `top_dst_ips` | Top 5 destination IPs by bytes (`ip=bytes,...`) |
| `protocol_dist` | Flow count per IANA protocol number (`proto=count,...`) |

## Detection

The detection engine evaluates each window snapshot against four threshold-based rules and logs a `WARN`-level `ALERT` line when one fires. All thresholds are configurable; no magic numbers exist in the rule logic.

### Alert format

```json
{
  "timestamp": "2026-03-07T00:00:12.000Z",
  "level": "WARN",
  "fields": {
    "rule": "udp_flood",
    "severity": "High",
    "target_ip": null,
    "window_secs": 10,
    "indicators": "packets/sec: 3400 (threshold: 1000) | UDP ratio: 92% of flows (threshold: 80%) | unique source IPs: 3400 (threshold: 10)",
    "message": "ALERT"
  }
}
```

Each `indicators` entry is a plain-English sentence with the observed value and the threshold that was crossed. Every alert contains at least two indicators.

### Rules

#### UDP Flood (`udp_flood`) — evaluated on 10 s window

Fires when ALL of:
- `packets_per_sec` ≥ `min_packets_per_sec` (default: 1000)
- UDP flows / total flows ≥ `min_udp_ratio` (default: 80%)
- `unique_src_ips` ≥ `min_unique_sources` (default: 10)

#### SYN Flood (`syn_flood`) — evaluated on 10 s window

Fires when ALL of:
- `packets_per_sec` ≥ `min_packets_per_sec` (default: 500)
- TCP flows with SYN set and ACK not set / total TCP flows ≥ `min_syn_ratio` (default: 70%)
- Average flow duration ≤ `max_avg_flow_duration_ms` (default: 500 ms)

#### Port Scan (`port_scan`) — evaluated on 60 s window

Fires when, for any single source IP:
- Distinct destination ports contacted ≥ `min_unique_dst_ports` (default: 50)
- Average bytes per flow ≤ `max_bytes_per_flow` (default: 100)

#### Destination Hotspot (`destination_hotspot`) — evaluated on 10 s window

Fires when:
- `bytes_per_sec` ≥ `min_bytes_per_sec` (default: 100)
- Top destination IP accounts for ≥ `min_traffic_ratio` (default: 80%) of total bytes in window

### Alert cooldown

Repeat alerts for the same `(rule, target_ip)` pair are suppressed for `cooldown_secs` (default: 60 s) to prevent log flooding during sustained attacks.

## Testing Without a Router

### Using flowgen

The `flowgen` binary generates synthetic NetFlow v5 traffic against a running Flodar instance.

**Normal traffic (no alerts expected):**

```bash
cargo run -p flowgen -- --flows 5 --repeat 5 --interval-ms 2000
```

**Attack simulation modes:**

```bash
# UDP flood — triggers udp_flood alert within ~20 s
cargo run -p flowgen -- --mode udp-flood --pps 2000 --duration-secs 30

# SYN flood — triggers syn_flood alert within ~20 s
cargo run -p flowgen -- --mode syn-flood --pps 1000 --duration-secs 30

# Port scan — triggers port_scan alert within ~65 s (60 s window)
cargo run -p flowgen -- --mode port-scan --src-ip 10.0.0.99 --ports 200 --duration-secs 60

# Destination hotspot — triggers destination_hotspot alert within ~20 s
cargo run -p flowgen -- --mode hotspot --dst-ip 1.1.1.1 --ratio 0.95 --duration-secs 30
```

**flowgen CLI reference:**

```
Usage: flowgen [OPTIONS]

Options:
      --target <TARGET>              Destination host:port [default: 127.0.0.1:2055]
      --mode <MODE>                  normal | udp-flood | syn-flood | port-scan | hotspot [default: normal]

Normal mode:
      --flows <FLOWS>                Flow records per batch [default: 5]
      --repeat <REPEAT>              Number of batches to send [default: 1]
      --interval-ms <INTERVAL_MS>    Milliseconds between batches [default: 1000]

Attack modes:
      --pps <PPS>                    Target packets-per-second (udp-flood, syn-flood) [default: 1000]
      --duration-secs <DURATION>     Duration of attack simulation [default: 30]
      --src-ip <SRC_IP>              Fixed source IP (port-scan) [default: 10.0.0.99]
      --ports <PORTS>                Unique destination ports to scan (port-scan) [default: 200]
      --dst-ip <DST_IP>              Hotspot destination IP [default: 1.1.1.1]
      --ratio <RATIO>                Fraction of traffic to hotspot IP (0.0–1.0) [default: 0.95]
```

### Using Python

Send a hand-crafted NetFlow v5 packet:

```python
import socket, struct

header = struct.pack(
    "!HHIIIIBBH",
    5, 1, 100000, 0, 0, 1, 0, 0, 0,
)

record = struct.pack(
    "!4s4s4sHHIIIIHHBBBBHBBH",
    bytes([10, 0, 0, 1]),
    bytes([10, 0, 0, 2]),
    bytes([0, 0, 0, 0]),
    0, 0, 10, 1400, 1000, 2000, 54321, 80,
    0, 0x18, 6, 0, 0, 0, 0, 0, 0,
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(header + record, ("127.0.0.1", 2055))
```

## Error Handling

Malformed or unsupported packets are logged as warnings and never crash the collector:

```json
{"level":"WARN","fields":{"exporter":"192.168.1.1:52000","error":"unsupported version: 9","message":"decode error"}}
```

Possible decode errors:

| Error | Cause |
|---|---|
| `unsupported version: N` | Packet is not NetFlow v5 (e.g. v9 or IPFIX) |
| `packet too short: expected N, got M` | Truncated or corrupt packet |
| `length mismatch: header count N, data fits M` | Record count in header doesn't match actual packet size |

## Running Tests

```bash
cargo test
```

33 unit tests across five modules:

| Module | Tests |
|---|---|
| `decoder::netflow_v5` | single record, multiple records, wrong version, truncated packet, length mismatch |
| `analytics::window` | push/compute, evict expired, keep fresh, protocol distribution |
| `detection::rules::udp_flood` | fires, no-fire on pps/ratio/sources, exact thresholds, indicator count |
| `detection::rules::syn_flood` | fires, no-fire on pps/ratio/duration/no-tcp, indicator count |
| `detection::rules::port_scan` | fires, no-fire on port count/bytes/window, correct target IP, indicator count |
| `detection::rules::destination_hotspot` | fires, no-fire on ratio/rate/no-bytes, correct target IP, indicator count |

## Pipeline

```
                          broadcast (FlowRecord)
FlowRecord ──────────────────────────────────────► analytics engine
     │                                                    │
     │ (SharedState)                           broadcast (WindowMetrics)
     ▼                                              ┌─────┴─────┐
SharedState ◄──────────────────────────────── log_metrics   detection engine
     │                                                          │
     ▼                                                     log_alert (WARN)
 api::run()
     │
     ├─ GET /metrics       (Prometheus text format)
     ├─ GET /health
     ├─ GET /api/summary
     ├─ GET /api/top-talkers
     └─ GET /api/alerts
```

## Project Layout

```
flodar/
 ├─ Cargo.toml                   workspace manifest
 ├─ docker/
 │  └─ Dockerfile                multi-stage build (debian:bookworm-slim runtime)
 ├─ grafana/
 │  └─ provisioning/
 │     ├─ datasources/
 │     │  └─ prometheus.yml      auto-configure Prometheus datasource
 │     └─ dashboards/
 │        ├─ dashboard.yml       dashboard provider config
 │        └─ flodar-overview.json  main dashboard (10 panels)
 ├─ examples/
 │  └─ prometheus.yml            ready-to-use Prometheus scrape config
 ├─ docs/
 │  └─ metrics.md
 ├─ flodar/
 │  ├─ flodar.toml               default configuration (also used in Docker image)
 │  └─ src/
 │     ├─ main.rs                 CLI, config loading, tracing init, task wiring
 │     ├─ collector/mod.rs        async UDP listener; broadcasts FlowRecords
 │     ├─ analytics/
 │     │  ├─ mod.rs               drives sliding windows, logs + broadcasts metrics
 │     │  ├─ metrics.rs           WindowMetrics struct and compute()
 │     │  └─ window.rs            SlidingWindow with push/evict/compute + tests
 │     ├─ decoder/
 │     │  ├─ flow_record.rs       FlowRecord struct
 │     │  └─ netflow_v5.rs        NetFlow v5 binary parser + tests
 │     ├─ detection/
 │     │  ├─ mod.rs               DetectionConfig, run() loop, alert cooldown
 │     │  ├─ alert.rs             Alert struct, Severity enum, log_alert()
 │     │  └─ rules/
 │     │     ├─ udp_flood.rs      UDP flood rule + tests
 │     │     ├─ syn_flood.rs      SYN flood rule + tests
 │     │     ├─ port_scan.rs      port scan rule + tests
 │     │     └─ destination_hotspot.rs  destination hotspot rule + tests
 │     └─ api/
 │        ├─ mod.rs               Axum router, run() entrypoint
 │        ├─ state.rs             AppState struct, SharedState type alias
 │        ├─ metrics.rs           FlodarMetrics — all prometheus metric handles
 │        └─ handlers.rs          HTTP route handler functions
 └─ flowgen/                      synthetic NetFlow v5 traffic generator
    └─ src/main.rs                normal + 4 attack simulation modes
```

## Loki logging (optional)

Build with the `loki` feature to enable log shipping to Grafana Loki:

```bash
cargo build --release --features loki
```

Then in `flodar.toml`:

```toml
[logging]
level = "info"
backend = "loki"
loki_url = "http://localhost:3100"

[logging.loki_labels]
job = "flodar"
host = "pi"
```

Stdout JSON logging remains active alongside the Loki stream. Only fixed-cardinality values belong in `loki_labels` — IPs, ports, and flow fields must never be label values.

If the Loki endpoint is unreachable at startup, Flodar logs a warning and continues with stdout only.

## What Flodar Does Not Do (v0.5)

- No NetFlow v9, IPFIX, or sFlow support
- No storage — logs and in-memory state only
- No authentication or TLS on the HTTP API
- No ML-based or statistical anomaly detection — all rules are threshold-based
