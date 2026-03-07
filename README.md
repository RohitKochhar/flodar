# Flodar

Lightweight network flow collector written in Rust. Receives NetFlow v5 over UDP, decodes each packet, emits one structured JSON log line per flow record, and continuously computes sliding-window traffic analytics.

## Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs))
- A router, switch, or traffic generator exporting NetFlow v5 to UDP port 2055

## Quickstart

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

Example JSON output:

```json
{
  "timestamp": "2026-03-07T00:00:10.000Z",
  "level": "INFO",
  "fields": {
    "window_secs": 60,
    "flows": 120,
    "packets": 1440,
    "bytes": 5990400,
    "flows_per_sec": 2.0,
    "packets_per_sec": 24.0,
    "bytes_per_sec": 99840.0,
    "unique_src_ips": 5,
    "unique_dst_ips": 1,
    "top_src_ips": "10.0.0.5=1198080,10.0.0.6=1198080,10.0.0.7=1198080,10.0.0.8=1198080,10.0.0.9=1198080",
    "top_dst_ips": "1.1.1.1=5990400",
    "protocol_dist": "6=120",
    "message": "window_metrics"
  }
}
```

If the analytics receiver falls behind the collector, dropped record counts are logged as warnings:

```json
{"level":"WARN","fields":{"dropped":42,"message":"analytics receiver lagged, records dropped"}}
```

## Testing Without a Router

Send a hand-crafted NetFlow v5 packet using Python:

```python
import socket, struct

# NetFlow v5 header (24 bytes)
header = struct.pack(
    "!HHIIIIBBH",
    5,          # version
    1,          # count (1 record)
    100000,     # sysuptime (ms)
    0,          # unix seconds
    0,          # unix nanoseconds
    1,          # flow sequence
    0,          # engine type
    0,          # engine id
    0,          # sampling interval
)

# Flow record (48 bytes)
record = struct.pack(
    "!4s4s4sHHIIIIHHBBBBHBBH",
    bytes([10, 0, 0, 1]),    # src ip
    bytes([10, 0, 0, 2]),    # dst ip
    bytes([0, 0, 0, 0]),     # next hop
    0, 0,                    # input/output SNMP
    10,                      # packets
    1400,                    # bytes
    1000,                    # start_time
    2000,                    # end_time
    54321,                   # src port
    80,                      # dst port
    0,                       # padding
    0x18,                    # tcp flags (PSH+ACK)
    6,                       # protocol (TCP)
    0,                       # ToS
    0, 0, 0, 0, 0,           # AS + masks + padding
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(header + record, ("127.0.0.1", 2055))
print("Sent 1 NetFlow v5 record")
```

Run Flodar in one terminal, send the packet from another, and confirm the JSON log line appears.

### Using flowgen

The `flowgen` binary generates synthetic NetFlow v5 traffic against a running Flodar instance:

```bash
cargo run -p flowgen -- --help
```

```
Usage: flowgen [OPTIONS]

Options:
      --target <TARGET>          Destination host:port [default: 127.0.0.1:2055]
      --flows <FLOWS>            Number of flow records per batch [default: 5]
      --repeat <REPEAT>          Number of times to send the packet batch [default: 1]
      --interval-ms <INTERVAL_MS>  Milliseconds to wait between sends [default: 1000]
  -h, --help                     Print help
```

Send 100 flows in 10 batches of 10, one batch per second:

```bash
cargo run -p flowgen -- --flows 10 --repeat 10 --interval-ms 1000
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

## Project Layout

```
flodar/
 ├─ Cargo.toml                   workspace manifest
 ├─ flodar.toml                   default configuration
 ├─ flodar/
 │  └─ src/
 │     ├─ main.rs                 CLI, config loading, tracing init
 │     ├─ collector/mod.rs        async UDP listener; broadcasts FlowRecords
 │     ├─ analytics/
 │     │  ├─ mod.rs               drives sliding windows, logs metrics on interval
 │     │  ├─ metrics.rs           WindowMetrics struct and compute()
 │     │  └─ window.rs            SlidingWindow with push/evict/compute + tests
 │     └─ decoder/
 │        ├─ flow_record.rs       FlowRecord struct
 │        └─ netflow_v5.rs        NetFlow v5 binary parser + tests
 └─ flowgen/                      synthetic NetFlow v5 traffic generator
    └─ src/main.rs                CLI: --target, --flows, --repeat, --interval-ms
```

## Running Tests

```bash
cargo test
```

The parser has unit tests covering: single record, multiple records, wrong version, truncated packet, and header/length mismatch.

The analytics module has unit tests covering: push and compute, expired record eviction, fresh record retention, and protocol distribution.

## What Flodar Does Not Do (v0.2)

- No NetFlow v9, IPFIX, or sFlow support
- No storage — logs only
- No HTTP API or Prometheus metrics
- No anomaly detection
