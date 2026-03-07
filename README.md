# Flodar

Lightweight network flow collector written in Rust. Receives NetFlow v5 over UDP, decodes each packet, and emits one structured JSON log line per flow record.

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
 │     ├─ collector/mod.rs        async UDP listener loop
 │     └─ decoder/
 │        ├─ flow_record.rs       FlowRecord struct
 │        └─ netflow_v5.rs        NetFlow v5 binary parser + tests
 └─ flowgen/                      traffic generator (not yet implemented)
```

## Running Tests

```bash
cargo test
```

The parser has unit tests covering: single record, multiple records, wrong version, truncated packet, and header/length mismatch.

## What Flodar Does Not Do (v0.1)

- No NetFlow v9, IPFIX, or sFlow support
- No storage — logs only
- No HTTP API or Prometheus metrics
- No anomaly detection or analytics
