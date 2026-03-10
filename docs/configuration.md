# Configuration Reference

## Complete `flodar.toml`

The file below shows every available field with its default value.

```toml
# Flodar configuration — all fields shown with their default values.

[collector]
bind_address = "0.0.0.0"
bind_port = 2055
# accepted_versions = [5, 9, 10]  # omit to accept all supported versions
# bind_port_ipfix = 4739          # optional secondary IPFIX-only port

[logging]
level = "info"       # trace | debug | info | warn | error
format = "json"      # json | pretty

[analytics]
snapshot_interval_secs = 10

[detection]
enabled = true
cooldown_secs = 60

[detection.udp_flood]
enabled = true
min_packets_per_sec = 1000.0
min_udp_ratio = 0.80
min_unique_sources = 10

[detection.syn_flood]
enabled = true
min_packets_per_sec = 500.0
min_syn_ratio = 0.70
max_avg_flow_duration_ms = 500

[detection.port_scan]
enabled = true
min_unique_dst_ports = 50
max_bytes_per_flow = 100.0

[detection.destination_hotspot]
enabled = true
min_traffic_ratio = 0.80
min_bytes_per_sec = 100.0

[api]
bind_address = "0.0.0.0"
bind_port = 9090
enabled = true

# [storage]
# enabled = true
# flow_db_path = "~/.local/share/flodar/flodar_flows.duckdb"   # default
# alert_db_path = "~/.local/share/flodar/flodar_alerts.db"     # default

# [webhook]
# enabled = true
# url = "https://your-endpoint.example.com/hook"
# timeout_secs = 5
# retry_attempts = 1
```

---

## `[collector]`

| Field | Type | Default | Description |
|---|---|---|---|
| `bind_address` | string | `"0.0.0.0"` | IP address to bind the UDP collector socket on. Use `"0.0.0.0"` to accept from all interfaces. |
| `bind_port` | integer | `2055` | UDP port to receive NetFlow and IPFIX datagrams. The IANA-assigned port for NetFlow is 2055; some vendors default to 9996. Must be 1–65535. |
| `accepted_versions` | array of integers | `[]` (all) | Restrict which NetFlow protocol versions are processed. Valid values are `5`, `9`, and `10` (IPFIX). Omit the field or set an empty array to accept all three. Packets with other version numbers are silently dropped. |
| `bind_port_ipfix` | integer | absent | Optional secondary UDP port that accepts only IPFIX (version 10) packets. Useful when your router sends NetFlow v9 to one port and IPFIX to another. |

**When to change `bind_port`**: Change this when your router is already configured to export to a specific port and you cannot modify the router config. Common alternatives are `9995`, `9996`, and `4739` (the IANA IPFIX port).

---

## `[logging]`

| Field | Type | Default | Description |
|---|---|---|---|
| `level` | string | `"info"` | Minimum log level. One of `trace`, `debug`, `info`, `warn`, `error`. Can be overridden at runtime with `RUST_LOG`. |
| `format` | string | `"json"` | Log output format. `json` emits structured JSON objects suitable for log aggregators. `pretty` emits human-readable output with colour for local development. |
| `backend` | string | absent | Set to `"loki"` to forward logs to Grafana Loki. Requires the `loki` compile-time feature (`cargo build --features loki`). |
| `loki_url` | string | `"http://localhost:3100"` | Loki push URL. Only used when `backend = "loki"`. |
| `loki_labels` | table | absent | Fixed key-value labels attached to every Loki log stream. See the Loki label cardinality note in [docs/metrics.md](metrics.md). |

---

## `[analytics]`

| Field | Type | Default | Description |
|---|---|---|---|
| `snapshot_interval_secs` | integer | `10` | How often (in seconds) the analytics engine emits a `WindowMetrics` snapshot to the detection engine. Must be > 0. Lowering this value increases detection responsiveness at the cost of more frequent rule evaluations. |

---

## `[detection]`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Master switch for the entire detection engine. Set to `false` to run flodar as a pure collector/metrics exporter without any alert logic. |
| `cooldown_secs` | integer | `60` | Minimum seconds between two alerts for the same (rule, target IP) pair. Prevents alert storms when an attack persists. Must be > 0; use a large value like `3600` to effectively disable cooldown. |

---

## `[detection.udp_flood]`

Fires on the 10-second window when all three conditions are simultaneously true.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable or disable this rule independently. |
| `min_packets_per_sec` | float | `1000.0` | Fire the UDP flood rule only when the 10 s window contains at least this many packets per second. Set higher on transit links where 1 000 pps is normal background traffic. |
| `min_udp_ratio` | float | `0.80` | Fire only when UDP traffic makes up at least this fraction (0.0–1.0) of all flows in the window. Set lower (e.g. `0.60`) on networks with naturally high UDP traffic such as gaming or VoIP to reduce false positives, or higher (e.g. `0.95`) on networks where UDP should be rare. |
| `min_unique_sources` | integer | `10` | Fire only when at least this many distinct source IPs contributed to the flood. This separates a volumetric DDoS (many sources) from a single misconfigured device. |

---

## `[detection.syn_flood]`

Fires on the 10-second window when all three conditions are simultaneously true.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable or disable this rule independently. |
| `min_packets_per_sec` | float | `500.0` | Fire only when the window contains at least this many packets per second. SYN floods often use smaller packets than UDP floods, so the default is lower than the UDP flood threshold. |
| `min_syn_ratio` | float | `0.70` | Fire only when SYN-only flows make up at least this fraction of all TCP flows in the window. A SYN-only flow is one where the SYN flag is set but ACK is not — indicating a connection that never completed the three-way handshake. Lower this value (e.g. `0.50`) if your network has legitimate half-open connections that you still want to detect. |
| `max_avg_flow_duration_ms` | integer | `500` | Fire only when the average flow duration is at most this many milliseconds. SYN flood flows are extremely short-lived because the connection is never established. Raise this value if your router reports flow durations inconsistently. |

---

## `[detection.port_scan]`

Fires on the 60-second window when both conditions are simultaneously true.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable or disable this rule independently. |
| `min_unique_dst_ports` | integer | `50` | Fire when any single source IP contacts at least this many distinct destination ports in the 60 s window. A port scan probing 50 different ports in a minute is a strong indicator of reconnaissance activity. Raise this on networks with service discovery tools that legitimately probe many ports. |
| `max_bytes_per_flow` | float | `100.0` | Fire only when the average bytes per flow is at most this value. Probe packets are small — typically just a TCP SYN or ICMP echo. Large flows are legitimate connections, not probes. This threshold prevents false positives from busy servers that happen to contact many ports. |

---

## `[detection.destination_hotspot]`

Fires on the 10-second window when both conditions are simultaneously true.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable or disable this rule independently. |
| `min_traffic_ratio` | float | `0.80` | Fire when a single destination IP receives at least this fraction (0.0–1.0) of total bytes in the window. A ratio of 0.80 means one destination is absorbing 80% of all traffic, which indicates a concentrated attack or exfiltration. Lower this value on networks with known high-volume destinations like a CDN origin. |
| `min_bytes_per_sec` | float | `100.0` | Fire only when the overall traffic rate is at least this many bytes per second. This suppresses spurious alerts during near-idle periods when a single low-volume flow can trivially account for 80% of almost-nothing. |

---

## `[api]`

| Field | Type | Default | Description |
|---|---|---|---|
| `bind_address` | string | `"0.0.0.0"` | IP address to bind the HTTP API server on. |
| `bind_port` | integer | `9090` | TCP port for the HTTP API and `/metrics` endpoint. |
| `enabled` | boolean | `true` | Set to `false` to disable the HTTP server entirely, useful in headless collector-only deployments. |

---

## `[storage]`

Storage is disabled by default. Enable it to persist flow records and alerts across restarts.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Master switch for persistent storage. When `false`, `GET /api/alerts` reads from the in-memory ring buffer and `GET /api/flows` returns 501. |
| `flow_db_path` | string | `~/.local/share/flodar/flodar_flows.duckdb` | File path for the DuckDB flow store. The directory is created automatically on first run. Override with any absolute path. |
| `alert_db_path` | string | `~/.local/share/flodar/flodar_alerts.db` | File path for the SQLite alert store. The directory is created automatically on first run. Override with any absolute path. |

---

## `[webhook]`

The entire `[webhook]` section is optional. When absent, no webhook delivery is attempted.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Set to `false` to disable delivery without removing the section. |
| `url` | string | required | The HTTP or HTTPS URL to POST alert JSON to. Must start with `http://` or `https://`. Validated at startup. |
| `timeout_secs` | integer | `5` | Per-request timeout in seconds. Requests that exceed this limit are abandoned and counted as failures. |
| `retry_attempts` | integer | `1` | Number of additional delivery attempts after the first failure. A value of `1` means the alert is tried twice in total. Set to `0` for a single best-effort delivery with no retries. |

---

## Minimal config

The smallest valid `flodar.toml` that starts the collector on standard ports with console-friendly output:

```toml
[collector]
bind_address = "0.0.0.0"
bind_port = 2055

[logging]
level = "info"
format = "pretty"
```

This relies on the following defaults:
- Analytics snapshot every 10 seconds
- Detection engine enabled with all four rules at default thresholds
- HTTP API on `0.0.0.0:9090`
- No persistent storage (in-memory alert ring buffer only)
- No webhook delivery
