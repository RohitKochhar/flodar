# Metrics and API Reference

## Prometheus metrics

Flodar exposes all metrics at `GET /metrics` in the Prometheus text exposition format (version 0.0.4). The endpoint is always available when the API is enabled.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `flodar_flows_total` | Counter | — | Total flow records successfully decoded and ingested since startup. |
| `flodar_packets_total` | Counter | — | Total packets across all ingested flow records since startup. |
| `flodar_bytes_total` | Counter | — | Total bytes across all ingested flow records since startup. |
| `flodar_alerts_total` | Counter | `rule` | Alerts fired per detection rule. The `rule` label value is one of `udp_flood`, `syn_flood`, `port_scan`, `destination_hotspot`. |
| `flodar_active_exporters` | Gauge | — | Number of distinct exporter IPs that sent at least one packet in the last 5 minutes. |
| `flodar_flows_per_sec` | Gauge | `window` | Flow ingestion rate for the given sliding window. The `window` label is `10s`, `60s`, or `300s`. |
| `flodar_packets_per_sec` | Gauge | `window` | Packet rate for the given sliding window. The `window` label is `10s`, `60s`, or `300s`. |
| `flodar_bytes_per_sec` | Gauge | `window` | Byte throughput for the given sliding window. The `window` label is `10s`, `60s`, or `300s`. |
| `flodar_unique_src_ips` | Gauge | `window` | Number of unique source IPs seen in the given sliding window. The `window` label is `10s`, `60s`, or `300s`. |
| `flodar_unique_dst_ips` | Gauge | `window` | Number of unique destination IPs seen in the given sliding window. The `window` label is `10s`, `60s`, or `300s`. |

---

## HTTP API reference

### `GET /health`

Returns the service status and version.

**Query parameters**: none

**Example response** (`200 OK`):

```json
{
  "status": "ok",
  "uptime_secs": 3600,
  "version": "1.0.0-beta"
}
```

**Error cases**: This endpoint always returns 200. It does not depend on storage or the analytics pipeline.

---

### `GET /metrics`

Returns all registered Prometheus metrics in text exposition format.

**Query parameters**: none

**Response**: `text/plain; version=0.0.4` — standard Prometheus scrape format.

**Error cases**: Returns an empty body on internal encoding failure (not expected in practice).

---

### `GET /api/summary`

Returns a snapshot of the 10-second sliding window.

**Query parameters**: none

**Example response** (`200 OK`):

```json
{
  "window_secs": 10,
  "flows_per_sec": 42.3,
  "packets_per_sec": 1234.0,
  "bytes_per_sec": 98304.0,
  "unique_src_ips": 15,
  "unique_dst_ips": 8,
  "active_exporters": 2,
  "uptime_secs": 3600
}
```

**Error cases**:

- `503 Service Unavailable` — returned with `{"status": "no data"}` when the analytics engine has not yet emitted its first 10 s snapshot (typically in the first 10 seconds after startup).

---

### `GET /api/top-talkers`

Returns the top 5 source and destination IPs by byte volume from the 60-second sliding window.

**Query parameters**: none

**Example response** (`200 OK`):

```json
{
  "window_secs": 60,
  "top_sources": [
    {"ip": "10.0.0.5", "bytes": 1048576, "bytes_per_sec": 17476.3},
    {"ip": "10.0.0.12", "bytes": 524288, "bytes_per_sec": 8738.1}
  ],
  "top_destinations": [
    {"ip": "203.0.113.1", "bytes": 786432, "bytes_per_sec": 13107.2}
  ]
}
```

**Error cases**:

- `503 Service Unavailable` — returned with `{"status": "no data"}` when the 60 s window is not yet populated.

---

### `GET /api/alerts`

Returns recent alerts. Reads from the SQLite alert store when storage is enabled; falls back to the in-memory ring buffer (up to 100 entries) when storage is disabled.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | `20` | Maximum number of alerts to return. Capped at 100. |
| `rule` | string | — | Filter to alerts from the named rule (e.g. `udp_flood`). |
| `ip` | string (IPv4) | — | Filter to alerts whose `target_ip` matches this address. |

**Example response** (`200 OK`):

```json
{
  "total": 2,
  "alerts": [
    {
      "id": 42,
      "rule": "udp_flood",
      "severity": "High",
      "target_ip": null,
      "window_secs": 10,
      "indicators": [
        "packets/sec: 2341 (threshold: 1000)",
        "UDP ratio: 94% of flows (threshold: 80%)",
        "unique source IPs: 27 (threshold: 10)"
      ],
      "triggered_at": "2026-03-10T12:00:00Z"
    }
  ]
}
```

**Error cases**: Returns an empty `alerts` array on store query failure (falls back to in-memory).

---

### `GET /api/alerts/:id`

Returns a single alert by its SQLite row ID.

**Path parameters**: `:id` — integer, the `id` field returned by `GET /api/alerts`.

**Query parameters**: none

**Example response** (`200 OK`): Same object shape as a single entry in `GET /api/alerts`.

**Error cases**:

- `404 Not Found` — `{"error": "alert 99 not found"}` when no alert with that ID exists.
- `501 Not Implemented` — `{"error": "alert storage is not enabled", "hint": "set [storage] enabled = true in flodar.toml"}` when storage is disabled.
- `500 Internal Server Error` — `{"error": "..."}` on unexpected store failure.

---

### `GET /api/flows`

Returns persisted flow records from the DuckDB flow store.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `start` | string (RFC 3339) | 1 hour before `end` | Start of the time range, e.g. `2026-03-10T00:00:00Z`. |
| `end` | string (RFC 3339) | current time | End of the time range, e.g. `2026-03-10T01:00:00Z`. |
| `limit` | integer | `100` | Maximum number of flow records to return. Capped at 1000. |

**Example response** (`200 OK`):

```json
{
  "total": 3,
  "flows": [
    {
      "src_ip": "10.0.0.5",
      "dst_ip": "203.0.113.1",
      "src_port": 51234,
      "dst_port": 443,
      "protocol": 6,
      "packets": 12,
      "bytes": 8192,
      "received_at": "2026-03-10T00:01:05Z"
    }
  ]
}
```

**Error cases**:

- `501 Not Implemented` — `{"error": "flow storage is not enabled", "hint": "set [storage] enabled = true in flodar.toml"}` when storage is disabled.
- `500 Internal Server Error` — `{"error": "..."}` on unexpected store failure.

---

## Grafana

The `grafana/` directory contains a provisioned datasource and dashboard JSON. Configure Grafana with `--config.provisioning-path=grafana/provisioning` (or set `GF_PATHS_PROVISIONING` to that directory) to load them automatically — no manual import or UI interaction is required. The dashboard covers all 10 Prometheus metric families and includes per-window traffic rate panels and alert rate panels labeled by rule.

---

## Loki

When compiled with `--features loki` and configured with `[logging] backend = "loki"`, Flodar forwards all structured log events to Grafana Loki. Keep label cardinality low: only fixed-cardinality values (e.g. `env = "prod"`, `host = "router1"`) belong in `loki_labels`. Never use IP addresses, port numbers, or flow field values as Loki label values — each unique label combination creates a separate log stream, and high-cardinality streams degrade Loki performance significantly.
