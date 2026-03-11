# API Reference

Flodar exposes an HTTP API on `0.0.0.0:9090` by default (configurable via `[api]` in `flodar.toml`). All JSON responses use `Content-Type: application/json`.

---

## `GET /health`

Returns the current service status, uptime, and version string.

**Query parameters**: none

**Example request**:

```
GET /health HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`):

```json
{
  "status": "ok",
  "uptime_secs": 3600,
  "version": "1.0.0-beta"
}
```

**Error responses**: This endpoint always returns `200 OK`. It does not depend on the analytics pipeline or storage backends.

---

## `GET /metrics`

Returns all registered Prometheus metrics in text exposition format (version 0.0.4). This is the standard Prometheus scrape target.

**Query parameters**: none

**Example request**:

```
GET /metrics HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`, `Content-Type: text/plain; version=0.0.4`):

```
# HELP flodar_flows_total Total flow records ingested
# TYPE flodar_flows_total counter
flodar_flows_total 148392
# HELP flodar_alerts_total Alerts fired per rule
# TYPE flodar_alerts_total counter
flodar_alerts_total{rule="udp_flood"} 3
flodar_alerts_total{rule="port_scan"} 1
...
```

**Error responses**: Returns an empty body on internal encoding failure (not expected in practice).

---

## `GET /api/summary`

Returns a snapshot of the 10-second sliding window, including traffic rates, unique IP counts, active exporter count, and server uptime.

**Query parameters**: none

**Example request**:

```
GET /api/summary HTTP/1.1
Host: localhost:9090
```

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

**Error responses**:

- `503 Service Unavailable` — `{"status": "no data"}` when the analytics engine has not yet produced its first 10-second snapshot (typically within the first 10 seconds after startup).

---

## `GET /api/top-talkers`

Returns the top 5 source and destination IP addresses by byte volume from the 60-second sliding window.

**Query parameters**: none

**Example request**:

```
GET /api/top-talkers HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`):

```json
{
  "window_secs": 60,
  "top_sources": [
    {
      "ip": "10.0.0.5",
      "bytes": 1048576,
      "bytes_per_sec": 17476.3
    },
    {
      "ip": "10.0.0.12",
      "bytes": 524288,
      "bytes_per_sec": 8738.1
    }
  ],
  "top_destinations": [
    {
      "ip": "203.0.113.1",
      "bytes": 786432,
      "bytes_per_sec": 13107.2
    }
  ]
}
```

**Error responses**:

- `503 Service Unavailable` — `{"status": "no data"}` when the 60-second window has not yet been populated.

---

## `GET /api/alerts`

Returns recent alerts. When `[storage] enabled = true`, reads from the persistent SQLite alert store. Otherwise reads from the in-memory ring buffer (last 100 alerts).

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | `20` | Maximum number of alerts to return. Capped at `100`. |
| `rule` | string | — | Filter results to a specific rule name, e.g. `udp_flood`, `syn_flood`, `port_scan`, or `destination_hotspot`. |
| `ip` | string | — | Filter results to alerts whose `target_ip` matches this IPv4 address. |

**Example request**:

```
GET /api/alerts?limit=5&rule=udp_flood HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`):

```json
{
  "total": 1,
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
        "unique source IPs: 27 (threshold: 10)",
        "unique destination IPs: 4",
        "top destination IPs: 203.0.113.1(458752B)"
      ],
      "triggered_at": "2026-03-10T12:00:00Z"
    }
  ]
}
```

**Notes**:

- `id` is `null` when storage is disabled (in-memory alerts have no persistent ID).
- `target_ip` is `null` for rules that are not tied to a specific source (e.g. `udp_flood`, `syn_flood`).
- Results are returned newest first.

**Error responses**:

- `400 Bad Request` — `{"error": "invalid IP address"}` when the `ip` parameter is not a valid IPv4 address.

---

## `GET /api/alerts/:id`

Returns a single alert by its SQLite row ID. Only available when `[storage] enabled = true`.

**Path parameters**:

| Parameter | Type | Description |
|---|---|---|
| `id` | integer | The numeric `id` field from `GET /api/alerts`. |

**Query parameters**: none

**Example request**:

```
GET /api/alerts/42 HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`):

```json
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
```

**Error responses**:

- `404 Not Found` — `{"error": "alert 42 not found"}` when no alert with that ID exists in the store.
- `501 Not Implemented` — `{"error": "alert storage is not enabled", "hint": "set [storage] enabled = true in flodar.toml"}` when storage is disabled.
- `500 Internal Server Error` — `{"error": "..."}` on unexpected store failure.

---

## `GET /api/flows`

Returns persisted flow records from the DuckDB flow store within a specified time range. Only available when `[storage] enabled = true`.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `start` | string (RFC 3339) | 1 hour before `end` | Start of the query time range, e.g. `2026-03-10T00:00:00Z`. |
| `end` | string (RFC 3339) | current server time | End of the query time range, e.g. `2026-03-10T01:00:00Z`. |
| `limit` | integer | `100` | Maximum number of flow records to return. Capped at `1000`. |

**Example request**:

```
GET /api/flows?start=2026-03-10T00:00:00Z&end=2026-03-10T00:05:00Z&limit=10 HTTP/1.1
Host: localhost:9090
```

**Example response** (`200 OK`):

```json
{
  "total": 2,
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
    },
    {
      "src_ip": "10.0.0.12",
      "dst_ip": "8.8.8.8",
      "src_port": 60001,
      "dst_port": 53,
      "protocol": 17,
      "packets": 1,
      "bytes": 72,
      "received_at": "2026-03-10T00:02:11Z"
    }
  ]
}
```

**Notes**:

- `protocol` is the IANA protocol number: `6` = TCP, `17` = UDP, `1` = ICMP.
- `received_at` is the time the flodar collector received the flow record from the exporter, not the flow start time as reported by the exporter.
- If `start` or `end` cannot be parsed as RFC 3339, the field is silently replaced with its default value.

**Error responses**:

- `501 Not Implemented` — `{"error": "flow storage is not enabled", "hint": "set [storage] enabled = true in flodar.toml"}` when storage is disabled.
- `500 Internal Server Error` — `{"error": "..."}` on unexpected store failure.
