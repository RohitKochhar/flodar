# Changelog

## [1.0-beta] – 2026-03-10

### Added
- Human-readable pretty-print alert format (`--log-format pretty` now renders a structured block instead of a single WARN line)
- Startup configuration summary banner — logged at INFO on every launch to confirm config was read correctly
- Graceful shutdown on SIGTERM/SIGINT: logs `reason = "signal"` at INFO and allows up to 2 s for in-flight storage writes to flush

### Changed
- Config validation now runs before any socket is bound — invalid config exits immediately with a descriptive error message and code 1
- `detection.cooldown_secs = 0` is now a validation error (use a large value to effectively disable cooldown)
- Webhook URL must be a valid HTTP or HTTPS URL when `webhook.enabled = true`

### Fixed
- Replaced `expect("alert serialization failed")` in `webhook::deliver` with proper error logging — no silent panics in production code paths

---

## [0.7.0] – 2026-03-08

### Added
- Webhook delivery: when `[webhook] enabled = true`, every fired alert is POSTed as JSON to the configured URL with configurable timeout and retry count
- SQLite alert store: alerts are persisted to a local SQLite database via `sqlx` when `[storage] enabled = true`
- DuckDB flow store: raw flow records are persisted to a local DuckDB database when `[storage] enabled = true`
- Alert IDs: `Alert.id` is populated from the SQLite row ID after insert, enabling stable references
- `GET /api/alerts/:id` endpoint: retrieves a single alert by its SQLite row ID; returns 404 if not found, 501 if storage is disabled
- CI caching: GitHub Actions workflow now caches the Cargo registry and build artifacts to reduce average CI time

---

## [0.6.0]

### Added
- IPFIX (RFC 7011) decoding: flodar now accepts IPFIX packets in addition to NetFlow v5 and v9
- NetFlow v9 decoding: template-based NetFlow v9 packet parsing
- Template cache: `TemplateCache` stores per-exporter, per-observation-domain templates for NetFlow v9 and IPFIX; templates are retained across packets from the same exporter

---

## [0.5.0]

### Added
- Docker support: `Dockerfile` and `docker-compose.yml` for containerised deployment
- Grafana provisioning: dashboard and datasource JSON files in `grafana/` are automatically loaded by the Compose stack
- Optional Loki adapter: compile with `--features loki` to forward structured logs to a Grafana Loki instance; configured via `[logging] backend = "loki"`

---

## [0.4.0]

### Added
- Prometheus `/metrics` endpoint exposing 10 metric families (counters, gauges, per-window gauges)
- HTTP API server (Axum): `/health`, `/api/summary`, `/api/top-talkers`, `/api/alerts`, `/api/flows`
- `docs/metrics.md`: Prometheus metric reference

---

## [0.3.0]

### Added
- Detection engine: evaluates `WindowMetrics` snapshots against configurable rule thresholds
- Four built-in rules: `udp_flood`, `syn_flood`, `port_scan`, `destination_hotspot`
- Explainable alerts: each `Alert` carries an `indicators` list describing exactly which thresholds were exceeded and by how much
- Per-rule cooldown: duplicate alerts for the same (rule, target IP) are suppressed for `detection.cooldown_secs` seconds

---

## [0.2.0]

### Added
- Sliding window analytics: three independent `SlidingWindow` instances computing 10 s, 60 s, and 300 s metrics
- `WindowMetrics` type: flows/packets/bytes rates, unique source and destination IPs, protocol distribution, TCP flood fields, per-source destination port sets
- `analytics::run()` task that broadcasts `WindowMetrics` on a configurable snapshot interval

---

## [0.1.0]

### Added
- UDP ingestion loop: binds a UDP socket and receives raw NetFlow v5 datagrams
- `FlowRecord` type: decoded flow with src/dst IP, src/dst port, protocol, packets, bytes, TCP flags, exporter IP, and received timestamp
- Structured JSON logging via `tracing` + `tracing-subscriber`
