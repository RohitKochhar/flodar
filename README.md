[![CI](https://github.com/RohitKochhar/flodar/actions/workflows/ci.yml/badge.svg)](https://github.com/RohitKochhar/flodar/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# Flodar

There's a gap in open-source network telemetry. Enterprise platforms require Kafka and ClickHouse. Simple collectors forward raw packets and leave analysis to you. Flodar sits in between — a single binary that ingests NetFlow v5/v9 and IPFIX from your router, computes sliding-window traffic analytics, detects common attack patterns, and exposes everything to Prometheus and Grafana. Local flow and alert history in DuckDB and SQLite. Webhook delivery for real-time notifications. Runs on a Raspberry Pi 4.

## Quick start — Docker

```bash
git clone https://github.com/RohitKochhar/flodar
cd flodar
docker build -t flodar .
docker run -p 2055:2055/udp -p 9090:9090 flodar
```

Then open http://localhost:9090/health and http://localhost:9090/metrics.

## Quick start — Bare metal

```bash
cargo build --release
./target/release/flodar
```

## Configuration

Flodar is configured via `flodar.toml`. Most settings have sensible defaults — the minimal config below is enough to get started.

```toml
[collector]
bind_address = "0.0.0.0"
bind_port = 2055

[logging]
level = "info"
format = "pretty"
```

See [docs/configuration.md](docs/configuration.md) for all options.

## Grafana dashboard

The `grafana/` directory contains a provisioned dashboard and datasource that are automatically loaded when you run the Docker Compose stack — no manual import required. See [docs/metrics.md](docs/metrics.md) for the full metric reference.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Metrics reference](docs/metrics.md)
- [API reference](docs/api.md)
- [Architecture](docs/architecture.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
