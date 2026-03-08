# Flodar Test Suite

## Overview

Flodar has two layers of tests, both run automatically by CI on every pull request.

| Layer | Command | What it covers |
|-------|---------|----------------|
| Unit tests | `cargo test --workspace --lib --bins` | Individual functions and modules in isolation |
| Integration tests | `cargo test --test integration --package flodar` | Full async pipeline end-to-end |

---

## Unit Tests (`flodar/src/**`)

Unit tests live alongside the source they test, inside `#[cfg(test)]` blocks.
Run them with `cargo test --workspace --lib --bins`.

### Decoder

| Test | What it checks |
|------|---------------|
| `netflow_v5::test_parse_single_record` | A well-formed v5 packet with one record decodes to the correct `FlowRecord` fields |
| `netflow_v5::test_parse_multiple_records` | A v5 packet with multiple records decodes all of them |
| `netflow_v5::test_too_short` | A packet shorter than the minimum header returns `TooShort` error |
| `netflow_v5::test_length_mismatch` | Header count field disagrees with payload length — handled gracefully |
| `netflow_v5::test_unsupported_version` | Version byte != 5 returns `UnsupportedVersion` error |
| `netflow_v9::test_parse_template_flowset_inserts_into_cache` | A template flowset (ID=0) is parsed and stored in the template cache with the correct fields |
| `netflow_v9::test_parse_data_flowset_correct_records` | A data flowset following a template flowset decodes to the correct `FlowRecord` fields |
| `netflow_v9::test_data_flowset_before_template_returns_empty` | A data flowset arriving before its template is silently discarded (returns empty vec, no error) |
| `ipfix::test_parse_template_set_with_enterprise_field` | An IPFIX template set containing a vendor-specific (enterprise) field is stored correctly; the enterprise bit and PEN are recorded |
| `ipfix::test_parse_data_set_correct_records` | A data set following an IPFIX template set decodes to the correct `FlowRecord` fields |
| `ipfix::test_data_set_before_template_returns_empty` | A data set arriving before its template is silently discarded |
| `template_cache::test_insert_and_retrieve` | A template inserted into the cache can be retrieved by its key |
| `template_cache::test_replace_existing_key` | Inserting a template with the same key replaces the previous entry |

### Analytics

| Test | What it checks |
|------|---------------|
| `window::push_and_compute` | Flow records pushed into a sliding window produce correct per-second rates and IP counts |
| `window::protocol_distribution` | The protocol distribution map correctly tallies flows by protocol number |
| `window::evict_keeps_fresh_records` | Records younger than the window duration are retained on eviction |
| `window::evict_expired_removes_old_records` | Records older than the window duration are removed on eviction |

### Detection Rules

| Test | What it checks |
|------|---------------|
| `udp_flood::fires_when_all_conditions_met` | Alert fires when packets/sec, UDP ratio, and unique source IPs all meet thresholds |
| `udp_flood::fires_at_exact_thresholds` | Alert fires at exactly the configured threshold values (boundary condition) |
| `udp_flood::no_fire_when_pps_below_threshold` | No alert when packets/sec is 1 below threshold |
| `udp_flood::no_fire_when_udp_ratio_too_low` | No alert when UDP-to-total flow ratio is below threshold |
| `udp_flood::no_fire_when_too_few_sources` | No alert when unique source IP count is below threshold |
| `udp_flood::alert_has_at_least_two_indicators` | Fired alert contains at least two human-readable indicator strings |
| `syn_flood::fires_when_all_conditions_met` | Alert fires when packets/sec, SYN ratio, and average flow duration all meet thresholds |
| `syn_flood::no_fire_when_pps_too_low` | No alert when packets/sec is below threshold |
| `syn_flood::no_fire_when_syn_ratio_too_low` | No alert when SYN-only ratio is below threshold |
| `syn_flood::no_fire_when_flow_duration_too_long` | No alert when average TCP flow duration exceeds the maximum (flows are too long to be SYN floods) |
| `syn_flood::no_fire_when_no_tcp_flows` | No alert when there are no TCP flows at all |
| `syn_flood::alert_has_at_least_two_indicators` | Fired alert contains at least two indicator strings |
| `port_scan::fires_when_many_ports_small_flows` | Alert fires when a source IP reaches many destination ports with small flows |
| `port_scan::no_fire_when_too_few_ports` | No alert when destination port count is below threshold |
| `port_scan::no_fire_when_bytes_too_large` | No alert when average bytes per flow exceeds the maximum (flows are too large to be probes) |
| `port_scan::no_fire_on_wrong_window` | Port scan rule only evaluates on the 60-second window; ignored on 10-second window |
| `port_scan::alert_has_at_least_two_indicators` | Fired alert contains at least two indicator strings |
| `port_scan::alert_reports_correct_source_ip` | Fired alert identifies the correct scanner IP |
| `destination_hotspot::fires_when_traffic_concentrated` | Alert fires when traffic ratio and bytes/sec to a single destination both meet thresholds |
| `destination_hotspot::no_fire_when_ratio_too_low` | No alert when traffic is spread across multiple destinations |
| `destination_hotspot::no_fire_when_rate_too_low` | No alert when bytes/sec to the hotspot is below threshold |
| `destination_hotspot::no_fire_when_no_bytes` | No alert when there are no bytes in the window |
| `destination_hotspot::alert_reports_target_ip` | Fired alert identifies the destination IP that received concentrated traffic |
| `destination_hotspot::alert_has_at_least_two_indicators` | Fired alert contains at least two indicator strings |

---

## Integration Tests (`flodar/tests/integration.rs`)

Integration tests run the real async pipeline in-process — no Docker, no external
processes (except `sigterm_exits_cleanly`). Each test binds to OS-assigned loopback
ports to avoid conflicts when tests run in parallel.

Run them with `cargo test --test integration --package flodar`.

### Protocol Decoding

These tests verify that each supported protocol is accepted end-to-end: UDP packet
arrives at the collector, is decoded, and increments the shared flow counter.

| Test | What it checks |
|------|---------------|
| `v5_flows_are_counted` | Three NetFlow v5 records in one UDP packet produce `total_flows == 3` in shared state |
| `v9_flows_are_decoded` | A NetFlow v9 UDP datagram containing a template flowset + data flowset produces `total_flows == 1` |
| `ipfix_flows_are_decoded` | An IPFIX UDP datagram containing a template set + data set produces `total_flows == 1` |

### Instrumentation

| Test | What it checks |
|------|---------------|
| `prometheus_metrics_increment` | After two v5 flows are received, `flodar_flows_total == 2`, and both `flodar_packets_total` and `flodar_bytes_total` are non-zero |

### Multi-Socket

| Test | What it checks |
|------|---------------|
| `dual_socket_ipfix_port` | When a secondary IPFIX port is configured, flows sent directly to that port (not the main collector port) are decoded and counted |

### Version Filtering

| Test | What it checks |
|------|---------------|
| `accepted_versions_filter_drops_unlisted` | When `accepted_versions = [5]`, a NetFlow v9 (version 9) packet is silently dropped and `total_flows` remains 0 |
| `accepted_versions_filter_drops_ipfix` | When `accepted_versions = [5]`, an IPFIX (version 10) packet is silently dropped and `total_flows` remains 0 |

### Detection Engine

| Test | What it checks |
|------|---------------|
| `udp_flood_detection_fires_alert` | Injecting a `WindowMetrics` snapshot that exceeds all UDP flood thresholds causes exactly one alert with `rule == "udp_flood"` to appear in shared state |

### Graceful Shutdown

| Test | What it checks |
|------|---------------|
| `sigterm_exits_cleanly` *(Unix only)* | The compiled `flodar` binary starts, becomes reachable on its HTTP API port, exits with code 0 within 5 s of receiving SIGTERM |

---

## CI Pipeline

The GitHub Actions workflow runs these jobs on every pull request:

```
fmt ──┐
      ├──► test (unit) ──► integration ──┐
clippy ──┘                               ├──► publish (main only)
build ───────────────────────────────────┤
audit ───────────────────────────────────┘
```

`publish` (Docker image push to ghcr.io) only runs on merge to `main` and requires
all five preceding jobs to pass — including the integration tests.
