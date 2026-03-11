# Architecture

This document describes Flodar's internal design for developers who want to contribute.

## The pipeline

```
UDP packet
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ collector::run()                                                │
│ Binds UDP socket, decodes packets via decoder::decode_packet() │
│ Broadcasts FlowRecord, spawns flow_store insert                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ broadcast (FlowRecord, cap 1024)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ analytics::run()                                                │
│ Maintains 3 SlidingWindows (10s / 60s / 300s)                  │
│ Emits WindowMetrics on snapshot_interval_secs tick             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ broadcast (WindowMetrics, cap 256)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ detection::run()                                                │
│ Evaluates 4 rules, manages (rule, target_ip) cooldowns         │
│ Spawns webhook delivery + alert_store insert                   │
└─────────────────────────────────────────────────────────────────┘

SharedState (Arc<RwLock<AppState>>): written by collector + analytics, read by api::run()
```

### collector

`collector::run()` binds a UDP socket (and optionally a secondary IPFIX socket), reads raw datagrams in a loop, and calls `decoder::decode_packet()` on each one. Successfully decoded `FlowRecord` values are broadcast on `flow_tx`. Each record is also handed off to the flow store via a fire-and-forget `tokio::spawn` so that slow disk writes never stall ingestion. The collector also writes cumulative counters (total flows, packets, bytes, exporter last-seen timestamps) into the shared `AppState`.

### decoder

`decoder::decode_packet()` inspects the version field of the datagram and dispatches to one of three submodule parsers: `netflow_v5`, `netflow_v9`, or `ipfix`. The NetFlow v9 and IPFIX parsers are template-based — they consult the `TemplateCache` to interpret data records and update the cache when they receive template records. All parsers return `Vec<FlowRecord>` or a `DecodeError`; they never panic on malformed input.

### analytics

`analytics::run()` subscribes to the `flow_tx` broadcast channel and feeds each `FlowRecord` into three `SlidingWindow` instances (10 s, 60 s, 300 s). On each `snapshot_interval_secs` tick it computes a `WindowMetrics` snapshot for every window and broadcasts each one on `metrics_tx`. It also writes the latest per-window snapshots into `AppState.window_10s`, `AppState.window_60s`, and `AppState.window_300s` so the API can serve them without subscribing to the broadcast channel.

### detection

`detection::run()` subscribes to the `metrics_tx` broadcast channel. For each `WindowMetrics` snapshot it evaluates the rules registered for that window duration: `udp_flood`, `syn_flood`, and `destination_hotspot` run on the 10 s window; `port_scan` runs on the 60 s window. Candidate alerts that are not suppressed by the per-(rule, target_ip) cooldown are logged, pushed into the `AppState.recent_alerts` ring buffer, and handed off (via `tokio::spawn`) to `webhook::deliver` and the alert store — neither operation ever blocks the detection loop.

### api

`api::run()` starts an Axum HTTP server and serves seven endpoints. Handlers read from `SharedState` (for in-memory data) and from `SharedAlertStore` / `SharedFlowStore` (for persisted data). The API task is completely independent of the ingestion pipeline; it holds only read locks on `AppState` and never writes to it.

### storage

The `storage` module defines two traits — `FlowStore` and `AlertStore` — and provides one implementation of each. `DuckDbFlowStore` wraps a DuckDB `Connection` in an `Arc<Mutex<Connection>>` and uses `tokio::task::spawn_blocking` for every query because DuckDB's Rust client is synchronous. `SqliteAlertStore` uses `sqlx` with a `SqlitePool` and is fully async.

### webhook

`webhook::deliver()` is a plain async function that takes an `Alert` and a `WebhookConfig`. It serialises the alert to JSON and POSTs it to the configured URL, retrying up to `retry_attempts` times on failure. Serialisation errors are logged and the function returns early rather than panicking. `deliver` is always called from a spawned task so that network latency or failures never affect the detection loop.

---

## Key types

| Type | Definition | Produced by | Consumed by |
|---|---|---|---|
| `FlowRecord` | `decoder/flow_record.rs` | `decoder::decode_packet()` | `analytics::run()`, `storage::FlowStore` |
| `WindowMetrics` | `analytics/metrics.rs` | `analytics::run()` | `detection::run()`, `api` (via `AppState`) |
| `Alert` | `detection/alert.rs` | detection rule `evaluate()` functions | `api`, `storage::AlertStore`, `webhook::deliver()` |
| `AppState` / `SharedState` | `api/state.rs` | `collector::run()`, `analytics::run()` | `api` handlers |
| `SharedFlowStore` | `storage/mod.rs` | `main()` | `collector::run()`, `api::flows` handler |
| `SharedAlertStore` | `storage/mod.rs` | `main()` | `detection::run()`, `api::alerts` handlers |
| `TemplateCache` | `decoder/template_cache.rs` | `decoder::netflow_v9`, `decoder::ipfix` | `decoder::netflow_v9`, `decoder::ipfix` |

---

## Concurrency model

Flodar runs four long-lived Tokio tasks (collector, analytics, detection, api) selected with `tokio::select!` in `main`. Two broadcast channels connect them:

- `flow_tx: broadcast::Sender<FlowRecord>` — capacity 1024. The collector sends on it; analytics receives from it. If the analytics receiver lags, records are dropped and a warning is logged.
- `metrics_tx: broadcast::Sender<WindowMetrics>` — capacity 256. Analytics sends on it; detection receives from it. Lagged snapshots are dropped with a warning.

`AppState` is wrapped in `Arc<RwLock<AppState>>`. Writes happen in two places: the collector (counters, exporter map) and analytics (window snapshots, recent alerts). Read locks are taken by all API handlers. Locks are held for as short a time as possible — the pattern is to acquire a write lock, update a field, and immediately drop the guard before any async `.await`.

Storage and webhook calls follow the fire-and-forget pattern: `tokio::spawn(async move { ... })`. The spawned task owns cloned `Arc` handles to the store or webhook config. A failure in a spawned task logs a warning but never surfaces to the caller.

---

## Adding a new detection rule

1. Create `flodar/src/detection/rules/new_rule.rs`. Define a `NewRuleConfig` struct that derives `Debug`, `serde::Deserialize`, and `Default`, with one field per tunable threshold.
2. Add `pub new_rule: NewRuleConfig` to `DetectionConfig` in `flodar/src/detection/mod.rs` and re-export the config type.
3. Implement `pub fn evaluate(metrics: &WindowMetrics, config: &NewRuleConfig) -> Option<Alert>`. Return `Some(Alert { ... })` when all conditions are met, `None` otherwise. Use `chrono::Utc::now()` for `triggered_at`. Populate `indicators` with human-readable descriptions of each exceeded threshold.
4. Register the rule in `detection/mod.rs`: call `evaluate()` in the correct `match metrics.window_secs` arm (`10`, `60`, or `300`) and push the result into `candidates`.
5. Add a `[detection.new_rule]` section with all fields and defaults to the example in `docs/configuration.md`.
6. Add unit tests in the same file: at minimum — fires when all conditions are met, does not fire when below threshold, partial match returns `None`.
7. If the rule requires specific traffic patterns to trigger, add a `flowgen --mode new-rule` simulation mode so contributors can test it locally without a real router.

## Adding a new flow protocol

1. Create `flodar/src/decoder/new_protocol.rs`.
2. Implement `pub fn parse(data: &[u8], exporter_ip: IpAddr, cache: &mut TemplateCache) -> Result<Vec<FlowRecord>, DecodeError>`. Map every protocol field to the corresponding `FlowRecord` fields. Return an error (not a panic) for any malformed input.
3. Add the version dispatch to `decoder/mod.rs`: inspect the protocol version byte and route to the new parser.
4. Add unit tests: known bytes produce the expected `FlowRecord`; malformed input returns an error, not a panic.
5. Add a `flowgen --mode new-protocol` subcommand that generates synthetic datagrams for local testing.
