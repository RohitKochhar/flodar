use flodar::{analytics, api, collector, decoder, detection, storage, webhook};

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "flodar", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Path to configuration file
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,

    /// Log format: json or pretty
    #[arg(long, default_value = "json")]
    log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    collector: CollectorConfig,
    #[serde(default)]
    logging: LoggingConfig,
    #[serde(default)]
    analytics: AnalyticsConfig,
    #[serde(default)]
    detection: detection::DetectionConfig,
    #[serde(default)]
    api: ApiConfig,
    #[serde(default)]
    storage: StorageConfig,
    webhook: Option<webhook::WebhookConfig>,
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.collector.bind_address.is_empty(),
            "collector.bind_address must not be empty"
        );
        anyhow::ensure!(
            self.collector.bind_port != 0,
            "collector.bind_port must be in range 1–65535"
        );
        anyhow::ensure!(
            self.api.bind_port != 0,
            "api.bind_port must be in range 1–65535"
        );
        anyhow::ensure!(
            self.analytics.snapshot_interval_secs > 0,
            "analytics.snapshot_interval_secs must be > 0"
        );
        anyhow::ensure!(
            self.detection.cooldown_secs > 0,
            "detection.cooldown_secs must be > 0 (use a large value like 3600 to effectively disable cooldown)"
        );
        for &v in &self.collector.accepted_versions {
            anyhow::ensure!(
                v == 5 || v == 9 || v == 10,
                "accepted_versions contains unsupported version {v} (must be 5, 9, or 10)"
            );
        }

        // Webhook: if enabled, url must be a valid HTTP/HTTPS URL.
        if let Some(wh) = &self.webhook {
            if wh.enabled {
                anyhow::ensure!(
                    !wh.url.is_empty(),
                    "webhook.url is required when webhook.enabled = true\n  \
                     Set a valid HTTP or HTTPS URL, e.g.:\n    \
                     [webhook]\n    \
                     url = \"https://hooks.slack.com/services/...\""
                );
                anyhow::ensure!(
                    wh.url.starts_with("http://") || wh.url.starts_with("https://"),
                    "webhook.url must start with http:// or https://, got: {}\n  \
                     e.g.: url = \"https://hooks.slack.com/services/...\"",
                    wh.url
                );
            }
        }

        // Storage: if enabled, both paths must be non-empty.
        if self.storage.enabled {
            anyhow::ensure!(
                !self.storage.flow_db_path.is_empty(),
                "storage.flow_db_path must not be empty when storage.enabled = true"
            );
            anyhow::ensure!(
                !self.storage.alert_db_path.is_empty(),
                "storage.alert_db_path must not be empty when storage.enabled = true"
            );
        }

        // Detection thresholds must be non-negative.
        anyhow::ensure!(
            self.detection.udp_flood.min_packets_per_sec >= 0.0,
            "detection.udp_flood.min_packets_per_sec must be >= 0"
        );
        anyhow::ensure!(
            self.detection.udp_flood.min_udp_ratio >= 0.0,
            "detection.udp_flood.min_udp_ratio must be >= 0"
        );
        anyhow::ensure!(
            self.detection.syn_flood.min_packets_per_sec >= 0.0,
            "detection.syn_flood.min_packets_per_sec must be >= 0"
        );
        anyhow::ensure!(
            self.detection.syn_flood.min_syn_ratio >= 0.0,
            "detection.syn_flood.min_syn_ratio must be >= 0"
        );
        anyhow::ensure!(
            self.detection.destination_hotspot.min_traffic_ratio >= 0.0,
            "detection.destination_hotspot.min_traffic_ratio must be >= 0"
        );
        anyhow::ensure!(
            self.detection.destination_hotspot.min_bytes_per_sec >= 0.0,
            "detection.destination_hotspot.min_bytes_per_sec must be >= 0"
        );
        anyhow::ensure!(
            self.detection.port_scan.max_bytes_per_flow >= 0.0,
            "detection.port_scan.max_bytes_per_flow must be >= 0"
        );

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct CollectorConfig {
    #[serde(default = "default_bind_address")]
    bind_address: String,
    #[serde(default = "default_bind_port")]
    bind_port: u16,
    #[serde(default)]
    accepted_versions: Vec<u16>,
    #[serde(default)]
    bind_port_ipfix: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct LoggingConfig {
    #[serde(default = "default_log_level")]
    level: String,
    /// "loki" to enable Loki backend (requires `--features loki`)
    #[serde(default)]
    #[cfg_attr(not(feature = "loki"), allow(dead_code))]
    backend: Option<String>,
    /// Loki push URL, e.g. "http://localhost:3100"
    #[serde(default)]
    #[cfg_attr(not(feature = "loki"), allow(dead_code))]
    loki_url: Option<String>,
    /// Fixed-cardinality labels attached to every Loki log stream
    #[serde(default)]
    #[cfg_attr(not(feature = "loki"), allow(dead_code))]
    loki_labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct AnalyticsConfig {
    #[serde(default = "default_snapshot_interval_secs")]
    snapshot_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
struct ApiConfig {
    #[serde(default = "default_api_bind_address")]
    bind_address: String,
    #[serde(default = "default_api_bind_port")]
    bind_port: u16,
    #[serde(default = "default_api_enabled")]
    enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct StorageConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_flow_db_path")]
    flow_db_path: String,
    #[serde(default = "default_alert_db_path")]
    alert_db_path: String,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            bind_port: default_bind_port(),
            accepted_versions: Vec::new(),
            bind_port_ipfix: None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            backend: None,
            loki_url: None,
            loki_labels: None,
        }
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            snapshot_interval_secs: default_snapshot_interval_secs(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_address: default_api_bind_address(),
            bind_port: default_api_bind_port(),
            enabled: default_api_enabled(),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    2055
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_snapshot_interval_secs() -> u64 {
    10
}
fn default_api_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_api_bind_port() -> u16 {
    9090
}
fn default_api_enabled() -> bool {
    true
}
fn flodar_data_dir() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("flodar")
    } else {
        std::path::PathBuf::from(".")
    }
}
fn default_flow_db_path() -> String {
    flodar_data_dir()
        .join("flodar_flows.duckdb")
        .to_string_lossy()
        .into_owned()
}
fn default_alert_db_path() -> String {
    flodar_data_dir()
        .join("flodar_alerts.db")
        .to_string_lossy()
        .into_owned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = if let Some(path) = &cli.config {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        toml::from_str::<Config>(&raw)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?
    } else {
        Config::default()
    };

    // Validate before binding any sockets. Errors are printed to stderr directly
    // because the logging layer is not yet initialized at this point.
    if let Err(e) = config.validate() {
        eprintln!("Error: invalid configuration\n  {e}");
        std::process::exit(1);
    }

    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    let env_filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    #[cfg(feature = "loki")]
    {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        let loki_init = if config.logging.backend.as_deref() == Some("loki") {
            let url_str = config
                .logging
                .loki_url
                .as_deref()
                .unwrap_or("http://localhost:3100");

            url::Url::parse(url_str).ok().and_then(|url| {
                let mut builder = tracing_loki::builder();
                if let Some(labels) = &config.logging.loki_labels {
                    for (k, v) in labels {
                        builder = builder.label(k, v).ok()?;
                    }
                }
                builder.build_url(url).ok()
            })
        } else {
            None
        };

        match (loki_init, cli.log_format) {
            (Some((loki_layer, task)), LogFormat::Json) => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().json())
                    .with(loki_layer)
                    .init();
                tokio::spawn(task);
            }
            (Some((loki_layer, task)), LogFormat::Pretty) => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().pretty())
                    .with(loki_layer)
                    .init();
                tokio::spawn(task);
            }
            (None, LogFormat::Json) => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().json())
                    .init();
                if config.logging.backend.as_deref() == Some("loki") {
                    tracing::warn!("loki layer init failed, using stdout only");
                }
            }
            (None, LogFormat::Pretty) => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().pretty())
                    .init();
                if config.logging.backend.as_deref() == Some("loki") {
                    tracing::warn!("loki layer init failed, using stdout only");
                }
            }
        }
    }

    #[cfg(not(feature = "loki"))]
    match cli.log_format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .pretty()
                .with_env_filter(env_filter)
                .init();
        }
    }

    let bind_addr: SocketAddr = format!(
        "{}:{}",
        config.collector.bind_address, config.collector.bind_port
    )
    .parse()
    .context("invalid collector bind address")?;

    let api_addr: SocketAddr = format!("{}:{}", config.api.bind_address, config.api.bind_port)
        .parse()
        .context("invalid API bind address")?;

    let ipfix_addr: Option<SocketAddr> = if let Some(port) = config.collector.bind_port_ipfix {
        Some(
            format!("{}:{}", config.collector.bind_address, port)
                .parse()
                .context("invalid IPFIX bind address")?,
        )
    } else {
        None
    };

    // Initialise optional storage backends.
    let (flow_store, alert_store): (storage::SharedFlowStore, storage::SharedAlertStore) =
        if config.storage.enabled {
            // Ensure parent directories exist so users don't have to create them manually.
            for path_str in [&config.storage.flow_db_path, &config.storage.alert_db_path] {
                if let Some(parent) = std::path::Path::new(path_str).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).with_context(|| {
                            format!("failed to create storage directory: {}", parent.display())
                        })?;
                    }
                }
            }

            let fs = storage::DuckDbFlowStore::new(&config.storage.flow_db_path)
                .context("failed to open flow store")?;
            let als = storage::SqliteAlertStore::new(&config.storage.alert_db_path)
                .await
                .context("failed to open alert store")?;
            (
                Some(Arc::new(fs) as Arc<dyn storage::FlowStore>),
                Some(Arc::new(als) as Arc<dyn storage::AlertStore>),
            )
        } else {
            (None, None)
        };

    // Resolve webhook config (only when enabled).
    let webhook_config = config.webhook.clone().filter(|w| w.enabled);

    // Print startup summary so the user can immediately confirm their config was read correctly.
    print_startup_banner(&config, &webhook_config, cli.log_format);

    let shared_state: api::SharedState =
        Arc::new(tokio::sync::RwLock::new(api::AppState::default()));

    let prometheus_registry = prometheus::Registry::new();
    let prom_metrics = Arc::new(
        api::FlodarMetrics::new(&prometheus_registry)
            .context("failed to register prometheus metrics")?,
    );

    let (flow_tx, flow_rx) =
        tokio::sync::broadcast::channel::<decoder::flow_record::FlowRecord>(1024);
    let (metrics_tx, metrics_rx) =
        tokio::sync::broadcast::channel::<analytics::metrics::WindowMetrics>(256);

    let api_enabled = config.api.enabled;
    let api_shared_state = shared_state.clone();
    let api_prom_metrics = prom_metrics.clone();
    let api_alert_store = alert_store.clone();
    let api_flow_store = flow_store.clone();
    let accepted_versions = config.collector.accepted_versions.clone();
    let pretty_alerts = matches!(cli.log_format, LogFormat::Pretty);

    tokio::select! {
        r = collector::run(
            bind_addr,
            flow_tx,
            shared_state.clone(),
            prom_metrics.clone(),
            ipfix_addr,
            accepted_versions,
            flow_store,
        ) => r?,

        () = analytics::run(
            flow_rx,
            metrics_tx,
            shared_state.clone(),
            config.analytics.snapshot_interval_secs,
        ) => {},

        () = detection::run(
            metrics_rx,
            config.detection,
            shared_state.clone(),
            prom_metrics.clone(),
            alert_store,
            webhook_config,
            pretty_alerts,
        ) => {},

        r = async move {
            if api_enabled {
                api::run(
                    api_addr,
                    api_shared_state,
                    prometheus_registry,
                    api_prom_metrics,
                    api_alert_store,
                    api_flow_store,
                )
                .await
            } else {
                tracing::info!("HTTP API disabled");
                Ok(())
            }
        } => r?,

        r = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate())
                    .map_err(|e| anyhow::anyhow!("SIGTERM handler: {e}"))?;
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c()
                    .await
                    .map_err(|e| anyhow::anyhow!("ctrl-c handler: {e}"))?;
            }
            tracing::info!(reason = "signal", "flodar shutting down");
            // Allow in-flight storage writes up to 2 seconds to complete before the
            // runtime drops. Writes are fire-and-forget tasks; this sleep gives them
            // time to flush without blocking indefinitely.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            Ok::<(), anyhow::Error>(())
        } => r?,
    }

    Ok(())
}

/// Print a concise startup summary at INFO level so the user can immediately
/// confirm that their configuration file was read correctly.
fn print_startup_banner(
    config: &Config,
    webhook_config: &Option<webhook::WebhookConfig>,
    log_format: LogFormat,
) {
    let storage_str = if config.storage.enabled {
        format!(
            "enabled (flows: {}, alerts: {})",
            config.storage.flow_db_path, config.storage.alert_db_path
        )
    } else {
        "disabled".to_string()
    };

    let webhook_str = if let Some(wh) = webhook_config {
        format!("enabled ({})", wh.url)
    } else {
        "disabled".to_string()
    };

    let log_fmt_str = match log_format {
        LogFormat::Json => "json",
        LogFormat::Pretty => "pretty",
    };

    tracing::info!(
        version     = env!("CARGO_PKG_VERSION"),
        collector   = %format!("{}:{} (NetFlow v5/v9, IPFIX)", config.collector.bind_address, config.collector.bind_port),
        api         = %format!("{}:{}", config.api.bind_address, config.api.bind_port),
        storage     = %storage_str,
        webhook     = %webhook_str,
        log_format  = %log_fmt_str,
        "flodar starting"
    );
}
