mod analytics;
mod api;
mod collector;
mod decoder;
mod detection;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "flodar", version = "0.6.0")]
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
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.collector.bind_address.is_empty(),
            "collector.bind_address must not be empty"
        );
        anyhow::ensure!(
            self.collector.bind_port != 0,
            "collector.bind_port must be non-zero"
        );
        anyhow::ensure!(self.api.bind_port != 0, "api.bind_port must be non-zero");
        anyhow::ensure!(
            self.analytics.snapshot_interval_secs > 0,
            "analytics.snapshot_interval_secs must be > 0"
        );
        for &v in &self.collector.accepted_versions {
            anyhow::ensure!(
                v == 5 || v == 9 || v == 10,
                "accepted_versions contains unsupported version {v} (must be 5, 9, or 10)"
            );
        }
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

    config.validate()?;

    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    let env_filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    #[cfg(feature = "loki")]
    {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        // Try to build the Loki layer when backend = "loki".
        // Returns None (and logs a warning) on any init failure; caller falls back to stdout-only.
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
    let accepted_versions = config.collector.accepted_versions.clone();

    tokio::try_join!(
        collector::run(
            bind_addr,
            flow_tx,
            shared_state.clone(),
            prom_metrics.clone(),
            ipfix_addr,
            accepted_versions,
        ),
        async {
            analytics::run(
                flow_rx,
                metrics_tx,
                shared_state.clone(),
                config.analytics.snapshot_interval_secs,
            )
            .await;
            Ok(())
        },
        async {
            detection::run(
                metrics_rx,
                config.detection,
                shared_state.clone(),
                prom_metrics.clone(),
            )
            .await;
            Ok(())
        },
        async move {
            if api_enabled {
                api::run(
                    api_addr,
                    api_shared_state,
                    prometheus_registry,
                    api_prom_metrics,
                )
                .await
            } else {
                tracing::info!("HTTP API disabled");
                Ok(())
            }
        },
        async {
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
            tracing::info!("shutting down");
            Ok(())
        },
    )?;

    Ok(())
}
