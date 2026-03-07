mod analytics;
mod collector;
mod decoder;
mod detection;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "flodar", version = "0.3.0")]
struct Cli {
    /// Path to configuration file
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,

    /// Log format: json or pretty
    #[arg(long, default_value = "json")]
    log_format: LogFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
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
}

#[derive(Debug, Deserialize)]
struct CollectorConfig {
    #[serde(default = "default_bind_address")]
    bind_address: String,
    #[serde(default = "default_bind_port")]
    bind_port: u16,
}

#[derive(Debug, Deserialize)]
struct LoggingConfig {
    #[serde(default = "default_log_level")]
    level: String,
}

#[derive(Debug, Deserialize)]
struct AnalyticsConfig {
    #[serde(default = "default_snapshot_interval_secs")]
    snapshot_interval_secs: u64,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            bind_port: default_bind_port(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
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

    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    let env_filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

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
    .context("invalid bind address")?;

    let (flow_tx, flow_rx) =
        tokio::sync::broadcast::channel::<decoder::flow_record::FlowRecord>(1024);
    let (metrics_tx, metrics_rx) =
        tokio::sync::broadcast::channel::<analytics::metrics::WindowMetrics>(256);

    tokio::try_join!(
        collector::run(bind_addr, flow_tx),
        async {
            analytics::run(flow_rx, metrics_tx, config.analytics.snapshot_interval_secs).await;
            Ok(())
        },
        async {
            detection::run(metrics_rx, config.detection).await;
            Ok(())
        },
    )?;

    Ok(())
}
