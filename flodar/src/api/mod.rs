mod handlers;
pub mod metrics;
pub mod state;

use std::sync::Arc;

use handlers::ApiState;
pub use metrics::FlodarMetrics;
pub use state::{AppState, SharedState};

pub async fn run(
    bind_addr: std::net::SocketAddr,
    state: SharedState,
    registry: prometheus::Registry,
    prom_metrics: Arc<FlodarMetrics>,
) -> anyhow::Result<()> {
    let api_state = ApiState {
        shared: state,
        registry: Arc::new(registry),
        prom_metrics,
    };

    let app = axum::Router::new()
        .route("/health", axum::routing::get(handlers::health))
        .route("/metrics", axum::routing::get(handlers::metrics))
        .route("/api/summary", axum::routing::get(handlers::summary))
        .route(
            "/api/top-talkers",
            axum::routing::get(handlers::top_talkers),
        )
        .route("/api/alerts", axum::routing::get(handlers::alerts))
        .with_state(api_state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(address = %bind_addr, "HTTP API listening");
    axum::serve(listener, app).await?;
    Ok(())
}
