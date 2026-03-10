pub mod alert_store;
pub mod flow_store;

use std::sync::Arc;

use crate::decoder::flow_record::FlowRecord;
use crate::detection::alert::Alert;

pub use alert_store::SqliteAlertStore;
pub use flow_store::DuckDbFlowStore;

#[async_trait::async_trait]
pub trait FlowStore: Send + Sync {
    async fn insert(&self, record: &FlowRecord) -> anyhow::Result<()>;
    async fn query_range(
        &self,
        start: std::time::SystemTime,
        end: std::time::SystemTime,
        limit: usize,
    ) -> anyhow::Result<Vec<FlowRecord>>;
}

#[async_trait::async_trait]
pub trait AlertStore: Send + Sync {
    async fn insert(&self, alert: &Alert) -> anyhow::Result<()>;
    async fn query_recent(&self, limit: usize) -> anyhow::Result<Vec<Alert>>;
    async fn query_by_id(&self, id: i64) -> anyhow::Result<Option<Alert>>;
    async fn query_by_ip(&self, ip: std::net::Ipv4Addr, limit: usize)
        -> anyhow::Result<Vec<Alert>>;
    async fn query_by_rule(&self, rule: &str, limit: usize) -> anyhow::Result<Vec<Alert>>;
}

pub type SharedFlowStore = Option<Arc<dyn FlowStore>>;
pub type SharedAlertStore = Option<Arc<dyn AlertStore>>;
