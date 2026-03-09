use std::net::Ipv4Addr;

use anyhow::Context;
use sqlx::SqlitePool;

use super::AlertStore;
use crate::detection::alert::{Alert, Severity};

pub struct SqliteAlertStore {
    pool: SqlitePool,
}

impl SqliteAlertStore {
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        let url = if path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite://{path}?mode=rwc")
        };

        let pool = SqlitePool::connect(&url)
            .await
            .context("failed to open SQLite alert store")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                rule         TEXT NOT NULL,
                severity     TEXT NOT NULL,
                target_ip    TEXT,
                window_secs  INTEGER NOT NULL,
                indicators   TEXT NOT NULL,
                triggered_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
            CREATE INDEX IF NOT EXISTS idx_alerts_target_ip ON alerts(target_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);",
        )
        .execute(&pool)
        .await
        .context("failed to initialise alerts schema")?;

        Ok(Self { pool })
    }
}

fn severity_to_str(s: &Severity) -> &'static str {
    match s {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
    }
}

fn str_to_severity(s: &str) -> Severity {
    match s {
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        _ => Severity::High,
    }
}

fn row_to_alert(
    rule: String,
    severity: String,
    target_ip: Option<String>,
    window_secs: i64,
    indicators: String,
    triggered_at: String,
) -> anyhow::Result<Alert> {
    let target_ip = target_ip.and_then(|s| s.parse::<Ipv4Addr>().ok());
    let indicators: Vec<String> = serde_json::from_str(&indicators).unwrap_or_default();
    let triggered_at = chrono::DateTime::parse_from_rfc3339(&triggered_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Ok(Alert {
        rule,
        severity: str_to_severity(&severity),
        target_ip,
        window_secs: window_secs as u64,
        indicators,
        triggered_at,
    })
}

#[async_trait::async_trait]
impl AlertStore for SqliteAlertStore {
    async fn insert(&self, alert: &Alert) -> anyhow::Result<()> {
        let indicators =
            serde_json::to_string(&alert.indicators).context("failed to serialize indicators")?;
        let target_ip = alert.target_ip.map(|ip| ip.to_string());
        let severity = severity_to_str(&alert.severity);
        let triggered_at = alert.triggered_at.to_rfc3339();

        sqlx::query(
            "INSERT INTO alerts (rule, severity, target_ip, window_secs, indicators, triggered_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&alert.rule)
        .bind(severity)
        .bind(target_ip)
        .bind(alert.window_secs as i64)
        .bind(&indicators)
        .bind(&triggered_at)
        .execute(&self.pool)
        .await
        .context("failed to insert alert")?;

        Ok(())
    }

    async fn query_recent(&self, limit: usize) -> anyhow::Result<Vec<Alert>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, i64, String, String)>(
            "SELECT rule, severity, target_ip, window_secs, indicators, triggered_at \
             FROM alerts \
             ORDER BY triggered_at DESC \
             LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .context("failed to query recent alerts")?;

        rows.into_iter()
            .map(
                |(rule, severity, target_ip, window_secs, indicators, triggered_at)| {
                    row_to_alert(
                        rule,
                        severity,
                        target_ip,
                        window_secs,
                        indicators,
                        triggered_at,
                    )
                },
            )
            .collect()
    }

    async fn query_by_ip(&self, ip: Ipv4Addr, limit: usize) -> anyhow::Result<Vec<Alert>> {
        let ip_str = ip.to_string();
        let rows = sqlx::query_as::<_, (String, String, Option<String>, i64, String, String)>(
            "SELECT rule, severity, target_ip, window_secs, indicators, triggered_at \
             FROM alerts \
             WHERE target_ip = ? \
             ORDER BY triggered_at DESC \
             LIMIT ?",
        )
        .bind(&ip_str)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .context("failed to query alerts by ip")?;

        rows.into_iter()
            .map(
                |(rule, severity, target_ip, window_secs, indicators, triggered_at)| {
                    row_to_alert(
                        rule,
                        severity,
                        target_ip,
                        window_secs,
                        indicators,
                        triggered_at,
                    )
                },
            )
            .collect()
    }

    async fn query_by_rule(&self, rule: &str, limit: usize) -> anyhow::Result<Vec<Alert>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, i64, String, String)>(
            "SELECT rule, severity, target_ip, window_secs, indicators, triggered_at \
             FROM alerts \
             WHERE rule = ? \
             ORDER BY triggered_at DESC \
             LIMIT ?",
        )
        .bind(rule)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .context("failed to query alerts by rule")?;

        rows.into_iter()
            .map(
                |(rule, severity, target_ip, window_secs, indicators, triggered_at)| {
                    row_to_alert(
                        rule,
                        severity,
                        target_ip,
                        window_secs,
                        indicators,
                        triggered_at,
                    )
                },
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_alert(rule: &str, ip: Option<Ipv4Addr>) -> Alert {
        Alert {
            rule: rule.to_string(),
            severity: Severity::High,
            target_ip: ip,
            window_secs: 10,
            indicators: vec!["test indicator".to_string()],
            triggered_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn insert_and_query_recent() {
        let store = SqliteAlertStore::new(":memory:").await.unwrap();

        store.insert(&make_alert("udp_flood", None)).await.unwrap();
        store.insert(&make_alert("syn_flood", None)).await.unwrap();

        let results = store.query_recent(10).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_by_rule_filters() {
        let store = SqliteAlertStore::new(":memory:").await.unwrap();

        store.insert(&make_alert("udp_flood", None)).await.unwrap();
        store.insert(&make_alert("syn_flood", None)).await.unwrap();
        store.insert(&make_alert("udp_flood", None)).await.unwrap();

        let results = store.query_by_rule("udp_flood", 10).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|a| a.rule == "udp_flood"));
    }

    #[tokio::test]
    async fn query_by_ip_filters() {
        let store = SqliteAlertStore::new(":memory:").await.unwrap();
        let target = Ipv4Addr::new(192, 168, 1, 10);

        store
            .insert(&make_alert("port_scan", Some(target)))
            .await
            .unwrap();
        store
            .insert(&make_alert("port_scan", Some(Ipv4Addr::new(10, 0, 0, 1))))
            .await
            .unwrap();

        let results = store.query_by_ip(target, 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].target_ip, Some(target));
    }

    #[tokio::test]
    async fn query_recent_respects_limit() {
        let store = SqliteAlertStore::new(":memory:").await.unwrap();

        for _ in 0..5 {
            store.insert(&make_alert("udp_flood", None)).await.unwrap();
        }

        let results = store.query_recent(3).await.unwrap();
        assert_eq!(results.len(), 3);
    }
}
