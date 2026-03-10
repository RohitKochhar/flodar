use crate::detection::alert::Alert;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebhookConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub url: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
}

fn default_enabled() -> bool {
    true
}
fn default_timeout_secs() -> u64 {
    5
}
fn default_retry_attempts() -> u32 {
    1
}

pub async fn deliver(alert: &Alert, config: &WebhookConfig) {
    let client = reqwest::Client::new();
    let payload = match serde_json::to_string(alert) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, rule = %alert.rule, "failed to serialize alert for webhook delivery");
            return;
        }
    };

    for attempt in 0..=config.retry_attempts {
        let result = client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .body(payload.clone())
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(url = %config.url, rule = %alert.rule, "webhook delivered");
                return;
            }
            Ok(resp) => {
                tracing::warn!(
                    url = %config.url,
                    status = resp.status().as_u16(),
                    attempt = attempt,
                    "webhook delivery failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    url = %config.url,
                    error = %e,
                    attempt = attempt,
                    "webhook delivery error"
                );
            }
        }
    }

    tracing::error!(url = %config.url, rule = %alert.rule, "webhook delivery abandoned after retries");
}
