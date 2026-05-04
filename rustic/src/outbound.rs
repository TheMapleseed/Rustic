use tracing::{info, warn};

/// Verifies outbound HTTPS using rustls + Mozilla roots (via reqwest), without OpenSSL.
pub async fn log_https_smoke() {
    let client = match reqwest::Client::builder().use_rustls_tls().build() {
        Ok(c) => c,
        Err(e) => {
            warn!(%e, "reqwest client build failed");
            return;
        }
    };

    match client
        .get("https://example.com/")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => info!(status = %resp.status(), "reqwest https smoke (example.com)"),
        Err(e) => warn!(%e, "reqwest https smoke failed (offline CI is ok)"),
    }
}
