use tracing::info;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

/// Waits for SIGTERM or SIGINT so `docker stop` and Ctrl+C drain in-process work cleanly.
pub async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut sigterm = signal(SignalKind::terminate())
            .expect("register SIGTERM handler (required for PID 1 on Linux)");
        let mut sigint = signal(SignalKind::interrupt()).expect("register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => info!("received SIGTERM"),
            _ = sigint.recv() => info!("received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("register Ctrl+C handler");
        info!("received Ctrl+C");
    }
}
