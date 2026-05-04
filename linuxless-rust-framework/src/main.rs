//! Entry point: global allocator, tracing, Axum server, graceful shutdown on SIGTERM/SIGINT.
use std::net::SocketAddr;

use linuxless_rust_framework::artifacts;
use mimalloc::MiMalloc;
use tracing::{error, info};

mod app;
mod dns;
mod outbound;
mod shutdown;
mod time_info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!(error = %e, "fatal startup or runtime error");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    app::init_tracing();

    artifacts::verify_on_startup_from_env()?;

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    time_info::log_sample_timezone();
    dns::log_sample_resolution().await;
    outbound::log_https_smoke().await;

    let router = app::router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    let shutdown = shutdown::wait_for_shutdown();
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;

    info!("shutdown complete");
    Ok(())
}
