//! Rustic binary: mimalloc, rustls crypto provider, **ECDSA P-256** image-trust verification, concurrent warm-up, Axum.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use mimalloc::MiMalloc;
use rustic::artifacts;
use rustic::http;
use rustic::kwt_access;
use rustic::state::AppState;
use rustic::telemetry;
use tracing::{error, info};

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

    telemetry::init_tracing();

    let attestation = artifacts::verify_on_startup_from_env()?;
    let kwt = kwt_access::kwt_access_from_env()?;
    let state = AppState::new(attestation, kwt);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Concurrent warm-up: DNS, HTTPS smoke, and time sample do not need to be sequential.
    let ((), (), ()) = tokio::join!(
        async {
            rustic::time_info::log_sample_timezone();
        },
        rustic::dns::log_sample_resolution(),
        rustic::outbound::log_https_smoke(),
    );

    let router = http::router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    let shutdown = rustic::shutdown::wait_for_shutdown();
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;

    info!("shutdown complete");
    Ok(())
}
