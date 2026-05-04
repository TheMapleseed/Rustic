use tracing::Level;
use tracing_subscriber::EnvFilter;

pub fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rustic=debug"));

    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
